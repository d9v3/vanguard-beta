# Version history

*[Français](CHANGELOG.md)*

What each day brought to Vanguard, most recent first. Since October 19, 2026, Vanguard has, as a rule, a single release
a day, gathering the day's work; October 21 had two, 0.82 in the morning and 0.84 in the evening, which takes over 0.83,
delivered just before it. Only the latest version has its download page; every version keeps its tag in the repository
(`git checkout v0.62.0`, for example), to be rebuilt if needed.

## Upcoming

- **Programs' protections checked before they leave.** `vanguard deploiement verifier-binaire` (former name:
  `verifier-pe`, kept) reads from their headers, without running them, the protections of the published programs: on
  Linux PIE, full RELRO marking (PT_GNU_RELRO, BIND_NOW), non-executable stack, no writable and executable segment; on Windows high-entropy
  ASLR, DEP and relocations, on top of System32 DLLs and the manifest; on macOS every slice PIE. verifier.sh, CI,
  deployment and publishing refuse a program that loses one; CFG and CET are shown without being required.

- **RELRO really applied on Linux.** The Linux program (musl static-pie) carried the full RELRO marking, but musl's
  startup does not apply it: the GOT and `.data.rel.ro` stayed writable for the whole life of the process. Vanguard
  now makes that segment read-only itself at launch, as glibc's loader does; a failure is logged without stopping
  the startup.

## October 26, 2026: version 0.88

- **Detection regression.** A corpus of harmless fabricated cases (tests/corpus-detection) proves through 77 cases
  (part of them per system) that the detection rules and tools still fire (depending on the system: each runs where it
  exists), at their exact severity, and that a clean case leaves them silent. For this, the 21 rules whose reading and
  judgement were mixed (Linux persistence and privileged programs, accounts, SSH, sudo, integrity, macOS agents and
  extensions, Windows startup and event logs, network audit checks) have their judgement apart, with the same
  behaviour. Every rule citing an ATT&CK technique, and every tool that detects, has its case or its reason; each
  rule's path to its judgement is kept, and verifier.sh runs it as two steps (Linux and Wine). A rule that only gives
  information is proven by a silent clean case, and a rule that always reports a part as unchecked (a store unreadable
  without a tool) also does so in its clean case, next to at least one checked result, except one, named with its
  reason. Tools and monitoring alerts (downloaded file, link, email, spyware, remote control, leaked secret, command
  server, critical files, router, Wi-Fi, new device or port, name poisoner) have theirs too; the YARA analyses, the
  live watchers and the active protection, as well as the list of programs talking to the Internet (an inventory), are
  exempted with their reason.
- **Other state files sealed, a single judge.** The decoy file list, the blocked ports, this computer's device record,
  the VANGUARD key references, the monthly check-up, the backup note and the monitoring's last run are sealed:
  changed, deleted or accepted as they were after the seals were remade, they no longer turn anything off (a decoy is
  still expected, an exposed port is reported again, every device is reported new again, the key is never called
  intact, nothing is undone from a forged note), and this is said. Every reader follows the same judge; only a file
  taken over by a known update is trusted as it is. An update is trusted only on proof: the head of the event log,
  sealed, written by the earlier version. This proof stops the seals' cleartext field from being set back by hand;
  sealed like the rest, it can be recomputed by a program that targets this mechanism on purpose (a limit in the
  threat model). Without it (log deleted, head rewritten), seals set back to an earlier form only accept what is there
  as it is, without trusting it, and the summary says the seals were remade; with no trace of the log at all (an
  earlier version that had not noted anything yet, or everything deleted), nothing is taken over either, and the
  summary says so one level lower, with both causes. The summary and the menu note the head of the log as they start,
  for the next update. These earlier seals are judged before the log leaves its first trace (lock, folder): its own
  traces no longer make them reported as remade. An older version that ran here again (a drive or a Mac left behind)
  is reported one level lower, and takes nothing over, for a month or until a file it left is rewritten. A seals lock
  held by another program now causes only one wait, one second in all, and is reported in the summary; vanguard
  --version waits for nothing; events that could not be noted are counted and reported in the summary once the lock is
  released, even if more go missing while it reports them (if Vanguard is killed before, its pending events are lost
  uncounted; this count, written without a seal, can be deleted), and “seals remade” goes away once said. A test reads
  the code so that each sealed file name appears only where it is allowed, exceptions stated; VANGUARD_ORIGINE is
  trusted only if it has the bytes of the running program. The threat model states the limits: the folder deleted as a
  whole, and a program that targets this mechanism on purpose.
- **Extensions and downloaded lists sealed.** Extension settings (“no restrictions”, “mine”, running with the
  check-up or monitoring) and their approvals are sealed: changed outside Vanguard, or accepted as they were (seals
  remade, earlier version), they no longer grant anything, nothing runs on its own, and the menu and the check-up say
  so (COM-ETA-001). Each downloaded list (Feodo Tracker, ThreatFox, URLhaus, MalwareBazaar, KEV, Échap, LOLDrivers,
  software versions) is sealed with its download date: its age comes from that date, no longer from the file's;
  emptied, unsealed or dated in the future, it is fetched again, and if it cannot be, “not checked” with the reason,
  never clean.
- **Wanted defenses and started program, judged on a sealed state.** Turning the hourly monitoring, the watcher and
  the ransomware watch on and off through Vanguard is noted in a sealed state and in the log (those from an earlier
  version are taken over as they are): with their note deleted along with their task, or that record changed outside
  Vanguard, the check says the defense was cut without going through Vanguard (never again “off, as by default”); a
  record lost with the seals is “not checked”, never green. The watcher's state is sealed, and a watcher is only said
  to be alive if its process runs the unit's program; the one from before an update, still running, is reported with
  the fix and restarted by Vanguard's update. The program each task starts (monitoring, check-up, watcher) and the
  task's text (unit and timer, scheduled task, agent) have their BLAKE3 fingerprint sealed when placed and at each
  update by Vanguard: another path, other bytes or a changed task are a high alert; a published and signed version
  placed outside Vanguard is recognized by the signed version history and reported as information.
- **Windows logs: a single judge, two more rules, a place in the menu.** The check-up (WIN-JRN-003) no longer reads
  the logs itself: it takes the thirteen EVT- rules of “What happened?”, alerts at the same level, and “not verified”
  with its reason when a log is missing or restricted to administrators; the HTML report no longer shows this
  computer's logs twice. New rules: EVT-TAC-001, a scheduled task created or changed to run an interpreter, an
  encoded command or a program from a temporary folder (task auditing, or the Task Scheduler history); EVT-PRC-001,
  suspicious processes (known attack tools, encoded command, download by certutil, bitsadmin, mshta, regsvr32 or
  rundll32), if the command line is logged. Off by default, these settings are named when they are missing. An
  updated task (Task Scheduler event 140) is reported as information. The check-up also lists the ordinary services
  installed over the period (five names at most), and a cleared log is no longer reported twice: COM-JRN-001 leaves
  to WIN-JRN-003 those it read, and reports the others itself, each on its own (an alert declared normal no longer
  silences another). Block and
  respond › Windows logs menu: this Windows, or a folder of .evtx on Linux and macOS.
- **Tighter reading and proofs (fourth attack campaign).** Windows logs: a task action written with attributes
  (`<Exec id="…">`), a namespace prefix (`<task:Exec>`), a blank before “>”, a CDATA section or numeric references
  (`&#112;`) is read (EVT-TAC-001), a tag written inside a comment, a processing instruction or a CDATA section is not
  one (a `</Arguments>` in a CDATA section no longer cuts the value, a commented-out `<Command>` no longer comes before
  the real one), an empty `<Command/>` tag no longer hides the next one, and any action tag opened beyond the actions
  read gives an alert instead of silence; PowerShell's encoded command is recognized in all its forms (`-e`, `-enc`,
  `--enc`, `-EncodedCommand:…`, `-e^nc`, typographic dashes “–enc”) in processes, tasks, services and script blocks
  (EVT-PRC-001, EVT-TAC-001), and judged by its value: an encoding name or a code page number (“gc $f -enc byte”,
  “Out-File -en BigEndianUnicode”) is not one, nor is “certutil -encode”; in a script it takes base64 that decodes to
  readable UTF-16 text, “-EncodedCommand” in full, or a variable passed to a named PowerShell. Memory: a loaded image
  whose code is mapped far from its header is read in one piece, and the scan is said to be incomplete rather than
  clean; an intact image outside the system folders (a program started from ~/.cache or /var/tmp) is read in memory
  instead of being “left to the file scan”, which did not read it, once for all processes that load it, but counted as
  read only after a process read in full (a decoy process that fills its share no longer makes it skipped elsewhere);
  it is named by its file (Linux: device, inode and dates; Windows: volume, file ID and write date, which a program can
  set back after rewriting the file: a narrow window, within one scan). A mapped data file without code (a systemd
  journal) is neither read nor called fragmented, unless it starts with an ELF or PE header, and a mapped file without
  code whose start is not mapped or not readable is left without being counted (nothing runs from a page without “x”);
  the host libraries seen by Steam games (/run/host/usr) are recognized as system ones. Only images from the system
  folders stay unread, and that is said. On Windows, these changes have not been tried on a real Windows yet. Detection
  corpus: every per-system version of a function in a rule's chain (its `cfg` conditions evaluated as for the published
  program: tests, fuzzing harness, debug mode and features excluded) must call the next one, including the
  login-attempt reader on each system, and the check-up and the corpus go through the same judge for forced logins
  (COM-CPT-003). Decompression: an extension's archive, the full MalwareBazaar list and gzip files (pacman databases,
  downloaded lists) are read before a deadline and, when their size is announced, with compressed bytes plausible for
  it: empty deflate blocks no longer hold the processor for minutes; an extension archive that is too slow is reported
  as “time limit exceeded”, not “unreadable”. An extension's archive also refuses two entries sharing the same bytes,
  and the same name twice.
- **macOS maintained, without Mac-specific new features.** The macOS program is still published and tested
  automatically on a GitHub Mac; it has never been tried on a real Mac, and the page, READMEs and key notes say so.
- **Optimize refused as administrator.** The Optimize tools (software, cleanup, settings, gaming, network
  measurements) refuse to run when Vanguard was elevated from an ordinary account (`sudo vanguard`, administrator
  console with UAC): they install, delete or read what the network sends, and each administrator action is already
  asked for when needed. “Undo everything” is never refused; root alone and Windows without UAC keep the tools, with
  the warning.
- **Kernel hardening is no longer undone.** On Linux, the fix that hardens the kernel (ASLR, ptrace, /tmp links…) is
  now a protection, like the firewall: it is no longer undone. An undo note never puts a kernel key back below its
  safe value, nor removes the 99-vanguard.conf file; those from 0.86 and 0.87, which stayed listed as undoable
  forever, are removed once, and this is said. If it gets in the way (a router, a VPN), removing Vanguard says how to
  undo it by hand: remove its line from the file, then `sudo sysctl --system`. A reglages.json accepted without an earlier seal (outside an update
  from a version that already seals, 0.86 or later) is no longer replayed as administrator, like public Wi-Fi mode
  and the backup. A history from a version without seals (0.85 or earlier) is therefore no longer replayed: its
  Optimize settings can no longer be undone by Vanguard; its copy is kept next to it (reglages.adopte-….json), only
  one per content, and this is said once.
- **Windows hardening and Defender protections are no longer undone.** The fourteen Windows hardening settings
  (WDigest, NLA, LSA, UAC…) and Defender's protections (ASR rules, network protection, unwanted software, controlled
  folders), whether set by the check or by Optimize, are now protections: “Put everything back” no longer undoes
  them, and a forged undo note can no longer lower them as administrator. The person can still change them in
  Windows. Their notes from 0.86 and 0.87 are removed once; Vanguard only remembers that it set a Defender
  protection, so the check can say more loudly that it was turned off afterwards. To be proven in the Windows VM.
- **Post-quantum on Windows.** The version of Windows' OpenSSH server is read (its `%SystemRoot%\…` path is
  expanded): COM-PQC-001 no longer calls it unreadable.
- **USB key: rescue images back by default.** The repository tools make the rescue key everywhere again: Ventoy, the
  installation and repair images (SystemRescue, Arch, Omarchy, Debian, Fedora, each checked against its project's
  signature), Windows 11 and macOS recovery. A `CLE_SECOURS=non` line in `~/.config/vanguard/images-cle.conf` turns it
  off on a computer (the key then only carries the program); Kali Linux stays optional (`IMAGES_EN_PLUS="kali"`).
  Booting the key on a real computer has not been tried yet.
- **AUR packages sent only with your consent.** On Arch Linux, the check sent aur.archlinux.org the name of every
  package installed outside the official repositories, without asking (rule LNX-MAJ-006, and AUR updates when yay or
  paru is there). A new setting, Settings › AUR packages (13th, off by default), gives this consent; without it,
  nothing is sent and these packages are reported as not checked.
- **Closed list of what leaves.** Vanguard now reaches over HTTPS only a closed list of sites, even at the end of a
  redirect (only rdap.org may forward to a domain's registry, and on GitHub only the repositories read are allowed); the threat model names them all, with the direct
  connections (DNS, STUN, blocklists) and what leaves towards each. A test fails if a destination written in the
  code is missing from the page. The age of an examined link's domain is read again (rdap.org's redirect to the
  registry was refused); the DNS check's made-up name no longer names Vanguard and no longer leaves offline.
- **MITRE ATT&CK coverage map.** Rules cite the ATT&CK technique they detect (T…) or the mitigation they apply
  (M…) in their references, like CIS: 160 rules out of 206. A generated page,
  [COUVERTURE-ATTACK.en.md](COUVERTURE-ATTACK.en.md), sorts them by tactic (ATT&CK version 20) and shows the
  techniques no rule sees yet: the list of gaps, kept up to date by the code. A test rejects an identifier that does
  not exist, or no longer exists, in ATT&CK, and `outils/verifier.sh` a map that is out of date.
- **Threat model.** A page says what Vanguard protects, against whom, what it does not protect (an attacker who is
  already administrator, the kernel, a threat still without a signature…) and what it assumes
  ([MODELE-DE-MENACE.en.md](MODELE-DE-MENACE.en.md)); the README and `vanguard --help` point to it.
- **Release publishing and key** (attack campaign no. 4). Resuming an interrupted deployment no longer lets what
  changed on the key in the meantime into its reference: if nothing else differs, what the deployment puts there and
  that differs is removed from the key, then put back, and each removed file is named along with what will put it back
  (a Mac program without a retrieved build, or the tldr examples offline, do not come back); if anything else differs,
  nothing is removed and the resume is refused, the key keeping the evidence. The safe point the backup key never goes
  past can also be forged with the stolen main key: when it is signed by that key, its versions (date and start of the
  checksums) are shown to the author, and the backup key signs nothing, not even the release manifest, until
  “contresigner” is typed in a terminal (without a terminal, it refuses). Only the author knows what they published: a
  forged version under a number they recognize, with no date or checksum they notice, still gets through. Claude on
  GitHub no longer starts on an issue or pull request written by anyone but the owner, nor on a thread where someone
  else commented or reviewed, nor on an issue from the key's log (written from any computer): it would read them as
  instructions. Just before Claude, the thread is locked and read again, which closes the minutes between this check
  and Claude reading it; a second `@claude` on the same thread waits for the first to end, which would otherwise
  unlock it under the second. The threat model states what remains.
- **Argument that is not UTF-8.** An error logged to the key's journal during a command with an argument that is not
  UTF-8 (a file name) no longer aborts Vanguard: the command is written there with “�” in place of the unreadable
  bytes.

## October 24, 2026: version 0.87

- **USB key and release security** (third attack campaign). When the key is plugged in, it is compared with its
  reference before anything is written: a file planted while it traveled (shortcut, image, Ventoy menu, tldr archive)
  no longer becomes “the key has not changed”; nothing is written to it, a notification says so, and only
  `outils/deployer.sh --accepter-cle` takes the key as it is. The tools only recognize the key by its token known to
  this computer, like the program: a volume labeled VANGUARD no longer receives the program or the source code. ISO
  images are tracked by their SHA-256 checksum, re-read one at a time, and copied again if they were replaced; the
  VTOYEFI boot partition, by the checksum of its files. The key's error log makes at most 5 GitHub issues per run (10
  a day), and nothing from a suspicious log without the author's consent. Release signing keeps a safe point the
  backup key never goes past; published programs are, byte for byte, those built from their commit (the published
  0.86.0 is indeed its commit's build: only the CI's C compilers differ). Claude on GitHub no longer acts on a pull
  request from a fork. The VM test queue only runs signed jobs (HMAC with the secret drawn when it is installed, to be
  redone once), and its verdicts are signed.
- **USB key: the program alone by default.** A key prepared by the repository tools, on any computer, now only
  carries Vanguard, its database, its reports and the VANGUARDLOG partition: no installation images, no Ventoy, no
  WIN11 or MACOS partitions. The full rescue key is only made on a computer whose local setting asks for it
  (`CLE_SECOURS=oui` in `~/.config/vanguard/images-cle.conf`, with `IMAGES="…"` and `IMAGES_EN_PLUS="kali"` if
  needed; read, never run); without it, the commands that would add images refuse and say how to turn it on, and the
  copy timers copy nothing. The project page gets its “Download, check, install” section: the program for your
  system, its checksum checked against `SHA256SUMS.txt`, then `vanguard shortcut` and `vanguard self-update`; the USB
  key as an option, for troubleshooting.
- **Menu window.** On Linux (Hyprland), the frame keeps a fixed height from one menu to the next: every size change was animated, and the transition showed. On Windows, the window still follows each menu's height but stays where it was put (brought back on screen only if it goes off). Near the bottom of the screen, it moves up only as much as needed; in the legacy console (conhost), which does not report its size changes, the menu redraws anyway.
- **Offered software.** Bitwarden installs from Flathub on Arch (the distribution package stayed at 2026.3.1) ; Flathub
  now only ships its commercial build, which is therefore shown as not open source, while winget and Homebrew install
  the GPL-3.0 build. VeraCrypt is for USB sticks, external drives and vaults, the system drive going to BitLocker or
  LUKS.
- **Wording.** All French text is now formal (« vous ») and says « routeur », « réseau local » and « adresse
  Internet publique » instead of « box » and « maison »; “Is someone controlling my PC?” becomes “Is my computer being
  controlled?”. `outils/textes.py` now rejects informal French in displayed text. Hourly monitoring and the monthly
  check-up record the generation of their texts: the first run after the update compares findings without their
  wording, by what names their object (addresses, ports, CVEs), with no false alert. Alerts marked normal, matched by their text when they have no key, may come
  back once in French.
- **Booby-trapped data.** A crafted tldr-pages archive (empty deflate blocks, entries sharing their data) no longer
  freezes the command guide: it is refused for its shape, and reading stops after 5 s; a "fresh" archive on the key is
  checked like the others, refused if damaged or dated in the future. Program memory: a library rewritten in memory,
  a program deleted or placed on tmpfs is read in full, its regions stitched back together (header and code together,
  the entry point where it belongs); what cannot be judged is said unchecked, never ✔. A fake access point copying
  the router's address on another channel is reported. Never again "nothing found" for a file to check that is a link
  or a pipe, for a Windows log present but empty, or for a list cut at its limit (Wi-Fi profiles, sessions,
  accounts); a fake GameMode no longer postpones the weekly self-test forever; comparing the key with its manifest
  no longer follows a link or waits on a pipe. File analysis, not wired in yet, sees
  archives appended to an image, macros where only the compiled code counts, procedures hidden by a line
  continuation and OOXML relationships hidden by an XML detail.

- **New menu.** Defense first: under "Security check" (1 to 3, unchanged), the **Cyber defense** part (4 This computer,
  5 Network and Internet, 6 Viruses and spyware, 7 Scams and privacy, 8 Block and respond), then **Also included**
  (9 Data and backups, 10 Command guide, 11 Step-by-step troubleshooting, 12 Optimize and install, 13 Vanguard). No
  screen scrolls any more: variants move to a choice screen (6.1 Antivirus scan › quick, full, USB drive, YARA;
  5.1 Devices on the network; 4.8 For developers; 9.3 Check a copy or backup; 13.4 Verify Vanguard itself), also
  reachable by its path ("6.1.3"). Lines specific to one system go at the end of their group: Defender is always 4.10.
  New in the menu: Startup programs (12.4), Event log (8.6), Check rules (13.5), the hash and the self-test (13.4), and
  incident shortcuts (8.3 to 8.5, to guides 11.7, 11.10 and 11.11). The prompt says "Number, or a word to search"; the
  first opening says so at the top of the menu. Paths 1, 2, 3, 5.2, 10 and 11.1 to 11.12, the letters from before 0.43
  and "s" do not move; the other paths changed meaning (nothing changes without your consent):

| 0.86 | 0.87 | | 0.86 | 0.87 | | 0.86 | 0.87 |
|---|---|---|---|---|---|---|---|
| 4.1 Security audit | 4.1 | | 5.14 Public Wi-Fi mode | 5.9 | | 6.20 Docker images | 4.8.2 |
| 4.2 Updates | 4.2 | | 6.1 Quick scan | 6.1.1 | | 6.21 Threat blocking | 8.1 |
| 4.3 Repair and clean up | 11.13 | | 6.2 Full scan | 6.1.2 | | 6.22 Dangerous sites | 8.2 |
| 4.4 Diagnostic | 11.14 | | 6.3 USB drive or folder | 6.1.3 | | 6.23 Latest flaws | 4.3 |
| 4.5 Integrity | 4.4 | | 6.4 YARA scan | 6.1.4 | | 6.24 Suspicious email | 7.2 |
| 4.6 What Vanguard has learned | 13.2 | | 6.5 Process memory | 6.4 | | 6.25 Spyware | 6.2 |
| 4.7 Why is it slow? | 12.3 | | 6.6 Decoy files | 6.5 | | 6.26 Outdated software | 4.9 |
| 4.8 Computer specs | 4.6 | | 6.7 Defender | 4.10 | | 6.27 Report a flaw | 8.9 |
| 4.9 Report to leave behind | 4.7 | | 6.8 Sandbox | 6.7 | | 7.1 Software | 12.1 |
| 4.10 What Vanguard changed | 8.7 | | 6.9 Password leaks | 7.4 | | 7.2 Gaming | 12.6 |
| 4.11 Monthly check-up | 4.5 | | 6.10 Browser passwords | 7.5 | | 8.1 Clean up | 12.2 |
| 4.12 Settings | 13.1 | | 6.11 Email leaks | 7.6 | | 8.2 Recommended settings | 12.5 |
| 5.1 Scan the network | 5.1.1 | | 6.12 Who talks to the Internet? | 6.3 | | 8.3 Privacy | 12.11 |
| 5.3 Deep scan | 5.1.2 | | 6.13 Camera and mic | 7.7 | | 8.4 Performance | 12.13 |
| 5.4 Name a device | 5.3 | | 6.14 Privacy check | 7.8 | | 8.5 Comfort and files | 12.12 |
| 5.5 Monitoring | 5.7 | | 6.15 Remote control | 7.3 | | 8.6 Fastest DNS | 12.7 |
| 5.6 Dashboard | 5.8 | | 6.16 Is this link dangerous? | 7.1 | | 8.7 Put everything back | 8.8 |
| 5.7 Watcher (Linux) | 8.10 | | 6.17 Check a file | 6.6 | | 9.1 Back up or restore | 13.8 |
| 5.8 Connection test | 12.8 | | 6.18 Quarantine | 6.8 | | 9.2 to 9.3 Copy, automatic backup | 9.1, 9.2 |
| 5.9 Blocklist | 5.6 | | 6.19 Git secrets | 4.8.1 | | 9.4 Check a copy | 9.3.2 |
| 5.10 Crowded Wi-Fi | 12.10 | | 9.5 Check my drive | 9.4 | | 9.6 Shortcut | 13.9 |
| 5.11 NAT type | 12.9 | | 9.7 My computers | 13.6 | | 9.8 Protect the key's data | 13.7 |
| 5.12 Hidden cameras | 5.5 | | 9.9 Update Vanguard | 13.3 | | 9.10 Check my backup | 9.3.1 |
| 5.13 Box and connected devices | 5.4 | | 9.11 Remove Vanguard | 13.11 | | 12 Extensions | 13.10 |

- **Software: seven more, two categories.** Ente Auth (two-factor authentication, first in "Accounts and
  encryption", formerly "Security and privacy"), Proton Pass, Mullvad Browser, Mullvad VPN (the only paid one, said in
  its role), LuLu (macOS), Kopia (Windows, macOS) and Déjà Dup (Linux), each from its publisher's source, checked
  online on October 24, 2026. Two categories at the end, without shifting the numbers: "Privacy and network" (Tor
  Browser, Mullvad Browser, Proton VPN, Mullvad VPN, Wireshark, LuLu) and "Backup". Proton Pass, Mullvad Browser and
  Kopia are not offered on Linux: their Flathub does not come from the publisher. Last line of the screen: update the
  whole computer (4.2). Search only offers the software that installs on this computer.

- **Small keyboard lists.** The letter questions (quarantine: restore or delete; dangerous sites: block or remove;
  who talks to the Internet: the abuse.ch key; protecting the key's data; my computers) become small lists drawn
  under the result, without erasing it: ↑ ↓ and Enter, the letter still a shortcut (it moves the marker, Enter
  confirms). Extensions: "↵ Back" like everywhere, instead of "0".

- **Command guide.** A new page at the end, 10.10 "Vanguard commands": every command, sorted like the menu, with
  what it does and its place in the menu, generated from the program (never copied by hand). The cursor opens on the
  computer's system. Each program and command page ends with its path and command ("Path: 10.6.7.2 · vanguard guide 6.7.2").
  `vanguard guide <path>` opens a page directly; `--summary` lists a system's programs with their path. No earlier
  path changes (test).

- **Search.** A word typed in the main menu finds every tool, its variants, the guides, the guide pages, the
  catalog's programs ("gimp" opens its category) and the Settings, ranked by relevance: the title before the rest,
  synonyms ("box" → router, "ransomware", "password", "update") and a typo corrected and said ("imprimnte"). Old
  command names can still be searched for ("harden" leads to Defender). `vanguard search <words>` does the same from
  the command line: the ten best, with their place and command; `--first` opens the best, `--json` for a script.

- **Renamed commands.** Whole words, no abbreviations, following the menu's labels; the English alias really
  translates the French name. The old names are no longer accepted: a script or task that calls them needs updating
  (the tasks Vanguard sets up itself keep their names). New commands: `rapport` (`report`), `annuler` (`undo`, like
  `optimize undo`) and `protection` (the state of each switch; `on` or `off` acts on real-time protection). Switches
  take `on|off`, `yes|no` (and the French `oui|non`, `marche|arret`) and `status`. `vanguard -h` gives the essentials
  in a few lines, `vanguard --help` every command sorted like the menu, generated from it.

| 0.86 | 0.87 | | 0.86 | 0.87 |
|---|---|---|---|---|
| `complet / full` | `bilan / check` | | `tableau` | `tableau-de-bord` |
| `machine / audit` | `audit` | | `fiche` | `fiche-ordinateur` |
| `reseau / network` | `appareils / devices` | | `durcir / harden` | `defender` |
| `maj / update` | `mises-a-jour / updates` | | `a-laisser` | `rapport-a-laisser` |
| `motdepasse / password` | `fuite-mot-de-passe / password-leak` | | `sauvegarder / backup` | `exporter / export` |
| `courriel / email` | `fuite-courriel / email-leak` | | `restaurer / restore` | `importer / import` |
| `navigateurs` | `mots-de-passe-navigateurs` | | `gaming` | `jeux / gaming` |
| `sortantes / outbound` | `connexions-sortantes / outbound-connections` | | `plugin` | `plugins` |
| `distance` | `acces-a-distance` | | `diag (alias)` | `diagnostics` |
| `acces / permissions` | `bilan-confidentialite / privacy-review` | | `apps (alias)` | `software` |
| `objets / iot` | `objets-connectes / smart-devices` | | `ext (alias)` | — |
| `cameras` | `cameras-cachees / hidden-cameras` | | `traces / evidence` | `depanner traces / troubleshoot evidence` |
| `canaux / channels` | `canaux-wifi / wifi-channels` | | `proche / relative` | `depanner proche / troubleshoot relative` |
| `connexion / connection` | `test-connexion / connection-test` | |  |  |

- **Results for scripts.** `diagnostic`, `lenteur`, `connexions-sortantes`, `acces-a-distance`,
  `bilan-confidentialite`, `test-connexion`, `lien`, `objets-connectes` and `listes-noires` take `--json`, in the same
  format as `logiciels-espions`: the findings, what was checked and what was not, never "safe" by default. Under
  `--json`, nothing is asked or changed; `lien` and `listes-noires` go on the Internet only with `--internet`, consent
  given in advance. Each examination, on screen as in JSON, is kept for the report and the event log.
  `protection --json` gives each switch's state, without changing anything.
- **Key tools in Rust.** At deployment, Vanguard itself checks the shipped vanguard.exe (DLLs loaded from System32,
  manifest read where Windows reads it), writes the key's markers and puts fully checked tldr-pages archives on it
  (CRC-32 of each entry, no overlap): no more Python at deployment. CI compiles the original YARA rules with the
  program's own engine. The key launcher no longer mistakes a missing or blocked PowerShell for a Defender block, and
  calls PowerShell (and the other Windows programs) by its full path in System32: a powershell.exe dropped at the root
  of the key is no longer started in its place.
- **The system read directly.** No more external programs where the system answers by itself: Wi-Fi read through
  the WLAN API, NetworkManager (bus, read only) and the kernel, without netsh, nmcli or iw, and a too-old list of
  nearby networks is reported as not verified; service state from systemd over the bus; TPM chip read without
  administrator rights; listening ports, gateway, ARP table and router echo from the system tables (Windows, macOS),
  with a ping that no longer mistakes a "host unreachable" for a reply; accounts in the traces and log export without
  PowerShell or wevtutil; links and files opened without cmd; startup programs in the antivirus menu read without
  PowerShell, and an unreadable source is no longer shown as empty.
- **macOS without go-between tools.** Processes, network sockets, the routing table, swap, SIP, startup options,
  mounted volumes, DNS, proxy and network services are read straight from the kernel and configd; ps, lsof, scutil,
  networksetup, csrutil and nvram are only fallbacks, and tests compare both on a real Mac. A custom SIP configuration
  is reported as reduced; startup options are judged for the current startup and the next one; the diagnosis reads
  the model, graphics card and disks even on a Mac set to French; incident traces put Vanguard's own reading next to
  the tools' output, so a replaced tool shows; `logiciels-espions` now checks connections on macOS.
- **Linux read by Vanguard itself.** Bluetooth, DNS over TLS, fwupd, NetworkManager, systemd (units, timers,
  backups), sessions and last logins (utmp, wtmp, lastlog2, wtmpdb, logind), the systemd journal, crashes, the network
  part of the traces, the pacman cache, dpkg --verify, Docker and snapd are read through D-Bus, netlink and their
  files, no longer through tools a rootkit can replace; what cannot be read is reported as impossible, never healthy.
  In the traces, the tools' output stays alongside as a witness, and a discrepancy between the two is flagged. Unit
  activations, notifications and Déjà Dup settings go through a closed list of D-Bus actions, on the session bus only.
- **Shell-free blocking.** Every step done as administrator is an order from a closed list, with typed parameters,
  that Vanguard judges again itself before acting (remote sessions, local network, ports 22 and 3389 never touched).
  On Linux and macOS, Vanguard relaunches itself (pkexec, run0 or sudo) instead of running "sudo sh -c"; nf_tables is
  written directly through netlink, connections already open are cut by the kernel (failure reported) and a process
  is stopped without a race on its number. On Windows, Firewall rules go through its interface, and a list mixed with
  PowerShell asks for a single consent, in Vanguard's name. Undo notes written by earlier versions can still be
  replayed as they are.
- **Vanguard's own antivirus, first building block.** Vanguard reads the files it scans by itself (Windows, Linux and
  macOS programs, Office documents and their VBA macros, shortcuts, scripts, zip, gzip and tar archives), bounded
  against booby-trapped files (decompression bombs, archives that contain themselves); what it cannot read (7z, RAR,
  ISO, PDF, encrypted, truncated) is reported as unchecked, never clean.
- **Home-made YARA.** The 308 ReversingLabs rules are applied by a YARA engine written for Vanguard (multi-pattern
  search after Aho-Corasick, pe and elf modules); a rule it does not understand is refused, named, and makes the scan
  incomplete, never clean. YARA-X now only checks this engine in the tests, with no discrepancy: the Windows program
  drops from 34 to 18 MB, with 150 fewer libraries.
- **Windows event logs read by Vanguard itself (first part).** A home-made .evtx reader, written from Microsoft's
  specification, bounded against booby-trapped files and fuzzed, reads the logs on Linux, macOS and Windows; one event
  shape serves both files and the running Windows, with refusals stated (security log without administrator rights,
  missing or unreadable log) instead of silence. Event numbers reveal removed events (partial wipe), without taking a
  rotating log, a damaged chunk or a copy made while writing for a wipe; a damaged chunk is read anyway, its events
  marked unverified. Eleven in-house rules (EVT-), written from Microsoft's documentation and ATT&CK, judge these
  events: cleared traces and removed records, attack service, extra administrator, guessed password, Remote Desktop
  from the Internet or through a tunnel, other credentials, malicious PowerShell, disarmed Defender, BITS, WMI
  persistence, reduced audit policy. A missing, refused, empty, silent, damaged or unaudited log makes the rule "not
  verified", never "nothing seen". `vanguard windows-logs [--folder D] [--days N] [--json]` answers "What
  happened?": each rule's verdict, the alerts in time order with account, program, address, log and number, the
  period really read per log and what is left beyond the limits; on this Windows, or on a folder of .evtx from any
  system. The report has its "Windows logs" section, the evidence's CHRONOLOGIE.txt places the alerts at their time,
  and an alert that is not critical can be declared normal. Tried on a real Windows 11 installed the same day, these
  rules no longer raise alerts for what Windows itself does: blocks PowerShell judges suspicious with no recognized
  attack pattern (its own modules) make one information line per script, saying how many; Windows setup and Windows'
  OpenSSH server use credentials without an alert; the WMI subscription Windows sets up itself is no longer reported;
  the first administrator created by setup is called so when the installation date and the security log confirm it.
  In-memory code loaders, memory dumps, token theft, keyloggers and fake sign-in windows are recognized too.
- **Windows, two fixes seen on a real Windows.** Wi-Fi on a computer without a Wi-Fi card (desktop, virtual machine) is "not applicable" instead of "not checked" when the WLAN service is stopped. The list of programs to update goes back through PowerShell when winget, run directly, answers with an error and no table: it said "not checked" in a virtual machine.
- **Dependency security.** crypto-bigint 0.7.6 (advisory RUSTSEC-2026-0387: computations meant to always take the same time did not), brought in by YARA-X.
- **Continuous checks back to green.** The Windows program reserves 8 MiB of stack (1 MiB by default with MSVC: the debug build overflowed at startup); journal issues no longer go through Claude on GitHub; nightly fuzzing finally runs (cargo-fuzz installed separately, checksum verified); the reproducible build checks the DLL guard with a recent enough linker.
- **The attack words it searches for are no longer in the clear in the program.** The offensive-tool command names and AMSI bypasses Vanguard recognizes in scripts are scrambled in the binary (decoded in memory when needed), so an antivirus does not take Vanguard for the tool it hunts. Nothing is hidden: the source stays in the clear, and a guard inspects the binary so that none of these words comes back into it in the clear.
- **State security.** What Vanguard keeps on the computer no longer turns against it. A named pipe or a link to
  /dev/zero put in place of a state file no longer freezes Vanguard (even `--version`, monitoring, the watcher) nor
  makes it load without end: every file read back is read as a plain file, bounded. The record of changes
  (`changements.jsonl`), the settings that turn a defense off (`parametres.json`: offline work, self-test, software
  versions; `blocage.json`: categories turned off), the administrator accounts and Bluetooth devices already seen, and
  the known keys are sealed: changed outside Vanguard, nothing in them is replayed as administrator, nothing in them
  turns anything off (an ignored setting is said in Settings, the blocking menu and the check-up, and can be set
  again), and what was already seen is reported again. Files taken over from an earlier version at the update keep
  their values; accepted after the seals were deleted, they turn nothing off and are not trusted. A block noted
  before the seal is only undone by itself if it can be judged
  again without its note (a firewall rule, a program put back at startup), the rest by hand. “Put everything back”
  never replays an old note as it is: it goes through the order guards (SSH and Remote Desktop are never reopened).
  A port closed by ufw without a read-back is said “not verified”, not “blocked”. The event log is written in two
  steps: lines added without its head read as tampered, then as a break reported at the check-up, never taken in as
  Vanguard's own. Deleting the seals with their lock no longer brings back the first use, and a month placed “in 2099”
  no longer links an action to a false cause. The log, the seals and the device database are never written without
  their lock any more (a system lock, released as soon as a Vanguard stops, which respects an earlier version's): two
  Vanguard writing at once on a slow Windows no longer make the log look tampered. An event that waits too long is
  put off until the next write or the end of the program, the rest refused, and the error log says so, never half
  written; a lock held without end is reported at the check-up.

## October 23, 2026: version 0.86

- **Spyware.** `vanguard spyware` (or `logiciels-espions`; Antivirus and protection menu, last) looks for signs of
  spyware planted by someone close: current connections and recently asked names going to known spyware servers and
  sites (list from the Échap association, CC-BY 4.0, downloaded when used and kept a day, never embedded), known
  monitoring software installed or running (FlexiSPY, Spyrix, Refog, Ardamax…; parental control and employee
  monitoring called normal if installed on purpose), programs reading the keyboard (Linux: /dev/input; recognized:
  compositor, key remappers, Steam, OBS), Input Monitoring, Accessibility and Screen Recording permissions (macOS,
  read by a SQLite reader written for Vanguard). Everything is read in Rust, without external commands. Read-only:
  nothing is removed, since whoever planted it could notice; the screen says to keep screenshots and ask for help
  first. What could not be checked is counted, and the verdict is never “no spyware”. In the full check too, without
  network.
- **Outdated software.** `vanguard outdated-software` (or `logiciels-perimes`; Antivirus and protection menu, last; in
  the full check on Windows and macOS) compares the installed version of browsers (Chrome, Extended channel included,
  Edge, Firefox and ESR, Brave), Office, Acrobat and Reader, Java, 7-Zip, PuTTY and Slack with the latest published:
  public files from the publishers, endoflife.date and Homebrew (formula.json, also taken on Windows for 7-Zip and
  PuTTY, whose formulae follow upstream), downloaded in full once a day, the same for everyone: the list of your
  software never leaves the computer (Settings › Software versions to turn these downloads off). The version is read
  in the file itself (a reader of .exe version resources written for Vanguard, Info.plist, Homebrew Cellar folder),
  for all accounts as administrator; per-account Slack in its version folder, not its launcher. Firefox: each
  exploited flaw in CISA's catalog is checked against the installed version (Mozilla security advisories); Edge Stable
  likewise, from the flaws Microsoft says each version fixes; a version older than the fix is critical. For the
  others, the number of exploited flaws of the product in the catalog, without concluding for the installed version
  (Slack embeds Chromium, but its flaws do not carry over to it). What has no source (Edge Extended Stable, Acrobat
  2020 and 2024, App Store) is said not checked, as is a Slack answer of an unexpected form (its API is undocumented),
  a disabled or deprecated Homebrew formula, or an Edge flaw list of another form; a browser that cannot be compared
  keeps the 60-days-without-update check, which leaves end of support. formula.json, cask.json and endoflife.date are
  read as a stream, with a cap on entries: a small hostile file no longer makes the program allocate gigabytes. The
  history no longer shows “fixed” then “new” for software whose version changes while still out of date. On Linux, the
  command points to the package manager. The zip reader (command guide) drops an entry whose content does not have the
  announced size, which could exceed its limit; gzip and zip join the fuzzing bench.
- **Public Wi-Fi mode** (`vanguard public-wifi`, Network and Internet › Public Wi-Fi mode). Turn it on when arriving
  at a café, a hotel or an airport, turn it off when leaving: the computer no longer accepts any connection from that
  network (an SSH session already open stays), file sharing and the announcement of its name are off (on macOS, the
  firewall closes sharing; Bonjour and AirDrop stay), and the DNS switches to the Canadian Shield “Protected”,
  encrypted on Linux when systemd-resolved answers (a resolver on the computer, such as NextDNS, is kept, and so is a
  DNS already encrypted and filtering, provided all its servers filter: otherwise the Shield is set, and the check no
  longer says such a DNS blocks dangerous sites). On Linux, a separate nftables table, which also closes transit
  coming from the Wi-Fi adapter (a container port published by Docker, podman or k3s, which goes through DNAT then
  `forward` and never `input`, can no longer be reached from the public network), and services masked until restart,
  then mDNS, LLMNR and encrypted DNS on the public network's profile only; on Windows, Public category, firewall
  Public profile closed to incoming connections, NetBIOS off, in a single administrator prompt; on macOS, firewall set
  to “block all” and stealth mode. Incoming connections that could not be closed (no nft, unreadable firewall, on
  Windows a network left Private, a company network or an unreadable category) are stated in the menu and the check,
  “on, incoming open”, never “everything in place”; a setting that cannot be read back shows as not verified, never ✔.
  On Linux, a DNS, encrypted DNS, mDNS or LLMNR undone by a program of the account (NetworkManager allows it without a
  password) shows in the check (Medium), on the menu line and in its header, with a way to put it back. Each change is
  shown with its previous value, noted and sealed before the first command; turning off puts everything back in
  reverse order, read back, even after a crash or a restart (the menu and the check say so). A state changed outside
  Vanguard is never put back: safe shutdown instead, which only removes Vanguard's table. A firewall found off is
  turned on and never turned off again. `vanguard public-wifi portal` reopens the network's sign-in page: encrypted
  DNS is relaxed until Enter, ten minutes at most, and the next launch makes it strict again if Vanguard was closed
  before. Nothing is sent to recognize a public network: a suggestion only. Tried on Linux (table set then removed in
  a separate namespace, previews); Windows and macOS: compiled and partly tested, not yet tried on a real system, nor
  encrypted DNS on a real public network.
- **Menus: arrow keys, and a window that fits.** In the menus, → runs the selected line like Enter (except when it
  completes a search prediction) and ← goes back like Esc; during a search, ← clears it. On the main menu, ← does
  nothing: one press too many when leaving a submenu would close Vanguard (Esc and q always quit). In checklists, ←
  goes back but → does not confirm: these lists start changes (clean up, uninstall), only Enter confirms them. “Enter
  to go back” pauses are left with a single key (Enter, ←, Esc or Backspace), typed questions go back with ← or Esc on
  an empty line, and leaving a tool with “back” no longer asks for one more pause. At each menu, the window takes 78
  columns and the menu's height, bounded by the screen, then centers itself; only a window opened for Vanguard: under
  Hyprland, its terminal's floating window; on Windows, a console where Vanguard is alone, the old console or Windows
  Terminal. Elsewhere, nothing moves.
- **Check-up fixes can be undone, one by one, and “Put everything back” undoes it all.** Before each fix (Linux,
  Windows, macOS), Vanguard reads the previous state of what it changes (sysctl or sshd file written by Vanguard,
  kernel settings, service, network time, rights of a personal file, registry value, preference) and notes it, sealed,
  in reglages.json, like Optimize. “What Vanguard changed” undoes a fix marked “undoable”, then reads the state back:
  restored, or not (and why). A fix whose previous state cannot be read is called “not undoable” before it is applied;
  one that turns a protection back on (firewall, antivirus, BitLocker, UAC, SELinux, Gatekeeper) is never undone. “Put
  everything back” (`vanguard optimize undo`) now undoes check-up fixes, Optimize, Gaming, blocks and public Wi-Fi
  mode, from the most recent to the oldest, in one administrator request. Gaming settings go through the same
  mechanism: their notes in jeux.json, which was not sealed, are taken over without loss, only once, never over an
  adopted reglages.json. Fixes from the same “[a]ll” that touch the same file share one note: undoing one marks them
  all undone; two notes on the same target undone together are both put back, without a false ✖. A service enabled but
  stopped is said not undoable rather than falsely restored, and fixed ~/.ssh rights can be undone.
- **Undoing never reopens what a fix closed, nor replays a command.** reglages.json, whose values are put back as
  administrator, is sealed: rewritten by another program, it is no longer trusted (it is set aside, intact, and
  nothing from it is restored), and a reglages.json accepted without a seal is not resealed on reading: the check-up
  keeps saying so. Each value is checked when put back, against a closed list (a known service state, a boolean, a
  number, IP addresses, a simple word); a value of any other form brings back the fresh-system one, written in the
  program. A note for the sysctl and sshd files Vanguard writes is put back only if it holds the safe values Vanguard
  writes there (“ptrace_scope = 0”, “PermitRootLogin yes” or an added weak algorithm are refused), and their content
  is shown before the question; a note aimed at UAC is refused on Windows. Undoing a block, alone or through “Put
  everything back”, never replays a command text read from the evidence or from changements.jsonl (which any program
  of the account can write): the commands are rebuilt from the noted address, port or value, and an unrecognized block
  is refused and shown instead of running as administrator. Undoing only puts back a copy of Claude Code settings made
  by Vanguard, and “put back as before” for the gaming settings only rewrites as root what Vanguard puts in /etc.
- **Report a flaw to a vendor** (`vanguard disclose`, French name `signaler`; Antivirus and protection menu). An
  assistant prepares the draft of a vulnerability report, which the person reviews and sends personally. It sorts
  first: an already known flaw (CVE, CISA's catalog) is fixed by an update; malware, a missed detection or a phishing
  site are not flaws of the vendor (the right recipient is named, nothing is prepared); a bypass of AppLocker or of
  controlled folder access is said not fixed by default by Microsoft. For abnormal behavior, the draft follows the
  chosen program's format (MSRC, Google, Chrome, Mozilla, Apple, GHSA advisory, CERT/CC, CERT-FR, Vanguard) and takes
  the thread of an incident or a tool's examination, with the log's state (tampered: “not verified”; adopted or
  incomplete: “not proven”); it stays titled INCOMPLETE while what only the person knows is missing (their steps,
  what happened, the proof of concept MSRC, Apple and Chrome require). A healthy, unchecked or tampered examination
  settles nothing, and with no CVE cited, CISA's catalog is “not checked”, never “not in it”. What is personal is
  removed in three layers: nothing useless (no command line, no relative's account, no personal file name),
  everything masked (paths, names, addresses, query strings of web addresses), then a final check that refuses to
  write if a known name survives; the count is shown. The outdated software examination only carries the product hit
  by an exploited flaw, never the list of installed programs. Values from outside go into code blocks, the rest is
  neutralized (no mention, image or link). The text is shown in full, written after consent in Vanguard's folder on
  this computer (file 0600) and recorded in the log without its content; `--effacer` removes the drafts, which
  uninstalling counts first. Nothing is ever sent: no network code in the module (checked by a closed list of
  calls), no clipboard, no email.
- **Self-test** (`vanguard self-test`, French name `autotest`). Vanguard checks its own readings on the computer where
  it works, without changing anything there. Every check rule runs under a guard and a time limit, read only and
  proven so: a switch refuses any state write, even from a rule stuck beyond its time limit, and BLAKE3 fingerprints
  of Vanguard's folder, before and after, would name what changed (a monitoring pass during the test makes the proof
  inconclusive, never “changed”). Every finding goes through invariants. Ten cross-checks on Linux (pacman, dpkg,
  AUR, enabled and failed units, groups, listening ports, encrypted root, sshd version, resolved's DNS) and four on
  Windows (firewall, Defender, BitLocker as administrator, local accounts, as JSON) compare what Vanguard reads with
  what the system's tools say; the “like the tool” tests call the same functions. Offline by default (`--internet`
  for the rules that need it); `--json` holds no value from the computer, `--detail` shows the values on screen only;
  exit code 0, 1 or 2. Each rule's duration goes to the timings log (eight weeks, summarized per day), which reports
  a rule three times slower than usual or close to its time limit. Once a week, the monitoring redoes the
  cross-checks on its pass's check (“autotest” setting, postponed during a game under GameMode); a contradicted
  reading is stated next to its rules' sound findings, and the diagnostic shows the last self-test. A gap goes to the
  error log (identifiers, numbers, kind of gap, no value from the computer); `journal-vers-github.py` gathers the
  occurrences of one upload into a single comment and no longer mixes two identifiers in one issue. Never a false
  “sound”: two failed Defender or BitLocker reads, an unreadable `ss` line or unread account units give “not
  checked”, neither “same” nor “not applicable”; a contradicted reading stays announced, with its date, until a new
  run settles it; before five weeks of timings, the duration comparison is said not checked.
- **Ransomware watcher** (Linux, `vanguard watcher ransomware on`). The watcher can now watch the personal folders
  live (Documents, Pictures, Desktop, Music, Videos and Downloads): an encryption burst (dozens of files rewritten in
  seconds, content no longer matching its format, a ransom note, a decoy file touched, backup copies erased) raises
  an alert within seconds instead of waiting for the hourly decoy check, and “Block” is offered at the next check. No
  administrator rights and no new dependency: inotify, through the crate already present, sees files change, and the
  processes' write counters tell who writes. With active protection and an almost-certain case (a decoy touched and a
  burst attributed without ambiguity to one program), Vanguard freezes the program and its descendants, records the
  evidence, then stops and quarantines it, with all the blocking safeguards; a program a safeguard refuses to stop
  stays frozen, and this is said. Otherwise, Vanguard only alerts. Offered in the same consent as
  `vanguard watcher on`, off by default. Removing the decoys does not raise “possible ransomware”, and an alert from
  an encryption tool used on purpose can be declared normal. Stated limits: a malicious program in the account can
  switch the watch off, and a backup remains the real protection; a write through a hard link placed outside these
  folders escapes the live watch (decoys are still checked hourly).
- **Read-only post-quantum check.** Encrypted traffic recorded today can be kept and read once a quantum computer
  exists: the check says where this computer has no post-quantum key exchange, without changing anything and without
  any added library. SSH server and client (COM-PQC-001, 002): the list sshd and ssh really keep, from the OpenSSH
  version read without running it (sntrup since 8.5, by default since 9.0, ML-KEM since 9.9) and the “+”, “-” or “^”
  written in the configuration. The advice never names an algorithm that version does not know, never puts a name
  before a “+”, “-” or “^” (sshd would not restart) and says to run `sshd -t` first; a setting for a single host stays
  information, without the host's name. Browsers (COM-NAV-004): X25519MLKEM768 turned off by a Firefox preference or
  by a policy (Firefox; Chrome and Edge up to 146, beyond which the policy is said to have no effect). For Firefox,
  policies.json, then on Windows the registry (the policy and its Preferences) and distribution\policies.json; a
  preference set to false only by default counts as long as the profile writes nothing, and
  security.tls.enable_kyber, which Firefox refuses in Preferences, does not count. Without a cut, the version
  decides: Firefox before 132 and Chrome before 124 do not offer it by default, Chrome 124 to 130 offers
  X25519Kyber768, and an unreadable version (Brave, Vivaldi, Zen…) is not checked. WireGuard (COM-PQC-003): peers
  without a pre-shared key, counted without ever keeping a key; the files are read only as administrator, and without
  rights, without a file or encrypted for SYSTEM, the finding is not checked, reason given. In the network audit: the
  router administration (SSH, HTTPS found open by the scan) that offers nothing post-quantum, as one grouped piece of
  information (COM-TLS-004), and the path to the Internet that would remove the exchange (COM-TLS-005), through a
  hand-written TLS probe to the reference site already contacted, computing no key. A refusal is concluded only if
  interception already shows in the certificate, otherwise it is not checked; a proxy that is set or unreadable also
  leaves it not checked (on Linux, the GNOME or KDE desktop one included).
- **A linked, sealed event log.** Alerts, the evidence recorded before each action, blocks, quarantines and fixes,
  their undoing, alerts declared normal and version changes go into a single log (evenements/YYYY-MM.jsonl, on this
  computer only), append-only: each line carries the fingerprint of the previous one, the head is sealed, and so is
  each closed month, 13 months and 20 MB at most. A removed, changed or added line shows; an end that no longer
  matches is recorded in the log itself. A botnet server's alert, the evidence, the block and its undoing are linked
  (`vanguard events --incident <id>`), and a block can no longer be recorded without its evidence. The monitoring
  dashboard and the incident traces read this log (and the old one, which an earlier version still writes); a flaw
  from the KEV catalog is critical there. It is read with an overall bound (months, bytes, events), most recent first,
  and says what it did not read. A broken chain is reported by the check; files placed under the names of future
  months (2099…) do not count, are neither followed by writing nor counted by pruning, no longer push the real current
  month out of the read and the traces, and are reported; a clock running ahead does not empty the history, and a full
  month refuses to write rather than become unreadable. Spyware, outdated software and suspicious email return a
  result (`--json`), kept for the report (“Latest tool examinations”) and sealed: a “nothing found” rewritten outside
  Vanguard shows as not verified, never green. Errors from blocking, quarantine and the versions seen have a stable
  code.
- **Evidence before the action, and what Vanguard did in the traces.** Before stopping a program, quarantining a file
  or blocking an address, including on its own at night, Vanguard records what the action will erase: the program, its
  command line, its parent, its account, the file's SHA-256 fingerprint, the current connections. What cannot be read
  is noted “not possible (reason)”, and the block happens anyway; on Windows, the evidence does not wait more than 3
  seconds for WMI before stopping, and a reused process number is not described. The evidence is kept with the block
  (“What Vanguard changed” summarizes it); the quarantine keeps each file's fingerprint. “vanguard traces” now
  includes what Vanguard saw and did (07-vanguard.txt): its alerts, its blocks and quarantines with their evidence,
  and threads that link the alert, the evidence and the action about the same program or address; these landmarks
  enter the timeline, and Vanguard's state files are copied as they are so the MANIFEST covers them. A file deleted
  from the Quarantine menu, or after a ClamAV scan, reads “deleted” there, with its fingerprint recorded; traces run
  with sudo read the data of the account that ran them, and a named pipe or a link in place of a state file no longer
  blocks them. A single path leads to the quarantine: the antivirus and YARA ones are now noted and undone with
  “vanguard blocking undo”, like blocking's; it no longer follows links, and root no longer writes into an account's
  folder there. The same file downloaded again after a quarantine is offered for blocking again. The watcher judges
  programs with the same sources as blocking: it also recognizes MalwareBazaar's known fingerprints (those of the last
  48 hours, the full list does not fit in its memory), and no longer gets stuck on a file that does not respond (not
  hashed, reported as not checked). Installing ClamAV or a third-party tool is noted like any fix.
- **“This is normal” for monitoring, the watcher and blocking.** An alert that keeps coming back for no reason (a
  development tool started from /tmp, a known device) can be declared normal for 90 days in What Vanguard has learned,
  and a threat offered for blocking with “i”. The choice is about what the alert is about (the program, with its
  reason and script, the address, the device), not its text: declaring python3 normal for a command that downloads
  does not silence python3 running something else. It is forgotten in the same place. An alert is offered only if its
  kind matches its key, and what it designates is shown before choosing; a certain threat, and the alert of its block,
  are never silenced. The list is sealed: changed outside Vanguard, it silences nothing.
- **A problem recognized by its rule and its object, no longer by its translated text.** Open ports, suspicious
  autostarts, browser extensions, forgotten accounts or new administrators, stalkerware, remote control tools,
  outdated software and the VANGUARD key's record now carry a key (“LNX-RES-001|port:8080/tcp:python3”): switching
  language no longer brings back an alert marked as normal, no longer shows “new” problems in the history and
  re-notifies nothing in the monitoring. Earlier choices are found by their text, then completed with their key; a
  choice only covers its object (another program on the same port, another outdated version come back), and one choice
  per key counts, the most recent. On macOS, a launch agent is recognized by its file and what it launches, on Linux
  each suspicious autostart line by its fingerprint: a rewritten command or a line added to an already reported file
  is never silenced by an earlier choice. Monitoring re-notifies an alert that gets worse without changing key (an
  extension that gains access to all sites). The history keeps its first checksum unchanged and gains a second one,
  covering the keys and the network audit grades: a key is never outside a checksum, and a check without it is called
  not checked, compared on its text. The check's JSON gains `objet`, `cle` and `etat` (healthy, not applicable, not
  checked with its reason, problem). The inventory of state files gains the device record, its locks, the takeover of
  an earlier version and the traces folder, and its test also reads the data folder's variables.
- **A rule that returns nothing says “not checked”, never a silence read as healthy** (outside a list of tolerated
  rules that can only shrink). Wi-Fi is no longer silent when NetworkManager is missing (iwd, systemd-networkd):
  without a card, “nothing to judge”; with a card, not checked; an unreadable network card list (/sys/class/net) gives
  “not checked”, never “no Wi-Fi card”. On Windows, a network that netsh hides for lack of location access is called
  not checked; on macOS, unreadable stealth mode and Remote Login too. Only reading the firewall itself decides
  whether the grade holds: unreadable stealth mode no longer removes it on its own. A “not applicable” finding no
  longer counts among the checks for the grade's reliability. `vanguard rules` also shows the network audit rules and
  the tools: a single registry of identifiers, checked by the tests, with the inventory of state files from which the
  seals take the list to protect.
- **New check rules: SSH and Defender on Windows, passwords, startup and persistence on macOS, one reference and one
  time limit per rule.** Windows gains the OpenSSH server (service, %ProgramData%\ssh configuration, password sign-in,
  administrators_authorized_keys rights, read in Rust: registry, WMI, files and their rights) and the keys in
  %USERPROFILE%\.ssh (no passphrase, readable by others), WIN-SSH-001 and 002. An uninstalled server whose
  configuration stayed is not applicable; administrators_authorized_keys open to others is medium when StrictModes
  (the default) makes it refused, critical without it, and its files are bounded before being read. The check re-reads
  the Defender protections that “harden” turns on (ASR rules, network protection, PUA, controlled folders,
  WIN-ANV-003): a protection Vanguard set (Optimize or a check fix) and that was later turned off is a high alert; the
  basic blocking, network protection and PUA are offered, each fix can be undone; nothing is said to “block” while
  real-time protection is off, nor healthy when nothing blocks. macOS gains the password policy and account lockout
  (pwpolicy, MAC-CPT-002), startup security (bputil or T2 chip, MAC-DEM-001), login and background items (sfltool, as
  administrator, MAC-PRS-002), login hooks and authorization plugins (MAC-PRS-003); root's settings unreadable without
  sudo make the login hook not verified, never “no hook”. Catch-all rules are split: Windows hardening into five
  (WIN-DUR-001 to 005), plus Windows Update off or paused (WIN-MAJ-003) and automatic sign-in (WIN-SES-002); sysctl
  settings into three (LNX-NOY-003, LNX-NOY-007, LNX-RES-003), whose fixes append to the file instead of overwriting
  each other. A “this is normal” choice on the old grouped Linux kernel alert applies to the three new ones; at the
  first check after the update, the history may still show it fixed then new. Every machine rule cites at least one
  CIS, Microsoft or ANSSI reference (required by a test for all three systems), also given in the check's JSON
  (“reference”). A software inventory, kept sealed on the computer and never sent, tells for a week each program
  installed since the last check (COM-LOG-001): erased or changed outside Vanguard, it no longer hides what was
  installed meanwhile (everything is reported again); an update whose displayed name carries the version (“Tool 1.3
  (x64)”) is no longer new software; a source that cannot be read (silent Flatpak, unreadable ~/Applications) or a
  bound that is hit (subkeys, entries in a folder, 20,000 programs, many keys without a name) makes the check not
  verified instead of forgetting programs or silently truncating them; programs of other open Windows sessions no
  longer count. Finally, each rule has its time limit (10 min, 30 for updates): one that exceeds it is reported as not
  checked, the others go on. None of this has run on a real Windows or a real Mac yet: tests under Wine, clippy for
  macOS.
- **Update chain of trust.** A backup key, kept offline and encrypted from its creation, also signs releases: if the
  main key is lost or stolen, updates go on, and the backup key can revoke the main one (“revoque principale” at the
  end of the manifest, which stays readable by 0.85 copies); kept in the sealed state, the main key is then never
  accepted again, and the highest version seen starts over. The main key can be encrypted, its passphrase asked once
  per release (`outils/signer-versions.sh`, `--secours`, which refuses an unencrypted backup key). Vanguard remembers
  the highest signed version already seen and refuses an older manifest; a latest signed version older than 45 days, a
  clock running behind that would make an old manifest look fresh, or a copy here newer than the latest version signed
  on GitHub (an old manifest may have been put back) are no longer called “up to date” or “nothing newer”, but not
  verified. The macOS program only comes from a master build, without cache (a tag named master does not reuse one),
  and it is checked before it is signed (commit, checksum from its build log, universal Mach-O, version). The
  monitoring's local copy goes through the update path (never to an older version), and a new copy is tried before it
  replaces the old one (Linux and macOS); as root, a program in a folder others can change is no longer replaced.
  Signed version history: `vanguard self-check [program]` also checks a copy that is no longer the latest, changing
  nothing for copies already installed; run without a terminal, it no longer asks about the history, which quit before
  the final warning, and 0.85 is no longer said to be missing from the history.
- **Vanguard's state sealed.** `appris.json`, `integrite.json`, `surveillance-botnets.txt`, the versions already seen,
  the machine state from the last monitoring pass, the changes already reported by integrity monitoring, real-time
  protection and its reminder, the audit, the sites and the gateway already reported, the time of the last look at
  Downloads and the unblocked threats already reported carry a BLAKE3 checksum: changed outside Vanguard (by a program
  trying to silence its alert, or to pause protection), they no longer count and the check says so (COM-ETA-001);
  damaged, they never silence an alert. They are read only when they are plain files of bounded size (a named pipe
  froze monitoring forever); writing no longer follows links, and root no longer writes into an account's folder.
  Deleting `sceaux.json` no longer makes the state files accepted as they are: they stay “adopted”, reported by the
  check, and the versions already seen are then not trusted; the adopted integrity reference is still used for
  comparing and stays reported until it is accepted (a difference with it is still a difference, and moving to a new
  version does not stop monitoring), never remade without consent. Deleted along with the seals, the state files are
  “unknown” and everything is said again, and the check says the seals were remade; deleting the history at the same
  time no longer makes a first pass, and an updated 0.85 does not look like deleted seals. A critical file changed
  again is notified again.
- **Two attack campaigns against Vanguard itself**, on October 23: 18 weaknesses fixed by the first, then 10 bypasses
  and regressions of these fixes, and 12 by the second, each with its test. Those about a subject above are described
  there; here are the others. The USB key: its Ventoy menu and ISO images (by size) enter the manifest; a recognized
  key whose serial number changed is reported, a VANGUARD key without a reference, where other keys have theirs, is a
  medium warning (changing its token too no longer brings it down to information), and only a reference carrying its
  token accuses it of a changed identifier (an unreadable identifier no longer accuses anything). Local network: UPnP
  is read only at the gateway (a device claiming to be the router is reported), never towards this machine or another
  host, and listening goes on after an oversized datagram, without counting it; DNS is also tested on randomly drawn
  names. The MalwareBazaar list is only unpacked up to its announced size, the ThreatFox export is bounded the same
  way, and the sshd log only counts lines written by root. The attachment name of a suspicious email goes filtered
  (direction marks, control characters) into the result, the log and the report, like every written finding message.
  The nightly watch no longer deposits into the VM the program of a branch written by the AI (to run after review,
  `vm-tester.sh --branche`), and only passes the subject, file and line of a proposal to the AI that fixes.
- **Small safety fixes.** On Windows, system programs (netstat, netsh, powercfg, wevtutil, tasklist, schtasks,
  ipconfig, cmd, PowerShell…) are started by their path in System32, asked from Windows itself: a fake program of the
  same name placed next to Vanguard (Downloads) or in the current folder can no longer hide a port, a process or a
  setting; cmd no longer searches its current folder, and a test refuses any new start by bare name. The vulnerable
  drivers list (LOLDrivers) is only replaced by an answer that really is one: an error page no longer stops the check
  for a week. On macOS, a download's hash is computed in Rust, without md5 or shasum, and the Privacy check reads the
  permissions database with Vanguard's SQLite reader, without /usr/bin/sqlite3. Clean up: “Downloaded packages” is no
  longer recommended without paccache, and says it erases what lets you roll back. The menu, `--help` and the launcher
  use the showcase tagline (“Portable cyber defense for endpoints and networks”). Dead code removed and lighter
  dependencies (one crate less on Windows, fewer features compiled for reqwest, tokio and futures): 9 to 14 fewer
  libraries depending on the system.
- **Common base, no duplicates.** What all of Vanguard shares lives in `src/socle/`, once, tested once: Vanguard's
  folder, atomic write and lock (out of the network module), cache of downloaded lists (out of abuse.ch), an IP
  address's scope per the RFCs, home folder, Linux and macOS processes, JSON with comments, os-release, fingerprints;
  the package inventory leaves Gaming for `machine/linux/paquets.rs`, and `sha1_smol` and the hand-written MD5 give
  way to RustCrypto's sha1 and md-5, already pulled in by YARA-X (no extra crate). Some copies were wrong: an SSH
  attempt logged as “::ffff:192.168.1.5” looked like it came from the Internet; a Chrome policy with “1, // comment”
  before “}” was called unreadable; a held package had no version; a folder or a non-executable file with the same
  name passed for an installed program before a sudo command; an empty HOME made reads and writes start from the
  current folder. An unreadable /proc no longer counts as checked (spyware, keyboard readers, camera, remote control),
  and a /proc mounted with hidepid is reported. Threat lists and tldr are written by the atomic write (on Windows,
  Defender holding the old copy kept it in place). Run keys are read one way, the safest: “Is someone controlling my
  PC?” and “Spyware” also see RunOnce and malformed names, and “Spyware” reports an unreadable key. The check-up reads
  Wi-Fi through nl80211 and wlanapi, like the network audit (nmcli and netsh as fallbacks), and judges saved open
  networks the same way it does: the protection kept is the one Windows negotiated (a WPA2/WPA3 access point joined in
  WPA2 stays WPA2), two access points with the same name and different protections, with no known transmitter, defer
  to nmcli, and NetworkManager profiles are also read from /run (netplan) and /usr/lib, with nmcli as a fallback when
  a file is refused.
- **Quality and delivery.** `outils/verifier.sh` builds the fuzzing bench and spends a few seconds on each target (two
  more: the SQLite reader and the Échap YAML list); CI spends five minutes per target every night, and a bench without
  targets fails. Tests that cannot run on a computer (missing tool, root of a namespace) say they were “skipped”:
  `verifier.sh` counts them next to the passed tests and gives their reasons, and those skipped on the real Windows
  and the Mac of CI are counted and shown there. A green that checked nothing no longer passes: under
  `verifier.sh --seulement` (the nightly CI audit), a skipped or unrun step fails and an unknown step name is refused
  (tried by `outils/essais-verifier.sh`). The text check and a keyboard test of the menus, in a real pseudo-terminal,
  are in the repository. CI runs `verifier.sh` itself (a single logic), the real distributions count, Windows runs on
  each push, and the delivered .exe (MinGW) is tried on a real Windows; without `.github/hors-code.txt`, the night
  tests Windows and the Mac instead of skipping them, and every night, even with the author's computer off, the real
  downloaded sources are read back by their reader (format canaries). CI: `/dev/root` read by its device number like
  findmnt, enable links of vanished systemd units left out like systemctl, local HTTP client time bound adjusted for
  Windows; `claude-journal.yml` analysis only. A release page is only published if the VM ran that very .exe, and an
  .exe without its manifest (UTF-8, asInvoker) no longer builds; a failed download of the previous signed history no
  longer restarts it from scratch before deleting the previous pages: nothing is signed or published
  (`signer-versions.sh --premier` for the very first time). A single table of tools for the menu and the command line,
  compared by tests with the README, `--help`, the key's manual and the Structure table; `vanguard optimize`
  (including `undo`) joins the command line, and the help of the watcher, dangerous sites and latest flaws finds its
  command again. Pinned Rust toolchain (`rust-toolchain.toml`) and a shared build recipe
  (`outils/compiler-version.sh`): two builds in two folders give the same program. Extensions: isolation on macOS too
  (sandbox-exec), with no `open`, Apple Events, clipboard or plugged-in disks (/Volumes), through which an extension
  left the sandbox (profile not checked on a Mac), and author checked by an Ed25519 signature of the folder, whose key
  is kept at approval. Windows test program down from 520 to 314 MB; tests without a click in the Windows VM (a queue,
  `outils/vm-tester.sh`), menus included, in a real console. Continuous watch (`outils/veille/`): every night, without
  AI, verification, fuzzing and sources; on an alert only, a fix proposed in a separate branch, never merged or pushed
  by itself.

## October 22, 2026, evening: version 0.85

- **Release repository renamed** `d9v3/vanguard-update` (formerly vanguard-officiel). The old address redirects:
  Vanguard copies already installed still update.
- **Is this email a scam?** `vanguard suspicious-email <file.eml>` (Antivirus and protection menu, last) reads a saved
  email without opening anything: no link followed, no image loaded, no attachment run. It looks at the real sender
  (display name imitating a brand or hiding another address, replies sent elsewhere, look-alike domain), the SPF,
  DKIM and DMARC result written by the receiving provider — never one a sender slips further down, and a “pass” only
  counts when it surely comes from the provider —, each link (shown text against real address, offline link check,
  links rewritten by Safe Links unwrapped), the attachments (program, double extension, macros, web page, disk image,
  shortcut, password-protected archive, PDF that runs code) written under a neutral name in a disposable folder for
  YARA and the antivirus, never opened. After your consent, only the domain names leave the computer for their age
  and the public lists. MIME parsing written for Vanguard, bounded in size, depth and number of parts (a trapped email
  is marked incomplete, never said to be read). An Outlook .msg: the steps to save it as .eml. The verdict is never
  “safe”, and says what could not be checked.
- **The watcher (Linux).** Between two hourly monitoring runs, a program or a connection lasting a few minutes went
  unnoticed. The watcher, off by default and turned on only after its unit is shown (`vanguard watcher on`, or the
  Network and Internet menu), listens to two streams that Linux 6.6 and later opens to ordinary accounts: each
  program started, even one of a few milliseconds, and each TCP or UDP connection as it closes. Programs are judged
  as in the check (known offensive tool, command that downloads or hides what it runs, with their lineage:
  “npm → node → sh”), connections against the botnet command servers already downloaded; what is serious goes to
  the dashboard and as a notification, at a bounded rate. It stops nothing, without root or code loaded into the
  kernel. A program gone before it could be read is counted as such, never judged safe; the program of a closed
  connection is not known. The check says whether it is off, on, or on but stopped.
- **Remove Vanguard from this computer.** `vanguard uninstall` (Data menu) finds everything Vanguard placed here,
  without a register: the hourly monitoring, the monthly check-up, the automatic backup, the watcher (its unit
  recognised by its mark: a unit of the same name placed by someone else stays), the decoy files, the shortcut and its
  icon, the program copy, and what a version from before the name change had left. Everything is shown with what
  will be done, then checked; the data folder (device record, history, learning, quarantine) is never checked by default
  and asks for a second consent. Changes made to the system are first undone by their own tools, or said with the
  command that undoes them; the USB key is never touched. At the end: what was removed, kept, and what failed or could
  not be checked. No administrator rights.
- **Shortcut removed with its icon** (Linux): `shortcut off` left the icon behind; it goes too, if it is really
  Vanguard's.
- **Monitoring that no longer runs is said.** The check-up verifies that the program started by the hourly monitoring
  and by the monthly check-up still exists (and rsync for the backup), not only the task, and says how to put it back.
- **Missed runs caught up.** Turned on now, monitoring catches up a missed hour on Windows (computer off or asleep) and
  runs five minutes after sign-in; on Linux, it catches up on wake-up the hour missed during sleep and runs five
  minutes after sign-in; on macOS, right at sign-in. Monitoring already in place is not changed silently: the
  check-up says it is "from an earlier version", and `vanguard monitor on` updates it.
- **Enforced anti-phishing protection turned off, seen.** A Chrome, Chromium, Brave, Edge or Firefox policy (a file
  in /etc on Linux, the registry on Windows, policies.json), read the way the browser reads it, that turns off Safe
  Browsing overrides Settings, which can no longer turn it back on: unwanted software uses this. The check-up says so,
  with where to remove it; a merely recommended policy counts as long as the person has not chosen. Unreadable browser
  settings or policies no longer pass for protection turned on.
- **A DNS that does not block dangerous sites is said.** The check-up reports it (information) and points to "Fastest
  DNS", where CIRA's Canadian Shield "Protected" or Quad9 is set in one choice, undoable. Nothing is said when a DNS
  already protects, or when nothing can tell (NextDNS, Pi-hole).
- **Latest exploited flaws** (`vanguard latest-flaws [--days N]`). Those CISA added to its catalog in the last days
  (7 by default), newest first, with those used by ransomware; on Arch, those affecting a package on this computer
  first. The check-up also gives the date an exploited flaw was added.
- **Actively exploited flaws first** (Linux, Arch). The CVEs of known flaws in installed packages are compared with
  CISA's KEV catalog (flaws with a known real attack), downloaded whole: the software list does not leave the computer.
  An exploited flaw makes the finding critical and comes first, even without a published fix; without the catalog, it
  is said. A flaw in a package with a program listening on the network (a service through its systemd unit, without
  root rights) comes first, at least high. Hourly monitoring notifies a new critical flaw (exploited, or critical for the distribution); the others,
  which change every day, stay in the check-up.
- **Dangerous sites blocked** (`vanguard dangerous-sites on|off`). URLhaus hosts and ThreatFox command server domains
  (abuse.ch key) are sent nowhere (0.0.0.0 and ::) by the hosts file, after your consent and with administrator
  rights. Vanguard's block sits between two dated markers: `off` removes it exactly, the rest of the file never
  changes. Writing checks the checksum of the prepared file and of the hosts file read at the start: nothing is
  written if either changed in between. The check-up says when the list is more than a week old. On Windows, 5,000
  names at most (beyond that, the DNS client slows down); elsewhere, 20,000. In the Protection menu, with "Latest
  exploited flaws"; `uninstall` reminds you to remove them first.
- **Site that distributes malware, reported.** The names this computer asked for (DNS cache: no rights needed on
  Windows, root on Linux) are compared with URLhaus hosts, with the abuse.ch key: "Who talks to the Internet?" shows
  it, and hourly monitoring notifies it once (antivirus scan, downloaded files). Without the list, it is said; the exact
  name only, so as not to accuse a whole host.
- **Frozen Feodo Tracker list, said.** abuse.ch has not updated its botnet server list since March 4, 2026 (a single
  address). Without ThreatFox (no abuse.ch key), it was the only list read, and nothing said it was frozen: "Who talks
  to the Internet?", the check-up, blocking and the watcher now say so among what could not be checked. Its addresses
  still count; with the key, ThreatFox follows the same botnets up to date.

## October 22, 2026: version 0.84.1

- **AI servers open to the network, now seen on Macs too.** The rule that spots a local AI server (Ollama, LM Studio,
  llama.cpp…) reachable from the network now reads the Mac's listening ports; until now it was always reported as not
  checked on macOS. Programs are named in full: a name cut at nine characters was not recognized, and an open server
  would have passed as safe. Each socket keeps the program of its own address: an AI server open to the Wi-Fi is no
  longer hidden by another program holding the same port on the machine itself. Without administrator rights, only
  the current account's programs are named, and "no AI server" says so; if lsof does not answer, the rule stays not
  checked. Threat blocking benefits too.
- **Forced SSH login, on Macs.** With no sshd, neither listening on port 22 or on the ssh port of /etc/services, nor
  running (a Homebrew sshd on another port), nor started by a launchd plist, there is nothing to read and Vanguard
  says so, instead of marking the rule not checked at every check-up; with one, the rule stays not checked (macOS's
  unified log is not read), never safe.
- **Test benches without an abuse.ch key.** On GitHub's Mac, on Linux and in the Windows VM, the YARA scan passes when
  Vanguard reports the MalwareBazaar fingerprints as not checked for lack of a key, and the exact-fingerprint match is
  tried on a copy laid down for the test, then removed: nothing depends any more on the lists closed on October 21.
- **Presentation.** Vanguard now presents itself as portable cyber defense for endpoints and networks (README,
  features page, repository description, files on the key), in professional wording: the router, the local network,
  the public Internet address. The GitHub Pages features page is rebuilt at each release
  again: it had stayed at 0.82, the program being launched by a relative path from another folder.

## October 21, 2026, evening: version 0.84

- **Threat blocking, in one click.** Each threat found offers "Block": the action is shown, carried out after your
  consent, written down in "What Vanguard changed" and undone exactly by `vanguard blocking undo` (only stopping a
  program cannot be undone). Depending on the threat: the program stopped then quarantined, the connection closed at
  the firewall (ufw, nftables, Windows Firewall, pf), a launch removed from startup, Windows' vulnerable driver
  blocklist turned on (effective after a restart), an AI server's port closed to the network, an AI agent set back to
  asking before it acts. Antivirus and protection › Threat blocking menu, or `vanguard blocking`.
- **Active protection, which blocks what is certain.** Accepted once, it blocks by itself what leaves no doubt, then
  lets you know: a file whose fingerprint is in MalwareBazaar, a known attack tool running, a connection to a known
  command server (Feodo Tracker, ThreatFox). What is doubtful stays an alert with its button. It runs during the check
  and in the hourly monitoring. Four categories (programs, connections, startup and drivers, AI agents), each off, one
  click, or automatic for programs and connections. As administrator, it blocks nothing by itself: its settings can be
  written by any program of the account, and what is certain is offered with one click there.
- **Never a block that would do more harm than the threat**: not Vanguard, not a system program or a critical process,
  not a remote session in progress (SSH, Remote Desktop, RustDesk, AnyDesk, Tailscale…), not a local address or a
  public DNS; an interpreter (python3, PowerShell) is never quarantined, at most the script it runs. Without the
  rights needed, nothing is done halfway.
- **Settings, all in one place** (This machine › Settings, "s" in the main menu, or `vanguard settings`): language,
  emojis, working without the Internet, real-time protection, hourly monitoring, monthly check-up, learned alerts,
  blocking, extension restrictions and the abuse.ch key. Each change shows the previous value and the command to put it back; learned alerts and blocking open
  their own screen ("What Vanguard has learned", Threat blocking). Language, emojis and working without the Internet
  stay chosen from one launch to the next (VANGUARD_LANG, VANGUARD_EMOJI and VANGUARD_HORS_LIGNE always win).
- **Vanguard's real-time protection turns off, for a while or until turned back on** (Settings, or `vanguard settings
  real-time no --for 1h|4h`): the hourly monitoring and the active protection of blocking stop at once, after your
  consent and the list of what stops, without their settings changing. It comes back by itself when the time is up;
  while it is off, this is said again at the top of the menu and on its Monitoring and Blocking lines, in each check-up
  (with no effect on the grade), in "Who talks to the Internet?", in blocking and on the monitoring dashboard, by a
  notification at the first run then every day, and in the monthly check-up: a program that turned it off quietly would
  be seen. Defender, the firewall and UAC are never touched, and a block already made stays in place.
- **Extensions: your own programs in Vanguard, without touching its code** (menu 12 Extensions,
  `vanguard extensions`). A plugin is a folder with a `plugin.toml` manifest, added once from a folder or a .zip
  archive (`vanguard plugin add`); a lab script is a file dropped as it is (`vanguard lab`), to try an idea quickly.
  Their findings are shown apart, never count in the grade, and go into a separate section of the HTML report with
  `--report`. To write a plugin in Rust: the `extensions/sdk` library, with no dependency, and a complete example.
- **An extension is checked before it runs.** Before your consent, its whole folder or archive is scanned (YARA,
  MalwareBazaar fingerprints) and every file hashed (SHA-256): a file changed, added or removed, and it must be approved
  again. The checked copy is what runs, without access to the terminal, with a bounded time and output: beyond them, it
  is stopped along with everything it started; on Linux, what it leaves behind is stopped as well when it ends by
  itself. An archive cannot write anything outside its folder. On Linux, `--isolated` runs it without network, the home
  folder hidden. A manifest can only ask for full trust or to run with the check or the monitoring: it is granted by a
  separate question, and the consent falls at the slightest change. As administrator, nothing in the extensions folder
  lifts a safeguard: nothing there runs by itself, and each run is asked for. The **Restrictions** switch
  (Extensions › 3, Settings, or for a single plugin or script) turns these safeguards off for what is yours; one thing
  stays: the extensions folder must be yours, closed to other accounts.
- **YARA-X 1.22.0**, which fixes eight known flaws in wasmtime, the library YARA runs on, one of them on Apple silicon
  Macs. Every library used is now checked at each version and every night (cargo deny): known flaws, licenses
  compatible with the GPL, origin (crates.io only). The two remaining advisories, with no published fix, come from
  YARA-X and do not apply to the way Vanguard uses it (the reason is written down).
- **Calculations checked in the released version** (ANSSI guide, LANG-ARITH): a number that overflows on hostile data
  (a size read in a network packet, a log, a Windows program) stops the check concerned instead of silently wrapping
  to zero and skewing what follows; the rest of the check goes on.
- **abuse.ch lists with your key.** On October 21, abuse.ch closed its public lists: MalwareBazaar, URLhaus and
  ThreatFox now require a free key, created at auth.abuse.ch. Vanguard takes it in Settings or in "Who talks to the
  Internet?", keeps it on this computer (readable by the account only), shows it only masked and never writes it in a
  displayed address or a log. Without a key, or with a refused key, these lists are reported as not checked, never as
  clean; Feodo Tracker stays keyless.
- **Linux read without extra commands.** A D-Bus client written for Vanguard reads failed services, boot time and disk
  health (UDisks2), instead of systemctl, systemd-analyze and busctl; GNOME settings and Flatpak app permissions are
  read from their files (GVDB); the systemd journal and its compressed data (zstd) are read in Rust, with journalctl and
  pacman kept as fallbacks. On macOS, administrator accounts are read through the system library, without dscl.
- **Each released program carries the list of its dependencies** (cargo auditable): anyone can check it against known
  flaws with `cargo audit bin`, and a known flaw stops the release. cargo audit joins cargo deny in every check, and
  unsound code is refused across the whole dependency tree.
- **Hostile input put to the test**: property tests on the readers of data that comes from elsewhere (router, DNS, HTTP,
  DHCP lease, logs, AI agent settings, Windows drivers and events) and a fuzzing bench. Two crashes found and fixed: an
  outsized date in a macOS lease, and a nested "cmd /c" that overflowed the stack. File size sums are bounded, a file
  that crashes the YARA scan is still matched against the fingerprints, and a DNS measurement whose thread crashes is
  reported as not checked.
- **Rescue key tools**: the key keeps itself up to date even when it stays plugged in (program and images every day,
  new images looked for on the 1st and the 15th, each download announced), Ventoy is checked on the key and its update
  offered, then done without erasing anything after the password; Windows 11 is flagged past six months.
- **Reporting a flaw**: SECURITY.md says how (GitHub's private reporting), what to include, and what follows the fix
  (a published security advisory, a CVE if the flaw warrants one).
- **Security review.** An attack tool is certain only by the name of the program itself: a script run by an interpreter
  that bears the tool's exact name (python3 laZagne.py) is only a doubt, and a name that merely starts like the tool
  (python3 sharphound_parser.py) is no longer reported. The program is checked again at the very moment it is stopped
  (its number could have passed to another one). The ufw rule that closes a port goes before the allow rules, and the
  port is reported closed only once checked. In automatic mode, an address where another account has an established
  connection is never blocked. An unreadable settings file (settings, blocking, extensions) is first copied aside, as it
  is, before being rewritten; for extensions, nothing is written until it could be set aside.

## October 21, 2026, evening: version 0.83

- **Live threat hunting.** A successful sign-in from an address that had just failed at least ten passwords: a guessed
  password, reported as critical (sshd's log on Linux; on Windows, as administrator, the security log for Remote
  Desktop and shares, and OpenSSH's log; macOS: not checked). A bounded or overlong read is reported as partial, never
  as safe without a caveat. Suspicious running programs: known offensive tool (Mimikatz, Rubeus, SharpHound, LaZagne,
  XMRig…), command line that downloads or hides what it runs, program started from Downloads, a temporary folder or
  the recycle bin; of the line, only the program and the pattern are shown, never a secret written around them.
- **Incident timeline** in `vanguard evidence` (CHRONOLOGIE.txt): what the collection read with a date, put back in
  time order over the last 7 days, with the MITRE ATT&CK technique when it is obvious: accepted or refused sign-ins,
  sudo, created accounts, added services and tasks, cleared logs, Defender detections, recent files that matter. A log
  that does not go back the whole week says why.
- **Windows' hidden doors and kernel drivers**: the DLLs Windows loads by itself (LSA packages, AppCertDlls, print
  monitors, time providers, Winsock catalog); drivers stored where nothing installed puts one, or known to be
  vulnerable (the LOLDrivers list, once a week). Read-only, without PowerShell.
- **Program memory** (`vanguard memory`, on demand): the 308 YARA rules applied to the memory of running programs,
  where "fileless" malware lives, on Linux and Windows (macOS: not checked). The memory of LSASS and protected
  processes is never read, nothing read is kept, and what could not be read is said.
- **AI agents**: a local AI server (Ollama, LM Studio, ComfyUI) open to the network without a password; an agent set
  to do everything without asking, an MCP server started without a pinned version, reached without encryption or with
  a key written in clear text, in the settings of Claude Code, Claude Desktop, Cursor, VS Code, Windsurf and Gemini
  CLI (the key's name only, never its value).
- **Windows fixes without PowerShell**: fourteen hardening settings from a closed list (WDigest, Remote Desktop NLA,
  NTLMv2 only, LLMNR, WPAD, UAC…) applied by Vanguard itself, relaunched as administrator: Windows' prompt names
  Vanguard, the restore point comes first and the previous value is recorded to undo exactly; only Enter or yes
  applies. Mixed with a fix outside the list, they go through the script, as before.
- **Check my backup**: a copy rewritten after the backup (newer than its original, and different), as by ransomware
  encrypting the backup disk, is reported as damaged; it passed as "changed since".
- **Command guide: 1,085 commands**, including Vanguard's own for defending and troubleshooting, and how to check by
  hand what the new rules report.
- **More accurate.** On Windows, Vanguard run as administrator believed it had no rights (Windows refused the reading
  of its elevation, which Wine accepted): `vanguard evidence` left the security log out there, and the administrator
  window for fixes closed without doing anything. A YARA scan thread that crashed made the scan conclude "clean"
  without reading its files: they are now reported as not scanned. Without journalctl, the evidence also takes the
  last rotated /var/log file (auth.log.1…). In what starts by itself on Linux, "nc -e" is caught inside ( … ), after ;
  or & and behind a path, and so is a downloaded script piped to ash, to "sudo -p x sh", to "sudo -s" or to su. The
  guard against a DLL placed next to the program is required at build time: it could disappear.

## October 21, 2026: version 0.82

- **Network audit, domain by domain** (`vanguard network-audit`). Six grades: Internet exposure (ports opened by
  UPnP, read by a UPnP client written in Rust), Wi-Fi (encryption, WPS, neighbouring networks, read through nl80211
  on Linux and the Windows Wi-Fi API), device separation (connected devices on the computers' network, rogue DHCP
  server, ARP integrity), DNS and certificates, connected devices, computers. What could not be checked is said and
  never counts as safe: without enough checked domains, no grade.
- **Windows read without PowerShell.** Accounts, startup, scheduled tasks, shares, Defender, BitLocker, Windows
  Update, disk health and slowness are read through Windows APIs (registry, WMI, COM). The check is faster and works
  even when PowerShell is blocked; PowerShell is only a fallback.
- **macOS and Linux read without commands.** On macOS, settings are read by a plist reader written for Vanguard; on
  Linux, through /proc, /sys and system files.
- **Router and connected devices** (`vanguard iot`): router model and software, HTTP-only administration, cameras,
  printers, NAS, and a reminder to change their default password. The only request sent to a device is SNMP
  "describe yourself", with the factory read password "public": it is announced on screen.
- **A relative's computer** (`vanguard relative`): three questions, the check, a plain-words summary and a page to
  leave them.
- **Privacy check** (`vanguard permissions`): who can use location, contacts, camera and microphone, on all three
  systems.
- **Backups truly read back** (`vanguard check-backup`) and a **monitoring dashboard** in the browser
  (`vanguard dashboard`).
- **Browser passwords** (`vanguard browser-passwords`): counted and their protection described, never read or sent;
  each browser's built-in check is pointed to.
- **Canadian Shield** offered among the fast DNS: CIRA's public DNS, which blocks malicious sites.
- **Windows: a DLL placed next to Vanguard is no longer loaded.** The program only takes its libraries from System32
  (PE DependentLoadFlags), even when run from a USB key or Downloads; deployment refuses a program without this guard.
- **PowerShell in a hidden window** in an automatic start: reported as information, no longer as an alert.
- **A security review** fixed many false "safe" results; the features page now publishes itself with each version
  (https://d9v3.github.io/vanguard-beta/).

## October 20, 2026: version 0.81

- **Linux, the check sees further.** ICMP redirects accepted (IPv4 and IPv6) and source address filtering off,
  fixed in `99-vanguard.conf` without ever loosening an interface set to strict; user namespaces open to every
  program (information only: Flatpak, Chrome and Steam need them); command folders (PATH, sudo's) that other
  accounts can change, where a fake command would take the real one's place; no lockout after wrong passwords,
  passwords shorter than 8 characters (PAM).
- **SSH.** Forwarded ports open to the whole network (`GatewayPorts`), forwarded X11 display, too many password
  attempts per connection; fixed by reloading sshd, which cuts no connection in progress. Broken algorithms (SHA-1
  key exchange, CBC, 3DES, arcfour, MD5, DSA) reopened in the configuration, read in the exact order of its Includes:
  removed by a line in `00-vanguard.conf`, checked by `sshd -t` before the reload.
- **Windows.** Automatic proxy discovery (WPAD), through which a device on public Wi-Fi can divert browsing; no
  account lockout after wrong passwords (fixed like Windows 11: 10 attempts, 10 minutes); minimum password length.
  An account that does not require a password is described as it is (“accepts an empty password”) and is
  fixed from Vanguard: a password becomes required, the current one does not change.
- **macOS.** Automatic proxy discovery on; command folders open to all; XProtect definitions, the built-in
  antivirus, too old; configuration profiles installed outside company management (adware uses them to force a
  proxy, a DNS or a certificate).
- **Command guide: 1,040 commands** (98 more), mostly for security and troubleshooting: lynis, SUID programs, locked
  accounts, ClamAV, gpg signatures, WireGuard, certificates, service exposure, needrestart, sbctl, dnf
  needs-restarting; on Windows, public or private network, shared folders, TPM chip, a program's signature, wiping
  free space, memory test; on macOS, what starts by itself, camera, microphone and screen access, a file's
  fingerprint, traffic per program; on Omarchy, 60 more commands: firmware, keyrings and clock that block an update,
  orphan packages, pacman's cache, FIDO2 key, SSH server and docker group to turn off, network and speed, sharing
  with LocalSend, screen captures and text, brightness, boot screen, web apps, games and services to install,
  factory reset. The tldr-pages examples are also renewed by the monitoring and the monthly check-up, without
  opening the guide.
- **Secrets in git projects.** Vanguard reads the history of the home folder's projects, where a password, API key
  or token written once stays, even when deleted later: keys recognized by their shape (AWS, GitHub, GitLab, Google,
  Stripe, Slack…), private keys, passwords in an address or in the code; gitleaks, when installed, adds its rules. No
  secret is shown or kept.
- **YARA with nothing to install.** The 308 rules are applied by YARA-X (VirusTotal's YARA engine in Rust, BSD
  license), compiled into Vanguard on Linux, Windows and macOS: no engine to install or offer any more, and four
  files read at once. A file over 256 MB or taking more than 30 s to scan is reported, never counted as clean. The
  program grows from about 10 to 25 MB.
- **Fingerprint antivirus, everywhere, even from the USB drive.** The YARA scan also compares every file it reads
  with MalwareBazaar's SHA-256 fingerprints (abuse.ch, public domain): a file listed there is that exact malware, no
  doubt possible, offered for quarantine. The full list updates once a week, the last 48 hours every day; offline,
  the saved copy is used, and with no copy, that is said.
- **Recognized open source tools, when installed.** “Flaws in Docker images”: trivy tells the known serious or
  critical flaws in Docker or Podman images; when missing, Vanguard offers to install it with the system's tool. After failed SSH logins, the
  check tells whether fail2ban, sshguard or CrowdSec already blocks the addresses that keep trying.
- **Windows, the classic backdoors.** A debugger set on a sign-in screen accessibility program (IFEO,
  SilentProcessExit), sethc or utilman replaced by cmd, Winlogon's Shell or Userinit hijacked, AppInit_DLLs, WMI
  subscriptions that run a command: in the check, tracked by the monitoring, fixed when the original state is known
  exactly, otherwise the steps to follow. And the event logs of the last 7 days: bursts of wrong passwords from the
  network, security log cleared, accounts created, suspicious services installed; without administrator rights, the
  security log is reported unreadable, never healthy.
- **Linux, the signs of a rootkit.** Hidden processes, programs running without a file (memfd, deleted, started from
  /tmp or /dev/shm), a kernel module that hides or unknown unsigned modules, a network card in promiscuous mode; read
  from /proc and /sys in a few milliseconds. No automatic fix: the steps to follow, with rkhunter and chkrootkit as a
  second opinion.
- **Name poisoner unmasked.** During the network scan, without slowing it down, Vanguard asks over LLMNR, NetBIOS and
  mDNS for a random name that does not exist: the device that answers is a tool like Responder, which steals the
  network's Windows passwords. High alert, and a notification from the hourly monitoring.
- **Collect the traces** (Troubleshoot, `vanguard evidence`, and first step of “After an infection”, ticked by
  default; with ransomware or a remote control, right after cutting the Internet, which cannot wait). Before cleaning up, what a specialist will want to see, in a dated folder on the key or in Vanguard's
  folder: processes with their program's SHA-256 fingerprint, connections, what starts by itself, the check as JSON,
  accounts, logs of the last 7 days, recent files; a README and a manifest that `sha256sum -c` checks. Read-only,
  nothing is sent; Vanguard warns that the folder holds personal data.
- **“Who talks to the Internet?” recognizes botnet command servers**: Feodo Tracker and ThreatFox lists (abuse.ch),
  with the malware's name, optional abuse.ch key (unavailable or too old: said, never counted as empty); the DNS
  cache too: a program that asked for a known command
  server's name shows up, even once the connection is closed. Other accounts' connections are compared too; a server
  found leads to “After an infection”, Internet cut first. Hourly monitoring warns when a program talks to a known
  command server. And the account's temporary folder is recognized wherever it is (a moved TEMP let a program
  started from there go unnoticed).
- **Update from GitHub, without the key.** “Update Vanguard” takes the latest published version, and the main menu
  announces it. Nothing is taken on trust: each version is signed with Ed25519 on the author's computer, and Vanguard
  refuses a badly signed manifest, a version that is not newer, or a program whose size, fingerprint or version are
  not the signed ones. Someone who took over the GitHub account could not get anything else installed. The programs
  are published separately (d9v3/vanguard-officiel), the code in d9v3/vanguard-beta.
- **HTTPS client in Rust**: lists, registries, leaks, tldr, speed test and blocklists without curl; redirects over
  HTTPS only. The program grows by 2 to 3 MB.
- **Read directly from the system**: connections, processes, rights and account, the traces' registry and event logs,
  without ss, tasklist, taskkill, whoami, pgrep, id or PowerShell; faster, and nothing depends on Windows' language.
  Without rights, the security log is reported unchecked (before, it passed as healthy without being read).
- **Windows cleanup**: paths written in full, never the current folder when a variable such as TEMP is empty
 ; the print queue empties safely.
- **More accurate and safer.** On Windows, an account without a Startup folder no longer makes every file in the
  current folder look like a “suspicious shortcut” (a false high alert, especially when run from the key); the last
  quick commands (notifications, df on a dead network volume…) have a time limit and no longer freeze the
  monitoring; the list of known keys no longer loses a note when two are written at once.
- **Rescue key: the Omarchy installer** in the boot menu, next to Arch, Debian, Fedora and SystemRescue:
  complete, no Internet needed, kept up to date like them and checked with the key that signs Omarchy's packages.
- **For testing**: the program's PowerShell scripts parsed and replayed with pwsh at each check, in a sandbox
  closed to the system;
  Windows virtual machine test that counts skipped steps, compares each run with the previous one and
  checks the 0.79 settings; scripts dropped from Linux and run by the VM with its consent.
- **Independent review before the release**: an account with an empty password that a fix would have shown as
  healthy, an SSH attempt limit strict enough to lock the door, a `chmod` that would have broken `/tmp` put in PATH;
  fixed.

## October 19, 2026, evening: version 0.78

- **New name: Vanguard**, with its logo, a V as a shield and a padlock. On a computer where it already ran,
  nothing is lost: data, automatic backup, shortcut and settings follow the new name by themselves.
- **A much faster check.** On Linux, from 7 seconds to under one: commands are no longer awaited in fixed 50 ms
  pauses, packages are verified in parallel, Wi-Fi no longer waits for a new scan. On Windows, about ten fewer PowerShell
  launches: firewall, UAC, Remote Desktop and screen lock read straight from the registry, listening ports
  read with netstat and tasklist.
- **Windows.** MSI packages installed with system rights, Defender cloud protection off, exploit protection off (DEP,
  ASLR, CFG, SEHOP), Windows Update turned off (service or policy), services with unquoted paths in a folder anyone
  can change; a suspended or pending BitLocker no longer counts as encrypted.
- **Linux and macOS.** Session that opens by itself without an encrypted disk (GDM, SDDM, LightDM), root programs'
  memory readable after a crash, kernel magic keys; unencrypted Time Machine backup, Mac Remote Login accepting root
  or accounts without a password.
- **More accurate.** Included SSH configuration files read, open Wi-Fi networks better recognized, a DNS on this computer also measured
  on a new site (its memory answered in under a millisecond), dnf-automatic that
  only downloads, APT settings read in their order, complete English interface, decimal numbers written the French way in French,
  long messages broken between two words, never in the middle of one; on Windows, a firewall with no readable profile
  no longer counts as checked (no grade), and Remote Desktop turned on by a group policy is recognized; a VPN
  interface is no longer taken for the local network.
- **Network scan twice as fast** (from 20 to 8-10 seconds on a network of eleven devices): the router is asked
  about UPnP from the start, in the background (it takes up to 8 seconds to answer), and TCP ports, UDP ports and
  device names are looked up at the same time. Same probes, nothing removed.
- **Command guide redone.** One entry per system: Omarchy, Arch, Fedora, Debian and Ubuntu, other Linux, Windows 11,
  macOS; each distribution has its introduction, its “Step by step” guides (update, install, free up space, repair,
  firewall, NVIDIA, new release…) and its programs, then those common to Linux; Windows 11 and macOS have theirs too
  (repair Windows, network, security, slowness, Time Machine…), all systems too (SSH key, git); over twenty more
  programs common to Linux (time, kernel, Wi-Fi, network diagnosis, accounts, sound, printers, UEFI boot…), openSUSE
  and Docker; 942 commands. You type what you are looking for and commands show up as you type; each one has its
  page, to copy it, or run it here when it only reads (its output scrolls in Vanguard, Esc stops it).
- **Over 30,000 more commands**: the tldr-pages examples (CC BY 4.0 license), downloaded automatically every week and
  already on the key (even without Internet, the guide has them from the first launch); to copy only. In every
  search, what starts with the typed word comes first.
- **Safer: the key recognized by its token.** A volume carrying a VANGUARD key marker is no longer the key for
  that: from its local copy (monitoring, maintenance, shortcut), Vanguard reads and writes only a key it was started
  from or one this computer knows (`vanguard.jeton` token written at deployment, log partition included); an unknown
  volume is said so in the menu and ignored. The key's record has its reference here: changed outside Vanguard, or
  back without its protection, it is neither read nor rewritten and the check says so (`vanguard manifeste
  --accepter` when intended).
- **Word prediction in every menu** and checklist: the end of the most likely word shows in grey, Tab completes it.
- **Deeper check.** Platform security according to fwupd (HSI level: TPM, BIOS protection, IOMMU), kernel lockdown and
  module signing, BPF, auditd; on Windows, PowerShell script logging, Credential Guard (Enterprise, Education),
  Sysmon. Deep scan of a device: service versions with nmap when installed. The new rules have a stable identifier
  (“vanguard rules”).
- **Safer.** The sandbox no longer reaches the system bus or Docker; on Windows, the fix script is checked just before
  it runs as administrator (a script changed in the meantime does not run); Vanguard's data is reserved for your
  account. Automatic backup recognizes its disk by its identifier (UUID), no longer by its name: another disk with
  the same name no longer receives your files. Any text from elsewhere (device, file or printer name) goes through a
  single protection before entering a command, and a test checks it across the whole code.
- **Vanguard updates itself from the key.** The copy placed on a computer (monitoring, maintenance, shortcut) did not
  follow the key: started from a newer key, Vanguard says so in the menu, and the update happens after your consent
  (9.9 or `vanguard self-update`), read back and compared before replacing the old one; never to an older version,
  and never from a key that is merely plugged in.
- **A single release a day.** This history groups versions by day; only the latest keeps its download page, and
  GitHub's Mac now compiles once per release.

## October 19, 2026: versions 0.62 to 0.77

- **A much fuller check on Windows.** LM or NTLMv1 network authentication, LM hashes, share signing and guest
  access, accounts listed anonymously, SMBv1 client, Remote Registry, UAC that no longer asks, PowerShell execution
  policy, Office macros all allowed, overly broad Defender exclusions, Secure Boot, WDigest, LSA protection,
  PowerShell 2, SmartScreen, memory integrity, paused updates, and screen lock.
- **Linux and macOS.** Automatic security updates, kernel settings (pipes and files in /tmp, processor counters),
  SSH client that does not check servers, SSH server that accepts accounts without a password, sudo that never asks
  for the password again, cups-browsed open to the network, X11 display open to everyone, open Wi-Fi networks that
  reconnect by themselves.
- **Everywhere.** New administrators and hijacked browsing (forced proxy, hosts file) reported; computer clock, end
  of support of the system, forgotten accounts, passwords kept by the browser, sensitive files lying around.
- **New tools.** Automatic backup, hacked account, report to leave behind, desktop shortcut, and "What Vanguard
  changed": every fix is logged and dated, and the HTML report sums it up.
- **Caution.** The key's partitions are no longer offered as a disk; Check my key and Time Machine more careful;
  booby-trapped disk names refused in automatic backups.

## October 18, 2026: versions 0.52 to 0.61

- **Step-by-step troubleshooting** (network, security, upkeep, after an infection, new or departing computer),
  command guide and learning.
- **New defenses.** Fake technician and remote takeover, shares open to everyone, Windows Defender blocks,
  ransomware decoy files, Bluetooth, watched Downloads folder, reversible quarantine, camera and microphone.
- **Vanguard checks itself**: key manifest, dependency flaws every night, check a copy, check my key, encrypted key
  data, "My computers".
- **Comfort.** Startup programs, scrolling menus, search in checklists, copy a command from the guide, aligned
  emojis, booby-trapped names made harmless on screen.
- **Lighter code, arranged like the menu**, with the same behavior; fewer false alarms.

## October 17, 2026: versions 0.9.5 to 0.51

- **Vanguard gets its name**, with its shield logo and a redone presentation.
- **Wider check.** DNS and root certificates, browser extensions and security settings, computer health, leaked
  passwords and email addresses, hidden persistence, known package flaws, erased logs, integrity of critical files,
  ARP spoofing of the router, ports opened to the Internet through UPnP.
- **Tools.** Updates for the whole system, drivers included; Repair and deep cleanup; Optimize, with settings that
  undo exactly; gaming on Windows and Linux; computer diagnosis; essential software; sandbox for unknown programs;
  connection test for gaming.
- **Follow-up.** Changes since the last check and grade curve, monitoring of this machine, emergency text report,
  automatic restore point before every fix.
- **USB key** write-protected, error log, antivirus for a key; French and English everywhere; keyboard menus
  (arrows, Enter, Esc); parallel check, three times faster; macOS on par with Linux and Windows.

## October 16, 2026: versions 0.2 to 0.9.4

- **First versions.** Local network scan and device database, check of Linux (Docker, firewall, UDP, SSH keys, screen
  lock, hardened kernel, AppArmor or SELinux, backups, sudo) and Windows.
- **Repair menu** for Linux, Windows and macOS.
- **Reliability.** No failed command taken for "all is well" anymore, timeouts on commands, safe device database; a
  Remote Desktop session in use is never cut.
