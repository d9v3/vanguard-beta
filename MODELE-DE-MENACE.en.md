# Threat model

*[Français](MODELE-DE-MENACE.md)*

What Vanguard protects, against whom, and what it does not protect. This page sets the frame for the features: each
one should be able to say which threat on this page it covers. Vulnerabilities in Vanguard itself (a flaw in the
program, the USB key or the update) belong on another page: [SECURITY.md](SECURITY.md#security).

## What Vanguard protects

- **The computer it runs on**: its security settings, its updates, what starts with it, what runs on it and what talks
  to the Internet. Linux, then Windows.
- **The local network as seen from that computer**: the router, the connected devices, what is open to the
  Internet, the Wi-Fi.
- **The person's data**: their files (ransomware traps, backup check), their secrets (leaked passwords and email
  addresses, SSH keys without a passphrase, private keys and tokens left in files), their privacy (spyware).
- **Their USB key**: write-protected on any computer but its owner's, against USB worms; its logbook can be encrypted
  with a passphrase, against a lost or lent key.

## Against whom: the threats covered

| Threat | What Vanguard does |
|---|---|
| Known malware on the computer | Vanguard's engine (MalwareBazaar and ClamAV hashes, YARA rules, ClamAV signatures, heuristics) with the system antivirus, program memory, startup entries, signs of a rootkit; blocking after consent, or on its own for what leaves no doubt (active protection). |
| Ransomware | Trap files checked every hour; on Linux, once turned on, a live watcher that stops a near-certain case when active protection is on. |
| A weak setting or an unpatched vulnerability | A security check graded A to F, missing updates, actively exploited vulnerabilities from the CISA catalog, end of support; every fix after consent, undoable except one that turns a protection back on (firewall, antivirus, encryption, UAC, SELinux, kernel hardening on Linux, Windows hardening and Defender protections). Lowering a protection remains the person's choice, never Vanguard's (see [Lowered by choice](#lowered-by-choice)). |
| Exposure to the Internet | Ports the router opens (asked of the router itself, UPnP openings included), public IPv6 without a firewall; in the logs, guessed passwords and Remote Desktop connections from outside. |
| An intruder on the local network or the Wi-Fi | Inventory of the devices and of newcomers, fake access point, hijacked DNS and certificates; public Wi-Fi mode when traveling. |
| Someone close who spies on the person | Spyware, remote control (fake technician). |
| A scam | Links examined without opening them, downloaded files checked, leaked accounts. |
| An AI agent that does too much | AI servers open to the network, agents that act without asking, poorly protected MCP servers. |

Each threat in detail, menu by menu: [Security functions, threat by threat](README.en.md#security-functions-threat-by-threat).

## What Vanguard does not protect

- **An attacker who already has administrator rights.** They can stop Vanguard, erase their traces or skew what the
  system tells it. Vanguard does not protect itself against being turned off: it only reports that its monitoring
  was turned off. When Vanguard itself runs as administrator, it blocks nothing on its own, because its blocking
  settings can be written by any program of the account.
- **The kernel and the firmware.** Vanguard loads nothing into the kernel. It reports the signs of a rootkit (hidden
  processes, kernel modules that hide or are unsigned), but a well-made rootkit can lie to the system that asks it.
  Secure Boot is checked and the firmware (BIOS, UEFI) updated after consent, but nothing watches it live.
- **A new threat, still without a signature.** Detection relies mostly on known lists; what is not on them yet can get
  through. Vanguard complements the system antivirus (Microsoft Defender, ClamAV): it does not replace it.
- **What Vanguard's engine does not see.** Its verdict (certain, family, suspicious, clean, not checked) comes from
  hashes (MalwareBazaar, ClamAV), YARA rules, ClamAV signatures and eight heuristics, on what is written on disk. It
  has no cloud analysis, no memory scanning and no AMSI: a script or a macro that only decrypts itself when it runs
  escapes it. On Windows, it refuses no launch: only Defender does. “Clean” means “nothing known in what was read”. A
  missing expected source or an unread part gives “not checked”; a missing optional source (ClamAV database,
  MalwareBazaar hashes) is stated with the verdict, and the result recorded for the report counts it as not checked.
  Heuristics can be evaded (a program signed with a stolen certificate, diluted entropy, an ordinary name) and can be
  wrong. For them, “signed” means “an Authenticode signature is present”, never verified (neither the chain nor the
  match with the file): a signature copied from another program, or self-signed, is enough to silence “program
  without a signature”. So they only give a “suspicious”, which triggers no action on its own: one click, and a
  `normales` key tied to the exact content to silence a false positive. A family rule (YARA, ClamAV signature) also
  starts from a click. Only a known hash (or the EICAR test) can lead to quarantine without a click, if active
  protection allows it, and quarantine stays undoable. On Windows, with Defender on, the engine is only a second
  opinion. With Defender turned off by the person (Defense options), it becomes the main one and the scan says what
  is missing. Defender off with no recorded choice, or unreadable: nothing is concluded.
- **Everything, in real time.** Apart from the two Linux watchers (programs, connections and arriving files;
  anti-ransomware; both off by default), the live integrity monitoring of critical files and Defender's blocking,
  monitoring runs every hour, between two checks.
- **Every launch, with no time gap (launch guard, Linux).** The guard (`vanguard guard on`, off by default) never
  locks the computer up: when it cannot answer, it lets the launch through. Two windows follow from this. While the
  guard restarts (about one second), launches are allowed without being seen. A frozen guard makes each launch wait
  until its watchdog (about five seconds); systemd then kills it and everything that was waiting goes through. A
  launch with no verdict within 250 ms also goes through, noted. A frozen sorting thread (a disk that no longer
  answers) is replaced after about five seconds (four threads at most in all) and reported in the check; until then,
  launches go through after 250 ms. The program watcher remains the second line. The guard refuses only what is
  certain (a hash from the lists, or the test mark), never a system program, Vanguard or what init launches.
- **What the launch guard does not see (Linux).** It judges the file an `execve` opens (the program, or the script
  launched directly and its interpreter), on a local file system it has marked. It does not judge a script passed to
  its interpreter (`bash script.sh`, `python3 script.py`), a program passed to the dynamic linker (`ld.so ./program`),
  or a library loaded by dlopen or LD_PRELOAD: these are plain opens. It sees no launch from FUSE (AppImages
  included), overlay, squashfs (snaps), a network share (NFS, SMB, 9p), or from a new file system mounted in a private
  namespace (`unshare`, without root on most distributions). It marks only ext2/3/4, btrfs, xfs, f2fs, tmpfs, vfat,
  exfat, msdos, ntfs3, bcachefs and jfs: any other type is not seen (ZFS included, as well as erofs, udf and iso9660).
  A mark covers a whole file system (its superblock): a bind mount of the same disk, even in a private namespace,
  stays covered. A file system mounted after the guard started (a USB key) is marked within about a second; a launch
  in that second is not seen. A program larger than 64 MiB goes through on its first launch and is judged only
  afterwards; on FAT and exFAT (USB keys), where nothing is cached for lack of reliable timestamps, it is never
  stopped in time. The antivirus and the program watcher remain the line for these paths.
- **What real-time file scanning does not see (Linux).** The watcher marks, without privileges, Downloads, the
  Desktop, ~/.local/bin and ~/.config/autostart (fanotify inode marks, the only ones an ordinary account may use). It
  sees a file closed after writing or arriving by rename, a DIRECT child of one of them. It does not see: a subfolder
  (an archive extracted into `Downloads/folder/`), another folder (Documents, /tmp, a USB drive), a file written
  before the watcher started or while it is off or paused, nor a program started without being written to these
  folders (the program watcher and the guard judge it at launch). Real-time scanning fits in 128 MiB of memory: it
  uses the YARA rules, the heuristics and the MalwareBazaar fingerprints of the last 48 hours; the ClamAV database and
  the full fingerprint list serve on-demand scans and the hourly pass. A file over 32 MiB, unreadable or gone before
  being read is not scanned: it is counted as not verified, never as clean. A file arriving when the queue is full (256
  waiting), or lost by an overflow of the kernel queue, is counted then taken up again by a new reading of the folder
  (by its name, or by the list of files changed since the loss, newest and oldest first); until it has finished, the
  check says "at least N loss(es)" as an alert. Stated limits: beyond 4096 lost names, the middle ones are forgotten
  and the whole folder is read again; a folder of more than 50,000 entries cannot be read again: the loss there is
  given up after three tries, kept as an alert in the check and retried every 2 minutes (the `vanguard antivirus` scan
  covers it in full). A file being
  downloaded (".part", ".crdownload") is only scanned at its final rename: it is counted as not verified (the hourly
  pass does scan it). A link is never followed. Nor does it see content that changes without a close after writing or
  a rename: a hard link created in these folders (`link()`, an event the watcher does not ask the kernel for), a write
  through `mmap(MAP_SHARED)` after the close, a `truncate()` by path; the hourly pass goes over the last two (modified
  within the week), a hard link to an older file is only picked up by the "Quick" scan. A file with several names
  (hard links) is never quarantined: zeroing its permissions would also affect the other names; and quarantine only
  isolates the scanned inode. What could not be verified is reported in the log every hour. A watched folder replaced
  under its name (moved then recreated) is noticed within half a second, counted, reported and marked again; what
  arrives there in between is not seen. Deleted, it is reported as "no longer watched" until it comes back. The hourly
  pass goes over this week's files placed in these folders again (64 MiB at most, 300 files, one minute in all); the
  "Quick" scan goes over all of them. Malware in the account can switch the watcher off, like the others.
- **The page being visited.** Vanguard has no browser extension: the open page is not examined. It examines a link
  it is given, blocks known dangerous sites through the hosts file after consent (`vanguard sites-dangereux`), and
  public Wi-Fi mode switches to a filtering DNS.
- **The other devices on the network.** It observes them, it does not fix them and never attacks them: the router is
  read, never changed; the only password tried is the SNMP community “public”, and the attempt is announced.
- **Online accounts.** Known leaks are reported; the account itself is up to the service that hosts it.
- **Data loss.** Malware running in the account can turn off the anti-ransomware watcher: the backup remains the
  real protection.
- **A stolen computer that is on and unlocked.** Disk encryption (BitLocker, FileVault, LUKS) protects a computer
  that is off; Vanguard checks it and recommends it.
- **Hijacking the control flow of Vanguard itself.** Its published programs carry ASLR, non-executable data memory
  and, on Linux, the full RELRO marking, checked before every release (`vanguard deploiement verifier-binaire`);
  since musl's startup does not apply that marking, Vanguard makes the PT_GNU_RELRO segment read-only itself at
  launch (`src/socle/relro.rs`). Control-flow
  protection (CFG on Windows, CET everywhere) is not there: MinGW and stable Rust do not set it reliably. It is shown
  without being required, to be revisited if the Windows build ever moves to llvm-mingw or MSVC.
- **What a borrowed computer reads.** Write protection keeps the key from being changed, not from being read: the
  logbook is safe only when encrypted.

## What Vanguard assumes

- **The program is the real one.** Check its SHA-256 checksum when downloading (`SHA256SUMS.txt`); every update is
  signed with Ed25519 and refused if it is badly signed, older, or if its size or checksum does not match. The
  program does not have a code signing certificate yet.
- **No one else drives Claude on the code repository.** Claude on GitHub (.github/workflows/claude.yml) can write to
  the repository and runs cargo build and cargo test, to check what it fixes. It starts only for the owner, on a
  thread (an issue or a pull request from the repository itself, never from a fork) whose every comment, review and
  review comment is from the owner or from the Claude and GitHub Actions bots. Just before Claude, the thread is
  locked, then read again the same way, and it stays locked until the job ends; a second `@claude` on the same thread
  waits for the first to end. What remains: people with write access to the repository, who can still write on a
  locked thread; what it reads outside the thread (a linked issue, a page, someone else's text copied by the owner);
  and the repository's own code, which cargo build and cargo test run.
- **The system answers truthfully at the time of the check.** A computer already compromised at the administrator
  level can deceive all of its readings (see above).
- **The lists and third-party tools are right.** The threat, version and vulnerability lists (abuse.ch, CISA,
  vendors) and the tools Vanguard runs without having written them (ClamAV, trivy, gitleaks) are trusted as they
  are; a list that is too old is reported as not checked.
- **The programs of your account do not target Vanguard itself.** Vanguard keeps its state (what it has already seen,
  what you have set, the defenses you have turned on) in a folder of your account. A malicious program running under
  your account can therefore tamper with that state. Vanguard sees and reports simple tampering (a file changed,
  deleted or dated in the future) and no longer relies on it: no defense is turned off, no alert is silenced. Two
  limits: Vanguard's folder deleted as a whole brings it back to its first use, where it learns again without saying
  anything; and a program that targets this mechanism on purpose (it also rewrites Vanguard's seals, or deletes them
  along with their witnesses) is not seen. A program that holds the seals lock (sceaux.verrou) keeps Vanguard from
  writing its state and its event log for as long as it holds it: Vanguard waits for it only once, then one second in
  all, says so in the check-up, and counts the events it could not note so as to report them once the lock is
  released. Those of a Vanguard killed in the meantime are lost without being counted, and that count, written without
  a seal, can be deleted. The real answer, a service running under an account other than yours (administrator), is
  planned for a future version.
- **The person decides.** Nothing is changed without their consent. What they accept can be undone one fix at a
  time, except what turns a protection back on (kernel hardening on Linux included) and the stopping of a program; a
  fix whose previous state cannot be read is reported as “not undoable” before it is applied. Windows hardening
  settings (WDigest, NLA…) and Defender protections are protections too: undoing does not reverse them, and a
  forged note can no longer lower them. An undo note accepted without an earlier seal (outside an update from a
  version that already seals, 0.86 or later) is not put back: a barrier against a file planted by another program,
  not a closed door, since a program that also rewrites Vanguard's seals goes unseen (see above). That is why
  protections are no longer reversed at all by undoing. The person can still lower them themselves, in Windows or in
  the Defense options, by the path described below.
- **Testing has its limits.** Vanguard is tested on the author's computer, a Windows VM, a second Windows PC and
  GitHub's machines (Windows, real Linux distributions); other cases are still to be tried on real hardware (other
  distributions, a real UPnP router, booting the key).

## The window

`vanguard` with no argument opens the Vanguard window (`vanguard-fenetre`, a separate program placed next to
`vanguard`) when someone is in front of a graphical screen; otherwise, the terminal menu, as before. Its safeguards:

- **It does nothing by itself.** It runs the `vanguard` program placed next to it (absolute path, never looked up in
  the PATH) with a command from a closed list, which changes nothing on the computer (`audit`,
  `protection`, `evenements`, `diagnostic`, `test-connexion`…), always with `--json`, no free argument, no shell,
  input closed, one at a time, with a time limit and a Stop button (on Linux, the whole process group is stopped,
  and whatever is left of it when the command ends too; `vanguard` is only reaped afterwards, so that group number
  cannot belong to anyone else; a process that left the group and keeps the outputs open does not hold the window, which lets go of the pipes).
  The window's console only accepts the names on that list. On Linux, that `vanguard` must be a regular file owned
  by the window's account or by root, that neither the group nor others can modify, in folders (up to `/`) that
  neither the group nor others can modify either (except a folder with the sticky bit, like `/tmp`), or it is not
  started: the same rule as for the window, below, checked again before each command, not only at opening.
- **A single change, in two steps: a startup program.** The startup screen shows the state of each program that
  starts at login. An ordinary program has “Remove from startup”, a program removed by Vanguard has “Put back”; a
  program to keep or a firewall has no button, its reason is shown. A click only opens a confirmation inside the window
  (name, command, what will happen, administrator window if the program belongs to the whole computer); only
  “Accept” starts the change, one at a time, buttons greyed out while a command runs, with no “remove all”. The window
  only offers the actions that `vanguard demarrage --json` has just written, and only sends the kind (remove or put
  back) and the program's fingerprint (32 hexadecimal digits, computed by `vanguard`): never a name, a command or a
  path. The form started is closed, `vanguard demarrage --retirer|--remettre <fingerprint> --json`, and `vanguard`
  judges everything again: malformed, unknown or ambiguous fingerprint, program to keep, firewall, Vanguard's notes
  unreadable or changed outside Vanguard (neither removal nor putting back while they are), “put back” for a program
  that already starts (put back or rewritten outside Vanguard, perhaps now a program to keep: the old note does not
  overwrite it, neither through undoing a block nor through “Put everything back”), all are refused without changing
  anything; what changes goes through the
  same correction as in the terminal (restore point, previous value noted, a single administrator window, never sudo).
  The console starts no change, in any typed form. “Accept” checks again that the action is still in the last list
  read: a list read again that no longer contains it closes the confirmation (“The list changed: nothing changed.”),
  as changing screens does; the alert watch goes on while a confirmation is open. A change once started is not
  interrupted (cutting it in the middle would leave a half-done state): Stop does nothing to it, and under Linux
  neither does closing the window (the relay lets it finish); it is stopped by declining the administrator window.
  Only its time limit, 15 minutes (the Windows administrator window may wait), cuts it. On the `vanguard` side, a
  change holds the notes lock (`reglages.verrou`) from reading the notes to their last write, as the terminal
  optimiser and “Put everything back” do: two Vanguards never change the notes at the same time, the second refuses
  without changing anything. “Put back” reads the notes again under this lock and requires the same noted setting as
  on the first reading (otherwise refused, nothing written); “Remove” on a program that starts replaces an old note
  left from before with the value read now, so that “Put back” brings back the state from before this removal. Under
  Linux, this previous value (the autostart entry) is read in a single opening that does not follow a link, does not
  wait on a pipe and stops at 64 KiB: otherwise refused, nothing changed (an entry that is a link therefore cannot be
  removed from here). Each change done or refused is written to the event log (kind, cleaned name, outcome,
  fingerprint); a refusal identical to the previous one (same fingerprint, same kind, same reason) is not written
  again for 10 minutes, so that a burst of requests does not drown the alerts; a change done is always written. Its end is told
  (done, refused, failure, with the reason), then the list is read again; only the last line of the output, a JSON of
  the same action, with exit code 0, means “done”: anything else is a failure, never a success
  (`fenetre/src/attaques.rs`, tests B1 to B3). Tests: `une_confirmation_ne_bloque_rien_et_suit_la_liste`
  (`fenetre/src/appli.rs`), the relay tests (`fenetre/src/relais.rs`), `verrou_des_notes_tenu_puis_rendu` and those
  of `src/optimiser/demarrage.rs` (`seul_un_programme_note_se_remet`, `pare_feu_reconnu_par_son_paquet`),
  `valeur_d_avant_d_autostart_ni_lien_ni_tube_ni_trop_gros` (`src/optimiser/linux.rs`), and end to end, with a
  throwaway home folder, `demarrage_retire_puis_remet_a_l_octet_pres` and the `demarrage_sous_attaque` module
  (`tests/programme.rs`: putting back over a program that starts, from the window and through “Put everything back”,
  removal on doubtful notes, simultaneous changes, link, lock held, forged or replayed notes, repeated refusals).
- **Its answers are read with suspicion.** Bounded size, long lines cut, terminal sequences and control characters
  removed, JSON read without ever crashing (readers, console and progress fuzzed: `fenetre_donnees`, `fenetre_saisie`, `fenetre_progression`); an
  unreadable answer is said to be so, never counted as healthy. As in the terminal (`ui::affichable`), a character that
  reverses or hides text (writing direction, invisibles, blanks that are not spaces) becomes “�”, and a space of another
  width (no-break, thin, hair, em, ideographic) an ordinary space: it no longer glues two parts of a name together, and
  a number written the French way stays readable. A variation selector (U+FE00 to U+FE0E, U+E0100 to U+E01EF,
  Mongolian ones) is removed: legitimate in Japanese, Chinese and Mongolian, it no longer hides anything between two
  letters and the name stays readable; the emoji one (U+FE0F) stays. Rare invisibles (U+206A to U+206F, U+FFF9 to
  U+FFFB, U+17B4, U+17B5) become “�”. Accepted: two names that differ only by a selector look the same (the judgement
  still sees the selector, and the key of an accepted choice writes it `\u{…}`: one choice never covers the other name).
  Also accepted: a letter from another script that looks like a Latin one
  (Cyrillic “а” in “Sаlon”) stays as it is, so as not to damage names written in those languages; and a state is judged
  after its trailing spaces are removed, which changes nothing as long as it is a fixed word of `vanguard`, never a name
  from outside. The check's grade is shown only when Vanguard says it is reliable (`fiable` in `audit --json`); when
  some points could not be checked, the grade is said to be incomplete, next to the number, with how many.
- **No connection, no file.** The window opens no network port, no server, no web page, and runs no JavaScript (no
  HTTP library among its dependencies); it writes no file (theme and language are not kept). The commands it runs
  reach the Internet as they do in the terminal (for example `test-connexion`, `logiciels-perimes`).
- **A sandbox (Linux).** At startup, before anything else, the window splits in two: a relay (`vanguard-relais`) keeps
  your account's rights and alone starts `vanguard`; the window locks itself in (Landlock and no_new_privs,
  `fenetre/src/bac_a_sable.rs`) and from then on only asks the relay for a command of the closed list, by its number
  (`fenetre/src/relais.rs`). Locked in, it can read the system's files (libraries, drivers and settings: /usr, /etc,
  /lib*, /opt, /proc, /sys, /run except /run/user and /run/media) and, from your account, only its cursor themes
  (~/.icons, ~/.local/share/icons, ~/.cursors) and its dead-key file (~/.XCompose); talk to its display (the Wayland
  socket, or the X11 ones and the ~/.Xauthority file, never both) and to the graphics card (/dev/dri, /dev/nvidia*);
  nothing else: it can neither read your home folder (SSH keys, browsers, tokens), /tmp, /var or plugged-in drives, nor
  write a file (not even the shader cache, which a trapped program could poison), nor start a program, nor (Landlock 4,
  Linux 6.7) open a connection, nor (Landlock 6, Linux 6.12) send a signal outside itself or, under Wayland, reach an
  abstract socket, nor (Landlock 9) reach a Unix socket other than the display's (the D-Bus bus, for example). The relay
  only understands “run command n of the list, in this language”, “remove or put back the program with this
  fingerprint, in this language” and “stop”; a request outside this protocol (length, unknown kind or language) stops it
  (protocol fuzzed, `fenetre_relais`); it finds the neighbouring `vanguard` itself and replays its guard; it cannot be
  observed (PR_SET_DUMPABLE set to 0). A change, it bounds itself, without trusting the window: only for a fingerprint
  and a kind it saw together, in the same action, in the last output of `demarrage --json` it relayed itself (“put
  back” does not pass for a program the list offered to remove); only when nothing else runs, and nothing else starts
  while it runs; “stop” does not cut it (tests `le_relais_ne_comprend_que_le_changement_de_forme_fermee`,
  `seuls_les_gestes_de_la_liste_sont_vus`, `aucun_nom_ne_fabrique_un_geste_vu`,
  `une_sorte_que_la_liste_n_offrait_pas_est_refusee`, `le_relais_refuse_la_sorte_que_la_liste_n_offrait_pas`,
  `un_changement_vu_passe_seul_et_ne_se_coupe_pas`). When the window
  closes, it stops the readings in progress, lets a started change finish, then leaves. Why not `vanguard`
  too: locked in, it would see less (no_new_privs alone makes the sudo check of the report disappear; Landlock hides
  other processes and the system bus from it), and a report that sees less without saying so would be worse. On opening,
  the window's console says whether the sandbox is active, with which Landlock version and what this kernel cannot take
  away; without Landlock (kernel before 5.13, or Landlock turned off), or if the relay does not start, it says so in
  orange and keeps the account's rights: never a `vanguard` started from the sandbox. Behind the scenes ("Vanguard —
  Behind the scenes", opened from the console header) shows what the window does: each command and its arguments,
  which way it goes (relay or window), its pid (sent back by the relay in a frame of exactly 9 bytes), its end, its
  lines, and refused inputs with the reason; in memory only, bounded, cleaned like the rest, read-only (the view only
  gets a state it cannot change: nothing starts from it, nothing is written from it).
- **The menu stays the safe choice.** The window does not open without a terminal (a script writing the choices),
  over SSH or Remote Desktop, as administrator (root, sudo, administrator console), without a graphical screen, when
  it is not placed next to `vanguard`, when (on Linux) it is not a regular file owned by this account or root that
  neither the group nor others can modify, in folders that neither the group nor others can modify, or when it does
  not say "open" within 20 seconds. `vanguard --menu` forces
  the menu.
- **Its libraries.** On Windows, like `vanguard.exe`, it loads its DLLs from System32 only: those it imports
  (DependentLoadFlags), and those a library opens by name after startup (SetDefaultDllDirectories, first line of the
  program; opengl32.dll for example). A DLL placed next to it, on the key or in Downloads, is never loaded. On Linux,
  it is linked to the system's glibc (its display libraries are loaded at run time): only the interpreter
  `/lib64/ld-linux-x86-64.so.2` is allowed, with no library folder written into the program (neither RPATH nor
  RUNPATH), checked by each run of `outils/verifier.sh` (`vanguard deploiement verifier-binaire --glibc`).
- **Limits.** Like the program, it assumes only you can modify its folder: whoever can replace `vanguard-fenetre` can
  also replace `vanguard`. On Windows, the window and `vanguard` only check that the other one is a regular file:
  neither its owner nor the permissions (ACLs) of the file and its folders, which Windows does not let you read as
  simply; a folder where other accounts can write is therefore not refused on Windows. On Windows, each command it
  runs is put in its own job object: Stop, the time limit and the end of the command also stop what it started, and
  everything stops if the window stops; a process started in the short moment before it enters the object would
  escape it. On Linux, no screen reader nor copy and paste yet. The window's sandbox does not hold back what the display
  allows any window, and Wayland is never counted as safe by default there. Under X11, any program on the screen can
  type into other windows and read their clipboard, and abstract sockets stay reachable (X11 needs them). Under
  Wayland, it depends on the compositor: Hyprland (without enforce_permissions) and the wlroots ones offer any window,
  over the very socket it draws on, a virtual keyboard and pointer (zwp_virtual_keyboard, zwlr_virtual_pointer), the
  others' clipboard (data-control, wlr and ext), screen capture (screencopy, image-copy-capture) and window capture
  (hyprland_toplevel_export); Landlock can do nothing about it. A window taken over could therefore type into an open
  terminal, see the screen or read the clipboard; your files, though, stay closed to it. The sandbox also protects less
  before Landlock 9 (it can still reach the account's Unix sockets, including the session bus, from which `systemd-run`
  would start a program, and the X11 ones even under Wayland) and before Landlock 6 (abstract sockets, including
  Xwayland's). Your account's driver settings (~/.drirc, ~/.nv) are not read: the card keeps its defaults.
  The confirmation of a startup change protects against one click too many, not against a hijacked window: that one
  could “accept” in your place. What it gets then stays bounded by what does not depend on it: under Linux, the relay
  only accepts the closed form, an action (fingerprint and kind) it saw in the last list, one change at a time;
  `vanguard` judges everything again and never removes a program to keep or a firewall; what is removed is put back
  exactly (previous value noted); each action is in the event log, where it shows. The relay puts no pause between two
  changes: a hijacked window can chain list and change and remove, one after the other, every ordinary program
  (`le_relais_n_impose_aucun_intervalle_entre_deux_changements`), each in the log and each can be put back. Vanguard's
  notes and their seals (`src/sceau.rs`) are a barrier against a file placed by another program, not a safe: a program
  of your account that keeps a copy of the notes with their seals can put it back later; “Put back” would then bring
  back an old noted value of a program that no longer starts (over a program that starts, it is refused:
  `notes_forgees_ou_rejouees`). The event log is bounded (13 months, 20 MiB in all, the oldest months go first):
  identical refusals are written only once per 10 minutes (`des_refus_repetes_ne_noient_pas_le_journal`), but requests
  for fingerprints that all differ are each written, and enough of them would push old alerts out of the log. Under Windows there is no relay: these bounds are
  those of `vanguard` alone, and closing the window also stops a change in progress (job object); since the previous
  value is noted before any change, it can still be put back.

## Lowered by choice

Vanguard never lowers a protection on its own. The person can lower one: it is their computer, and a setting that is
too strict can get in the way of software they need. That choice always takes the same path, built so that another
program cannot make it in their place.

**What they can lower.** In the Defense options (`vanguard defense-options`, tool 4.10 on Windows, 4.9 on Linux):

- on Windows, each Microsoft Defender option (real-time, cloud, sample submission, potentially unwanted apps, network
  protection, controlled folder access, behavior, downloads, scripts, block at first sight), a scan exclusion, a
  program allowed despite controlled folder access, each of the 19 ASR rules (block, audit or off), Windows Firewall
  for each profile (on, inbound, outbound, block all) and its existing rules, and putting back a value that a
  Vanguard fix had changed (`--put-back`);
- on Linux, the firewall (ufw, firewalld or nftables), turned off or back on.

Elsewhere, only two lowerings, each on its own and with the same question: when leaving public Wi-Fi mode, each
restore that makes the Public profile less blocked (incoming allowed, inbound rules followed again) or puts the
network back to Private, in its own administrator window (a Public firewall found off on entry is turned on, even
if it was off by choice, and turned back off only if the person asks, through a separate question); on Linux,
removing a firewall (recognized by its package) from the programs at startup. A hand-added service that runs a
firewall program (nft, iptables, ufw, firewall-cmd…), directly or through a script it names (one level), or that
drives one through `systemctl` or `service`, is not disabled from the check: a firewall is turned off through the
Defense options.

**Why it is allowed, and how.**

- **The lowering goes alone.** A list that mixes a lowering with other changes is refused as a whole: a lowering
  cannot slip into a list of fixes accepted in one go.
- **It is judged again, then shown.** The administrator process (Windows) or root (Linux) reads the state itself and
  decides whether the action strengthens or lowers, without trusting what the request says. It shows what changes;
  on Windows, also what still protects.
- **It is confirmed.** The question says: “These changes make your PC LESS protected. Did you ask for them yourself,
  in Vanguard, just now? If it was not you, answer N.” Enter alone means no. On Windows, the answer is read only from
  a real console; on Linux, from the person's terminal (/dev/tty), never from the program's input. With no console
  or terminal, the answer is no.
- **It is noted first.** The previous value is written before the action; if the note cannot be written, nothing is
  lowered. On Windows, the notes are under HKLM `SOFTWARE\Vanguard\ChoixAvant`, which only administrators can
  write, each with its SHA-256 hash: one family of notes per way of putting back, all under this key (the Options
  choices, put back by “Turn back on”; the values a fix changed, put back by “What Vanguard changed” and “Put
  everything back”), 256 values at most, and going over says how to free some. On Linux, they are in
  `/var/lib/vanguard/avant`, owned by root, one file per action, with three fixed names for the firewalls (ufw,
  firewalld, nftables): without rights the folder cannot be listed and a file cannot be read (0711 and 0600), and a
  note not owned by root is not read. Only the
  administrator or root process uses this note to put things back; the copy kept in “What Vanguard changed” is for
  display only.
- **It leaves a trace.** On Windows, each lowering also writes an entry to the Windows event log (Application,
  source “Vanguard”), which remains if Vanguard is removed. The check reports the protection lowered “by your
  choice”, with the date, followed by “If it was not you: Turn back on”: a lowering is never counted as healthy.
- **“Turn back on” restores it.** On Windows, it puts back the previous value if it protects at least as much as
  “on”, otherwise the safe value: a forged or damaged note never turns anything back on weaker. On Linux, it puts
  back the state noted before turning off; with no note, it turns the firewall on, a strengthening that cannot be
  undone. Turning back on is never reversed by undoing.
- **“It was me”.** A protection lowered outside Vanguard can be noted “by your choice” (`--note`), with the same
  question; the check then stops alerting, and “Turn back on” stays offered.

**What Vanguard refuses, whatever happens.**

- **Defender's tamper protection** is never bypassed. When it blocks a setting, Vanguard opens the Windows page
  where it lives: the person turns it off, then back on.
- **The defense services themselves.** Vanguard does not offer to stop Defender's service (WinDefend), the firewall
  service (mpssvc) or the filtering engine (BFE).
- **The remote session in progress.** On Windows, during a remote session (Remote Desktop, SSH, AnyDesk, VPN…), or
  when connections cannot be read, the firewall of the current network cannot block everything, block outbound
  traffic, close a port of the session or disable a rule that lets it through. Turning the firewall off only opens
  more: it is not refused for that reason. On Linux, a defense action never disables a unit that carries a session
  (sshd, the login screen: gdm, sddm, lightdm…, systemd-logind, dbus, polkit, xrdp), nor the network, tunnel, VPN or
  firewall they go through, nor the service Vanguard's own session comes from. It is a refusal, with no question.
- **Other people's nftables tables.** Turning nftables off removes, in a single transaction and after a backup
  checked by `nft -c`, each table that is not Vanguard's; never the whole ruleset at once. iptables-nft tables
  (Docker, libvirt, fail2ban…), recognized by their name or their shape, and tables marked `owner` or `persist` are
  never removed; Vanguard's own are not either.
- **Network isolation.** Isolating the computer keeps the current remote session: it is found before any rule, and
  if it cannot be identified with certainty (tunnel, VPN, unreadable connections), the isolation is refused. It
  removes nothing from the existing firewall; lifting it removes only what carries Vanguard's name and restores the
  settings noted before, even if the note is lost (without a note, the firewall stays closed to inbound traffic,
  never more open). On Linux, the state lives in root's folders and a damaged state at boot keeps the computer
  isolated. The automatic isolation of an almost certain ransomware (separate consent, active protection) goes
  through the same shown elevation: a program of the account can neither isolate nor lift without it; the watcher's
  hardened service cannot obtain it by itself, and the alert says so.

  What still gets through during the isolation, and its limits:
  - The kept session is kept by its exact connection (remote address and port, local port 22 or 3389), in its own
    direction only: nothing else to that address, and a connection this PC opens outward (SSH client) is not a session
    to keep. Once dropped, it does not come back, even from the same address.
  - During the isolation the person asks for, Vanguard's servers are reachable over HTTPS only (TCP 443). Their
    addresses often belong to a host (CDN) shared with other sites: any HTTPS site served from those same addresses
    stays reachable, and a hostile program can use it to send data out. The automatic isolation of a ransomware keeps
    no Vanguard server (the elevated side decides it from the order, which cannot ask for any): this residue does not
    apply to it, and Vanguard no longer updates itself until it is lifted.
  - The current DNS stays reachable on port 53: a hostile program can send data out through names asked of that
    resolver (DNS tunnel).
  - On Linux, a copy of Vanguard runs as root at each boot while the isolation lasts (bounded by its unit's
    hardening); it is copied from the Vanguard that asked for the isolation: if that one lives in a folder of the
    account, a program of the account that replaced it before the password becomes root, as with any elevation
    (checking the program before copying it is a separate batch).
  - Sessions Vanguard does not recognize are cut: mosh (which goes on over UDP), and a session that goes through IPsec
    without an interface (ESP and IKE are not kept).
  - On Linux, a `restart` or `reload` of nftables sets the table again (its unit follows nftables); an administrator's
    `systemctl stop nftables` or `nft flush ruleset` removes it until the next boot, and the banner still says
    “isolated”.
  - On Linux, a virtual machine bridged at layer 2 (“bridged” network, macvtap, bridge tied to the network card) is not
    filtered by the isolation: its frames are switched without going through the computer's IP hooks, unless
    `br_netfilter` is active, which is not the default. It keeps its whole network while the computer is isolated; a
    routed virtual machine or container (libvirt NAT, Docker) is cut.
  - On Windows, the firewall blocks, to a kept address, only TCP, UDP and ICMP (other protocols to it get through); during
    the isolation the person asks for, an inbound connection from port 443 of a Vanguard server is not refused
    (Windows does not tell an established connection apart); RDP's UDP channel is not kept (RDP falls back to TCP); a kept session's ICMPv4 error messages
    (packet size) are not allowed by a rule, and whether the firewall lets them through was not checked; and the traffic
    of virtual machines (Hyper-V, WSL2) may not go through the computer's firewall.

**Guards against lockout (Linux).** A defense action that could cut the person off from their computer (locking
root or their own account, removing the last administrator, making sudo, su and pkexec unusable) is not refused: it
may be what needs doing. It is preceded by a WARNING, and the `[y/N]` question defaults to no; if it cannot be
undone, that is said (“not undoable”). Turning the firewall off while an SSH session may be open also gives a
warning: “If you are connected from afar, answer no”.

**What Vanguard never does on its own.** No lowering comes from “Fix the problems found”, the “Recommended settings”,
“Put everything back”, the automatic response to alerts (active protection) or monitoring. “Put everything back” turns
back on what was lowered, never the reverse. Public Wi-Fi mode turns on a firewall found off and never turns it back
off on its own. On Windows, a test checks in the code that lowering lines are built only in the Defense options and
when leaving public Wi-Fi mode.

**Limit.** On Windows, a program that drives the real Vanguard can make the question appear, but it cannot answer
it: Windows prevents a non-elevated program from sending keys to the administrator window. If Vanguard already runs
as administrator, or if User Account Control (UAC) is off, a hostile program driving it is itself an administrator:
it has already won (see above). The same goes, on Linux, for a program already running as root.

**Alerts declared normal.** "This is normal for me" silences an alert for 90 days (it comes back sooner if it gets
more serious), in a list sealed like the rest of Vanguard's state; a date in the future extends nothing. An alert to
fix yourself can only be declared normal if its rule records what the choice would be bound to: today, on Linux, only a line of a systemd user unit (under /etc/systemd/user, only if the file and every folder of its real path are root-only) or a launch line (exec-once, exec_on_start…) of a file in ~/.config/hypr, judged by its real path (a link that leads out of it, from the file, the folder or a subfolder, is not in it) (the author's decision, 10 Nov. 2026): a line of a shell profile, of environment.d or of the systemd settings, a Hyprland line that sets a variable or comes from a file included outside ~/.config/hypr, a .desktop launcher, a cron, preload or system unit line, and a session variable stay raised until the line is removed (the information about system services added by hand, which only root writes, keeps its bound choice) (the refusal names the file and the line, and says why), and an older choice outside this scope comes back at every check while the line remains, with that reason; detection, for its part, joins lines continued with "\" the way the shell does and replaces Hyprland variables ("$name = …") before judging a launch line, a variable without a known value being raised; a critical alert to fix yourself cannot be declared, nor can a line shaped like
a backdoor (a shell to the network). Before the choice, Vanguard shows every reported line without exception
(file:line, the file's fingerprint, the program, script or library it names and their fingerprints); the choice is
always confirmed (typing "normal" from the high level up), only at the keyboard in a terminal (input and output: a
choice coming from a pipe is refused), and the state is recorded again at confirmation: a file changed while you read
makes it refuse everything. Each choice is written to the log, and the list is only written under its lock, re-read
just before: two Vanguard open at the same time do not overwrite each other's choice. The choice is bound to that
exact state: a line added or changed, another source in the same alert, the file, a systemd addition (.d folders,
including the session's and the priority ones, and those of a moved XDG_CONFIG_HOME or XDG_DATA_HOME), including under
an alias of the unit or an alias of an alias and in /run/systemd/user, the launched program or the script passed to
an interpreter changed, replaced by a link or deleted, and any change to a file that sets variables for sessions
(bash, zsh and fish profiles, Hyprland and the files it reads through "source =", environment.d, the systemd manager
configuration, pam_env), read in full, even a comment, bring the alert back, which then says why and where. A unit
can only be declared if each of its directives, and of its additions', belongs to a short closed list (describe,
order, restart, Type, User, Nice, the variables of the safe list, dependencies on ".target" targets, the Exec lines):
any other (PrivateTmp, JoinsNamespaceOf, LoadCredential, PAMName, OnFailure, OnSuccess, UnsetEnvironment, a [Socket]
section…), an empty ExecStart=, a dependency on a service or a variable whose value is a path makes it refused; each
Exec line of the unit and of its additions is shown and bound with what it starts, like the reported line. A variable
file that names a variable making code load (LD_*, BASH_ENV, ENV, PYTHON*, NODE_OPTIONS, GTK_MODULES…, even escaped, split by quotes or by a "\" at the end of a line: the line is read joined, as the shell and environment.d read it; AWKLIBPATH and VSSCRIPT_PATH too, outside a file only root can change, which is never trusted inside a user namespace) makes everything refused, and the refusal names the file and the line. "source" lines are
followed at every level: Hyprland's, also outside ~/.config/hypr and through a wildcard in the last name; a
profile's at command position, also after "&&" or inside an "if … fi", through an absolute path or under ~ or $HOME;
also split by "\"; those that cannot be followed (relative or computed path) are listed in the detail. A launch line of a file that Hyprland reads through "source =" outside ~/.config/hypr is reported, without being declarable. The detail shows one line for the
bound variable files, then in clear each line that sets a variable outside the safe list. The folders of the real
path of a bound file, behind a folder link, are compared too. ~/.xsessionrc, ~/.bash_logout and the zsh files under
ZDOTDIR are read. What
cannot be recorded without ambiguity (a variable, a pipe, code in the line, a module, a launcher such as env or sudo,
an addition that redirects the program, its working directory or its environment, a service variable outside a short
list of known ones (LANG, TZ, DISPLAY…) or written with a backslash, an unreadable file, a byte that is not UTF-8 in
the line, its file or a path, a script with a carriage return or an invisible character, searched in the raw bytes, a
file read by an interpreter that is not text, a service's standard input, a path through /proc or /dev or with "." or
"..", which names another file depending on the program that reads it, an argument that is neither an option nor an
absolute path for a program Vanguard does not recognise as an interpreter, including after "--" and in an option's
value, a copy of a system interpreter under another name, or a program that cannot be compared with them, a home
folder that is missing or cannot be read, an unreadable folder of the account's startup files, more than 12 lines)
cannot be declared normal; a bound file that is too long or not text is not shown, and this is said (its fingerprint
can be compared with sha256sum); the confirmation also compares the device, inode and dates of each file and of each
folder above it, so a file or one of its folders swapped and put back while you read is seen; a list restored or kept
as is after tampering loses the states it held. Limits: a program looked up in PATH and what the script or launched
program reads in turn (sourced file, import, library, "dofile" of a Lua configuration) are not bound; a program
Vanguard does not recognise can read a file named by an option stuck to its value ("-fMakefile"): nothing binds what
it reads; a profile is a program: its variables with computed names and the files it reads through a computed path
(`. "$DIR/x"`) are not followed (they are listed in the detail), but its own content is bound; variables that say
where to look (PATH, HOME, XDG_*, ZDOTDIR) or that pick a driver by name (__GLX_VENDOR_LIBRARY_NAME,
LIBVA_DRIVER_NAME) or that a root file sets for a single program (AWKLIBPATH from /etc/profile.d/gawk.sh, of an Arch base package) are only bound through the whole content of their file, not through what they name, and a variable
set by "eval" or by an export with a computed name is not seen; the closed list of directives and the refusal of
variables that make code load mean that hardened units (ProtectSystem…) or an account that sets LD_PRELOAD can no
longer be declared normal, on the safe side; a variable set during the session (systemctl --user
set-environment) and Vanguard's own environment are not bound; a file with an ELF header but malformed, in place of the
program, is bound by its fingerprint without being checked as a text, though a shell could read it; a launched file over 32 MiB (node, deno) or a non-ELF file over 1 MiB
is not bound, so it cannot be declared; folders added through XDG_CONFIG_DIRS or XDG_DATA_DIRS are not followed; the
state is only compared at each scan, so a program that puts the original content back before each pass is not seen;
binding the whole environment brings accepted alerts back at each change of a profile, of Hyprland or of
/etc/profile.d (a package update included), on the safe side, and a folder of the path changed between the scan and
the confirmation makes the choice refused, to be made again; a hostile program that opens a pseudo-terminal itself can
answer in the person's place, but the choice is still written to the log; on Windows, Run keys and tasks are still
declared by their command line alone.

## What leaves the computer

The threat, version and vulnerability lists are downloaded in full, the same for everyone. What Vanguard sends
itself:

- **On Windows**, the list of installed software does not leave: their versions are judged against these lists.
- **On Arch Linux, after consent** (Settings › AUR packages, off by default): the names of the packages installed
  outside the official repositories, to aur.archlinux.org, to learn their latest version (rule LNX-MAJ-006 and AUR
  updates); without this consent, these packages are not checked, which is said.
- **After consent**: the email address to the services that look up its leaks, the public Internet address to the
  four blocklists (Spamhaus, SpamCop, DroneBL, PSBL), the domain name of an examined link.
- **A checked password**: only 5 characters of its hash, to Have I Been Pwned; never the password.
- **With an abuse.ch key**: the key, to abuse.ch.
- **In public Wi-Fi mode**: DNS queries, to CIRA's Canadian Shield.
- **The update check**: a request to GitHub.
- **The improvement record**: nothing in this version. The relay that will receive it is not deployed and the program
  does not have its address; without it, Vanguard prepares no sending and opens no connection (a test counts it). What
  would leave one day, after the notice shown at launch or your "yes" (before 1.0, a "yes" will be required), never
  after "No", is described below ("The improvement record and its relay").
- A vulnerability report prepared by Vanguard is never sent by it: the person reads it and sends it themselves.

This list is closed: Vanguard refuses to reach over HTTPS a host that is not in the first table (even at the end of
a redirect), and a test in the repository fails if the code names a destination missing from these tables, or if a
table names one the code no longer reaches. A proxy set in the system receives Vanguard's HTTPS connections (the
encryption stays end to end up to the site); the public address judged by the blocklists is then that of its exit.

### Sites reached over HTTPS

| Site | What for | What leaves |
|---|---|---|
| `api.pwnedpasswords.com` | Checked password | 5 characters of its hash |
| `haveibeenpwned.com`, `api.xposedornot.com` | Leaks of an email address, after consent (the first with a key) | The email address; the Have I Been Pwned key |
| `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `urlhaus-api.abuse.ch` | MalwareBazaar, ThreatFox and URLhaus lists | The abuse.ch key |
| `feodotracker.abuse.ch` | Botnet servers | Nothing |
| `raw.githubusercontent.com` | Stalkerware indicators (Échap) | Nothing |
| `www.cisa.gov` | Exploited vulnerabilities (KEV) | Nothing |
| `www.loldrivers.io` | Vulnerable drivers | Nothing |
| `armmf.adobe.com`, `clients.config.office.net`, `edgeupdates.microsoft.com`, `res.public.onecdn.static.microsoft`, `product-details.mozilla.org`, `versionhistory.googleapis.com`, `versions.brave.com`, `slack.com`, `formulae.brew.sh`, `endoflife.date`, `codeload.github.com` | Latest software versions and security advisories, whole lists | Nothing |
| `aur.archlinux.org` | AUR packages, after consent | The names of the packages installed outside the official repositories |
| `github.com`, `release-assets.githubusercontent.com`, `objects.githubusercontent.com` | Vanguard update, tldr help pages | Nothing |
| `rdap.org` | Age of an examined link's domain, after consent | The domain name; rdap.org forwards the request to the domain's registry (a single hop, over HTTPS), the only redirect allowed outside this table |
| `1.1.1.1` | Public Internet address (blocklists), presented certificate (intercepted HTTPS) | Nothing |
| `speed.cloudflare.com` | Connection speed, on request | Bytes without content, received then sent: about 500 MB at most each way |

### Direct connections

| Destination | What for | What leaves |
|---|---|---|
| `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001` (Cloudflare), `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9` (Quad9), `8.8.8.8`, `8.8.4.4`, `2001:4860:4860::8888`, `2001:4860:4860::8844` (Google), `94.140.14.14`, `94.140.15.15`, `2a10:50c0::ad1:ff`, `2a10:50c0::ad2:ff` (AdGuard), `149.112.121.20`, `149.112.122.20`, `2620:10a:80bb::20`, `2620:10a:80bc::20` (Canadian Shield) | Fastest DNS (DNS questions); DNS audit and “No Internet” (Cloudflare, Quad9, Google): does a TCP 443 connection open? connection quality and post-quantum probe to `1.1.1.1` | Common names, the same for everyone; the public Internet address, as to any site |
| `www.amazon.com`, `www.apple.com`, `www.google.com`, `www.microsoft.com`, `www.wikipedia.org`, `www.youtube.com`, `www.example.com` | Names asked to measure or check DNS | The name, to the DNS |
| `one.one.one.one`, `dns.google`, `dns.quad9.net`, `internetsociety.org`, `dnssec-failed.org` | DNS audit: known answers, DNSSEC | The name, to the DNS in use |
| `stun.cloudflare.com`, `stun.l.google.com`, `stun1.l.google.com` | NAT type, and address seen from the Internet at each full network audit (never offline) | The public Internet address and port, as to any site |
| `zen.spamhaus.org`, `bl.spamcop.net`, `dnsbl.dronebl.org`, `psbl.surriel.com` | Address blocklists, after consent | The public Internet address, in a DNS question |
| `dbl.spamhaus.org`, `multi.surbl.org`, `dbltest.com`, `test.surbl.org` | Domain blocklists, for an examined link, after consent (and their test name) | The domain name, in a DNS question |

The check also asks the system DNS for a random name under .com, which does not name Vanguard (does the DNS
invent answers?), except offline. The names of the sites in these tables go through the system DNS, as for any
program; in public Wi-Fi mode (and after consent in “Fastest DNS”), that DNS becomes the Canadian Shield or the
chosen DNS, for the whole computer. The list of outgoing connections asks that DNS for the reverse name of each
remote address. The other direct connections stay on the local network: the router (UPnP, SSH and HTTPS probes), printers, cameras,
the device scan, LLMNR and mDNS.

### Programs run by Vanguard

During the check, without separate consent, Vanguard asks the system's tools for pending updates, and they query their
repositories: checkupdates, dnf, apt, zypper, flatpak, snap, fwupdmgr (firmware, LVFS); yay or paru only with the AUR
consent. On request or after consent, it runs programs that reach their own servers: the package manager (pacman, apt,
dnf, winget), flatpak (`dl.flathub.org`), freshclam for ClamAV, the Defender signature update, trivy for containers
(its vulnerability database); nmap only queries devices on the local network. A page opened in the browser after
consent (“Report” pages, public Wi-Fi portal: the system probe's address, NetworkManager's on Linux, shown first) is
reached by the browser. An extension added by the person has the computer's network, unless run isolated (Linux).
These destinations depend on those programs, not on Vanguard.

### The improvement record and its relay

Since 0.89.1, Vanguard keeps a local record of how it runs, so that the author learns what fails or slows down on
other computers. Four stages; the last two do not happen while the relay is not deployed, which is the case today:

- **On the computer.** Each day the record notes, as aggregated counts, Vanguard's errors, its slowdowns, the result
  of fixes and the choices made in Vanguard, with the platform reduced to a closed list. An open lane keeps names in
  it, because a problem is hard to understand without them: name and version of the software, services and drivers
  involved, model of the processor and graphics card (no serial number), error texts cleaned by `amelioration::texte`
  (paths, addresses and tokens removed) or dropped whole. It never holds: the content of a file, the arguments of a
  command, a password, the browser history, typed text, the list of your files, accounts, networks or devices, or the
  inventory of your software. It is kept in `amelioration/` (sealed, at most 96 KiB a day, 90 days, 10 MB in all) and
  the batch it would yield can be read, byte for byte, through "See what would be sent". Answering "No" to sharing
  erases it, along with the sending queue and the installation identifier; this "No" is also noted separately
  (`partage-non`), which an older version that rewrites the settings does not touch, and holds until a "Yes" given in
  Vanguard. `VANGUARD_ENVOI=0` turns it off.
- **The sending queue, with no host.** `RELAIS` is empty in the code and the closed list of HTTPS sites (`HOTES`, the
  first table above) holds no relay: no batch is prepared, no sending file is written, no thread or connection is
  started. Even with a relay, nothing would leave under the tests, under Wine, in CI, with `VANGUARD_ENVOI=0`, from a
  key, as root (Linux), in a development build, offline, before the notice shown at launch or your "yes" (before 1.0,
  a "yes" will be required), after "No" to sharing, or for what was recorded before the day of consent.
- **The relay, once deployed.** Its address will then enter `HOTES` and the first table, like the other sites.
  Vanguard will reach it over HTTPS only, without following a redirect; it will send at most one batch a day (96 KiB,
  strictly re-read before leaving), with an installation identifier drawn at random and renewed every 90 days; at most
  three attempts a day, 24 h of waiting after a 429 or a 503, seven days kept at most. Only the response code is read,
  never the body: there is no downward channel, and no instruction, rule or update can come through the relay. The
  relay's code is in the repository (`relais/`): it checks the same schema, strictly, and one layer of the secret
  detector, refuses a batch where that layer goes off (the full strict reading is done again at the author's), does
  not keep the IP address (a fingerprint of its prefix, with a salt drawn each day and erased the next day) and erases
  what is not collected after 14 days.
- **At the author's.** Each collected batch is re-read as if it came from anyone: the same strict reading, refusals
  counted, a quarantine for any batch where the secret detector goes off (never read further). A source (the
  fingerprint of the address prefix) counts once a day, whatever its number of batches, and a signal needs at least 5
  sources in 3 /16 networks. A likely false positive, the path a poisoner would take to get a rule relaxed, never goes
  to the watch's AI: only into a ticket, which the author judges. Names and texts from the batches enter a ticket only
  inside a data block closed by a marker drawn at random that this data does not contain (`~~~~donnees-` followed by
  16 hexadecimal digits), and a name the author never approved appears elsewhere only by its fingerprint
  (`inconnu#…`). Nothing in a batch is an instruction, and the watch never merges or pushes anything.
