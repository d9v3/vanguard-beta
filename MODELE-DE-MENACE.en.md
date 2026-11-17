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
| An AI agent that does too much | AI servers open to the network, agents that act without asking, poorly protected MCP servers. The door Vanguard itself opens to assistants is read-only (see [The read-only door for AI assistants](#the-read-only-door-for-ai-assistants)). |

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
- **SSH settings meant for some servers only.** Vanguard reads the SSH client configuration (`~/.ssh/config` and its
  `Include`s; `/etc/ssh/ssh_config` only for the post-quantum exchange: agent forwarding or host-key checking turned
  off in that system file are not reported) with OpenSSH 10.6's rules (including the `Match host=…` form, which an
  older client rejects; a list pattern of 1023 bytes or more, which SSH never compares, makes the scope doubtful; a
  `KexAlgorithms` list longer than 4096 bytes is reported as not read), but it only judges what may apply to every
  server: a
  setting under a `Host` or `Match` that names a server is not reported. Nor does it see that several precise `Host`
  lines, taken together, cover every name (one per first letter, for example). A header SSH may apply to every
  server (`Match user`, `Match exec`, `Host *.*`…) is treated as global: it raises the alert, and Vanguard never
  takes it on trust to announce a post-quantum exchange as "offered" or settings as "correct". Alerts are bounded:
  one per setting and per file, sixteen at most, the rest counted.
- **A startup entry changed during the action (Linux).** `demarrage --retirer` refuses an autostart entry changed
  between its reading and its writing, within the same run. The fingerprint, however, only names the path: an entry
  changed after the list was shown (`demarrage --json`, the window) and before the action is removed as it is then,
  and the note keeps that content, put back byte for byte. Windows of about a microsecond remain, which already
  require the account's rights to aim at: a content swapped just after the second reading is lost (the old one is
  written hidden, the note says what was shown); an autostart folder moved out of the home folder after it was opened
  receives the write where it now is (the link put in its place is not followed). An entry kept behind a link
  (dotfiles), an entry that is itself a link or a pipe, an `XDG_CONFIG_HOME` or `HOME` that is relative or contains
  `..` are neither read nor offered, and the list says so (“not verified”, in `demarrage --json` as in the terminal
  checklist), never “no program”. An autostart entry that cannot be read within bounds (64 KiB or more, not UTF-8) is
  neither removed nor put back over (a note from an old removal does not overwrite it), and the list says so; an
  entry that, once hidden, would exceed 64 KiB is said “to keep” and refused before anything is written. Known limit,
  for 0.95: the account's systemd unit file is still read without a bound to get its command.
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
- **Where the list shown in the administrator window comes from (Windows).** The elevated process checks that its
  parent is the announced process and that the file of its program has the same bytes as its own: this proves which
  file started the parent, not which code runs in it. A program of the same account can drive a non-elevated Vanguard
  of that account, or start the real vanguard.exe itself and hold the pipe in its place; the list received then does
  not come from what you asked for. What remains: the closed list of actions, the orders judged again by the elevated
  process, the script shown in full after its fingerprint is checked, and your Enter. Compare what is shown with what
  you just asked for. Such a program could already ask for PowerShell to be elevated itself; going further would take
  a signed program (the author's decision).
- **The copy of Vanguard placed on this computer.** Vanguard notes in a sealed register the fingerprint and version
  of each copy it places in your folder. It never replaces a newer copy with an older program, nor a newer copy it
  does not recognize (neither noted, nor published and signed for this system according to the signed version
  history): this is reported as "not checked" and nothing is set up. A list of copies that is deleted, emptied,
  damaged or changed outside of Vanguard is never read as "nothing noted": a key then refuses to set up its copy, does
  not rebuild the list, and states the way out (put the latest published version on the key, then run it again from
  the key with Internet: Vanguard checks that its number is not older than the latest signed version and that its
  bytes are in the signed version history for this system, then rebuilds the list; setting up elsewhere never lifts
  this doubt); the update from GitHub then replaces the copy with the latest signed version only, and says so; a copy
  already at that number, or missing, is not replaced and the doubt is still reported. If the versions already seen
  were also changed outside of Vanguard, the latest signed version is unknown until you run "vanguard
  se-mettre-a-jour" with Internet and accept to start over from the signed version received (the versions seen
  are only forgotten once that signed manifest is received, never offline); until then, everything
  stays "not checked", never counted as sound. What remains: the seals of this
  register have no secret, a barrier and not a safe; a program of your account that rewrites the register along with
  its seals can have another copy noted in it, or erase the note, and a fully erased state (register and seals) looks
  like a new computer: an older key places its copy there without knowing anything. This protection only comes with
  the versions that contain it: a key published before it does not read the list of copies. When the signed history
  does not answer (offline, GitHub unreachable or filtered, history missing or badly signed, or no published version
  for this system), a newer copy placed by a version from before this register cannot be judged and is refused. The
  way out of a list in doubt does not require a recent manifest: an old signed manifest, put back in place, can make
  an old key pass for the latest one. Monitoring, maintenance, the watcher (Linux) and "se-mettre-a-jour" return a
  non-zero exit code after a refusal, even when the input ends on a question that follows it (your "n" is not a
  refusal; neither is GitHub being unreachable, except when the list of copies is in doubt: the doubt is then
  reported, with a non-zero code); versions already seen that were changed outside of Vanguard return a non-zero code,
  even after "start over", when there is a Vanguard program here to update (a placed copy, or the program
  started outside of the key and replaceable); with nothing to update, they are neither reported nor counted (zero
  code), except when the list of copies is also in doubt; as root with another account's folder, nothing is promised;
  the shortcut still returns a zero code. Vanguard's temporary copies are recognized in the account's folder (`XDG_RUNTIME_DIR` or
  `TMPDIR`): a program of the account can place an exact copy of Vanguard there and have it taken for the key of the
  launch; no gain found for it, as it already has the account's rights.

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
- **The account variables that readings keep.** A system tool run to read runs under your account, with an environment
  emptied except for a short list (language, terminal, desktop, HOME, TMPDIR, TZ, the XDG folders, the proxy). What a
  program of your account can still change there: the proxy (http_proxy…) can make a network reading fail or detour
  it: over https, it is then reported as not checked, not healthy (re-read at the 0.95 re-check); through an http
  mirror, this is not verified; XDG_DATA_DIRS changes the default values gsettings reads; XDG_DATA_HOME is kept but
  FLATPAK_USER_DIR removed, so account Flatpak applications installed elsewhere through that variable are not seen;
  DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR name the session bus, which a fake bus served by an account program can
  replace for what is read through it (gsettings, systemctl --user). These readings concern the account's own state,
  which such a program can change anyway (see the next point).
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
  a seal, can be deleted. Each file is sealed in two steps: Vanguard first notes the content it is about to put down (“pending”), then writes and seals it. Killed between the two, it then accepts the old content as well as the new one, until a command that can write reads that file again; killed during a removal, the removed content, put back by another program, reads as intact. Both contents are Vanguard's, and forging a pending entry takes rewriting its seals (see above). An older version of Vanguard, put back after an update, does not know these pending entries: it reports as tampered a file left between the two steps (safe direction). Updates on Arch (checkupdates) are read with a separate database, in a folder with a random name, closed to other accounts, under the temporary folder: a program of the account that watches for its creation can put its own list of installed packages there before checkupdates does, and the reading can then say “up to date”. This is not seen. The real answer, a service running under an account other than yours (administrator), is
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

**The window comes back in 0.96, verified.** In 0.94, `vanguard` started any executable named `vanguard-fenetre`
placed next to it, on the strength of its name and location, not its content: a fake one could have said "open" in
its place; 0.95 no longer started it at all. Since 0.96, `vanguard` only starts the window built with it:
`outils/compiler-version.sh` builds the window first and engraves its SHA-256 fingerprint in `vanguard`, which the
author signs (manifest and version history); the window's fingerprint is therefore signed along with it, with no
extra key or signature. On Linux, its bytes are read through a handle opened without following links, copied into
a sealed in-memory file (memfd: nothing can change it any more), the fingerprint is computed on that copy, and that
copy is what runs, not the path: a window replaced on disk after the check does not run. On Windows, the file is
held open with read-only sharing (nobody can write, delete or rename it while the handle lives) from the fingerprint
check until "open". A different fingerprint, a program built without one (`cargo build`, the tests) or an
unreadable mark: no window, the menu, with the reason.

`vanguard` with no argument opens the Vanguard window (`vanguard-fenetre`, a separate program placed next to
`vanguard`) when someone is in front of a graphical screen; otherwise, the terminal menu, as before. Its
safeguards:

- **It does nothing by itself: reads, and four actions accepted one by one.** What changes the computer only goes
  through four actions, each shown in the window then accepted, and judged again by `vanguard`: removing or putting
  back a startup program, applying an account fix, putting it back as before, installing the Vanguard update (each
  described below). Everything else is reading: it runs the `vanguard` program placed next to it (absolute path,
  never looked up in the PATH; started from an in-memory file, it receives that path from `vanguard` through
  `--vanguard`, and applies the same safeguards to it) with a command from a closed list, which changes nothing on
  the computer (`audit`,
  `protection`, `evenements`, `diagnostic`, `test-connexion`…), always with `--json`, no free argument, no shell,
  input closed, one at a time, with a time limit and a Stop button (on Linux, the whole process group is stopped,
  and whatever is left of it when the command ends too; `vanguard` is only reaped afterwards, so that group number
  cannot belong to anyone else; a process that left the group and keeps the outputs open does not hold the window, which lets go of the pipes).
  The window's console only accepts the names on that list. On Linux, that `vanguard` must be a regular file owned
  by the window's account or by root, that neither the group nor others can modify, in folders (up to `/`) that
  neither the group nor others can modify either (except a folder with the sticky bit, like `/tmp`), or it is not
  started: the same rule as for the window, below, checked again before each command, not only at opening.
- **First action, in two steps: a startup program removed or put back.** The startup screen shows the state of each
  program that starts at login. An ordinary program has “Remove from startup”, a program removed by Vanguard has “Put
  back”; a program to keep or a firewall has no button, its reason is shown. A click only opens a confirmation inside
  the window (name, command, what will happen, administrator window if the program belongs to the whole computer);
  only “Accept” starts the change, one at a time, buttons greyed out while a command runs, with no “remove all”. The
  window only offers the actions that `vanguard demarrage --json` has just written, and only sends the kind (remove or
  put back) and the program's fingerprint (32 hexadecimal digits, computed by `vanguard`): never a name, a command or
  a path. The form started is closed, `vanguard demarrage --retirer|--remettre <fingerprint> --json`, and `vanguard`
  judges everything again: without the action's consent (`--accord`, the one `demarrage --json` gives, which binds the
  name, the whole command and the scope), nothing is done, the fingerprint alone no longer designating anything (the
  window gives back, as is, the consent the list gave, without computing it; under Linux, its relay adds it to the
  closed form); malformed, unknown or ambiguous fingerprint, program to keep, firewall, Vanguard's notes unreadable or
  changed outside Vanguard (neither removal nor putting back while they are), “put back” for a program that already
  starts (put back or rewritten outside Vanguard, perhaps now a program to keep: the old note does not overwrite it,
  neither through undoing a block nor through “Put everything back”), all are refused without changing anything; what
  changes goes through the same correction as in the terminal (restore point, previous value noted, a single
  administrator window, never sudo). The console starts no change, in any typed form. “Accept” checks again that the
  action is still in the last list read: a list read again that no longer contains it closes the confirmation (“The
  list changed: nothing changed.”), as changing screens does; the alert watch goes on while a confirmation is open. A
  change once started is not interrupted (cutting it in the middle would leave a half-done state): Stop does nothing
  to it, and under Linux neither does closing the window (the relay lets it finish); it is stopped by declining the
  administrator window. Only its time limit, 15 minutes (the Windows administrator window may wait), cuts it. On the
  `vanguard` side, a change holds the notes lock (`reglages.verrou`) from reading the notes to their last write, as
  the terminal optimiser and “Put everything back” do: two Vanguards never change the notes at the same time, the
  second refuses without changing anything. “Put back” reads the notes again under this lock and requires the same
  noted setting as on the first reading (otherwise refused, nothing written); “Remove” on a program that starts
  replaces an old note left from before with the value read now, so that “Put back” brings back the state from before
  this removal. Under Linux, this previous value (the autostart entry) is read in a single opening that does not
  follow a link, does not wait on a pipe and stops at 64 KiB: otherwise refused, nothing changed (an entry that is a
  link therefore cannot be removed from here), and an entry unreadable in this way is offered neither for removal nor
  for putting back (the list says it was not read), and “Put back” never overwrites it. An entry that, once hidden,
  could no longer be read back within this bound is refused before being written. The list and the name of a removed
  entry are read the same way, bounded, without waiting on a pipe; a rewritten entry keeps its permissions. Each
  change done or refused is written to the event log (kind, cleaned name, outcome, fingerprint); a refusal identical
  to the previous one (same fingerprint, same kind, same reason) is not written again for 10 minutes, so that a burst
  of requests does not drown the alerts; a change done is always written. Its end is told (done, refused, failure,
  with the reason), then the list is read again; only the last line of the output, a JSON of the same action, with
  exit code 0, means “done”: anything else is a failure, never a success (`fenetre/src/attaques.rs`, tests B1 to B3).
  Tests: `une_confirmation_ne_bloque_rien_et_suit_la_liste` (`fenetre/src/appli.rs`), the relay tests
  (`fenetre/src/relais.rs`), `verrou_des_notes_tenu_puis_rendu` and those of `src/optimiser/demarrage.rs`
  (`seul_un_programme_note_se_remet`, `pare_feu_reconnu_par_son_paquet`),
  `valeur_d_avant_d_autostart_ni_lien_ni_tube_ni_trop_gros`, `entree_trop_grosse_ni_proposee_ni_ecrite` and
  `liste_et_noms_lus_bornes`, `remise_sur_une_entree_pas_lue_n_ecrit_rien`,
  `entree_trop_grosse_une_fois_masquee_refusee_avant_d_ecrire` (`src/optimiser/linux.rs`), and end to end, with a
  throwaway home folder, `demarrage_retire_puis_remet_a_l_octet_pres` and the `demarrage_sous_attaque` module
  (`tests/programme.rs`: putting back over a program that starts, from the window and through “Put everything back”,
  removal on doubtful notes, simultaneous changes, link, pipe, oversized entry, permissions, lock held, forged or
  replayed notes, repeated refusals). The action written by `vanguard demarrage --json` also carries a consent: a
  BLAKE3 fingerprint (64 hexadecimal digits) of the kind, fingerprint, name, command and scope shown, and of the
  fingerprint of the whole name and command (the text shown is cut at 80 and 160 characters: two commands that only
  differ after the cut give two consents). The finding's object (an autostart entry) goes to the window as “~/…”, no
  longer by the home folder path; the fingerprint stays that of the whole path, as before. Given back with
  `--agreement <consent>`, `vanguard` reads the programs only once under the notes lock, and that same reading judges
  the consent and decides the action (remove or put back): it requires the same consent: a program whose command, name
  or scope changed between the list and the click is refused (“changed since the list”), nothing is written, and the
  consent of a “remove” does not work for “put back”. Without `--agreement`, nothing is removed or put back (“missing
  agreement”); the window reads it strictly and gives it back in its change frame, with the kind and the fingerprint.
  A window taken over can still read the list again and give back the current consent: it does not prove that a person
  clicked, only that what is changed is what was shown. Tests: `accord_de_chaque_champ_montre`
  (`src/optimiser/demarrage/resultat.rs`), `une_seule_lecture_juge_l_accord_et_choisit`
  (`src/optimiser/demarrage.rs`), `demarrage_l_accord_tient_ce_qui_a_ete_montre` (`tests/programme.rs`).
- **One account fix, shown then applied, then put back as before (commands and window).** The audit
  (`audit --json`) gives each fixable finding a token (32 hexadecimal digits); `vanguard correction --show <token>
  [--json]` runs only the token's rule again and shows everything the fix would do (commands, rights, values before,
  undo) with a consent, the BLAKE3 fingerprint of everything shown (and, for each file, its kind, device and inode
  number). It only writes the preview log (token, consent, time; sealed, data folder 0700), nothing else. A tampered
  preview log (changed outside Vanguard, or unreadable) is replaced by a new one, and this is said: “preview log
  tampered with: replaced” at `--show` (on the error output in JSON), then a “carnet-altere” alert in the event log at
  the next action; earlier previews no longer count. In read-only mode, `--apply` and `--undo` are refused outright
  (code 2), before any reading. `vanguard correction --apply <token> --agreement <consent> [--json]` does one fix at a
  time, and only an account fix that undoes exactly: today, the permissions (chmod) of files in the home folder
  (`permise_au_compte`, `src/machine/apercu.rs`, is the only door; everything else, and everything that would need
  administrator rights, is refused and is done from the terminal). When acting, `vanguard` holds the notes lock, reads
  the state again with the same rules as the preview, redoes its guards (owner, file kind, hard link, UTF-8 name, no
  link on the path), computes the consent again and compares it (changed since the preview: refused, nothing changed),
  then consumes the preview log entry (at least 2 s after the preview, at most 10 minutes; missing, falsified, already
  used: refused), first writes its trace (an “in progress” line in “What Vanguard changed”, and its event), then notes
  the value before with the file's kind and inode (otherwise nothing is applied), sets each permission and completes
  the trace. Permissions are read and set without a shell or any program started: each element of the path is opened
  from the home folder without following a link (openat, O_NOFOLLOW), read on the descriptor (fstat) and set on it
  (fchmod), only if it still has the value read and is the same file (same kind, same device, same inode: otherwise
  “changed since”, nothing changed); a link on the path is refused. `vanguard changes --json` gives, for each account
  fix that can be put back from here, the `voir-annulation` action and its token; `vanguard changes --show <token>`
  shows each file, its permissions today, those before and those Vanguard set (“changed since” if someone touched it),
  with a consent; `vanguard changes --undo <token> --agreement <consent>` puts back exactly the permissions before,
  only once, under the same guards, on the noted file only (another kind or another inode: refused, nothing changed),
  and refuses when a more recent note targets the same file and is shown (to be put back first); a more recent note
  that is not shown never blocks. Only “done”, read back “back”, exits with code 0; “not back” exits with 1. Each
  request, done or refused, goes to the event log: the rule, the token and the typed outcome only (“done”, “refused
  (change-depuis)”, “failed (echec)”…), never a file name or a command; the detailed reason, which may name a file, only goes
  to the screen and the window. What goes to the window names files “~/…”, never by the home folder path. What the
  consent does not prove: that a person clicked. A window taken over, or another program of the account, can ask for
  the preview then apply it; all it gets is a hardening of the account's file permissions, one fix at a time, written
  to the log and put back exactly in one action; nothing that raises rights. The preview log and the notes are
  sealed, but the seal is a barrier, not a safe: a program of the account that can seal again can backdate the log
  (the 2 s delay no longer holds), put an old log back (the same action replayed without a new preview) or forge a
  note (permissions such as 0666, 1777, 0000 or 0200 are accepted, 4755 refused; a note without a file identity
  targets the file that bears the name today; a note redirected to another file: the preview shows the real target,
  but the line in “What Vanguard changed” keeps the old name). Everything stays inside the home folder (outside it,
  `..`, relative path, link: refused), and that program could already change those permissions itself. The JSON of
  these commands (`commandes`, `avant.geste`, `valeurs.chemin`) carries the exact names, bidirectional and zero-width
  characters included (the messages and the text screen make them harmless): the window must clean them before
  showing them. These commands are hidden from the online
  help (they serve the window) and described here and in the command table. All or nothing: if a file is refused,
  those already set are put back as before; if that fails, it is said file by file, and a file never touched is never
  said “changed since”. A brutal stop (Vanguard killed midway) leaves the trace written before acting: the line shows
  as “interrupted” in “What Vanguard changed” and is put back like any other (“nothing to undo” if the value before
  was not noted yet); a note without a line, from before this change, shows the same way. An undo killed midway
  likewise leaves its line “undo interrupted, to resume”, written before anything is restored, never “undoable” as if
  nothing had moved; a second undo finishes it. Once finished, the line is said undone before the note is dropped:
  killed in between, it says “undone”, never “done”. The test stop point
  (`VANGUARD_ESSAI_ARRET`), like the tests' tool reported absent (`VANGUARD_ESSAI_ABSENT`, which only removes),
  only exists in a debug build, never in the published one. Tests (`tests/programme.rs`,
  throwaway home folder): `appliquer_une_correction_du_compte_une_seule_fois`,
  `appliquer_refuse_un_etat_change_depuis_l_apercu`, `carnet_falsifie_ou_note_impossible_rien_n_est_applique`,
  `remettre_comme_avant_exactement_une_seule_fois`, `remettre_dans_l_ordre_et_sur_l_etat_montre`,
  `remettre_refuse_un_lien`, `tue_apres_la_pose_la_ligne_est_interrompue_et_se_remet`,
  `tue_avant_la_pose_rien_n_est_dit_change`, `annulation_tuee_en_route_ne_se_dit_ni_annulable_ni_faite`,
  `le_journal_ne_nomme_ni_fichier_ni_commande`;
  `refuse_un_lien_a_chaque_element`, `un_autre_fichier_sous_le_meme_nom_n_est_pas_touche` (`src/optimiser/droits.rs`),
  `une_ligne_refusee_fait_remettre_les_lignes_deja_posees`, `en_lecture_seule_rien_ne_s_applique`
  (`src/machine/appliquer.rs`), `seul_le_revenu_est_un_succes` (`src/machine/annuler.rs`).
  From the window: “See the fix” on an audit finding, or “Restore as before” on a line of “What Vanguard changed”,
  opens a sheet showing the preview read strictly (`fenetre/src/donnees/correction.rs`,
  `fenetre/src/donnees/changements.rs`: texts bounded, cleaned and shown sign by sign, bidirectional and zero-width
  characters made visible). A preview that is contradictory, cut, wider than the sheet, would need the administrator or
  cannot be undone has no button that changes anything: the reason is said (and, for a fix that needs other rights, the
  command can be copied for the terminal). The button that changes (“Apply this fix”, “Restore as before”) stays greyed for 2 seconds after the
  preview is shown; one action at a time, no “apply all”. The window only gives back the preview's token and consent,
  as is: its frame carries the kind, 16 bytes of token and 32 of consent (all zero for a “show”, never for an action
  that changes, otherwise the frame is rejected), and the relay builds the closed form itself, `vanguard correction
  --appliquer|changements --annuler <token> --accord <consent> --json`. Under Linux, the relay, which has the
  account's rights, judges again on its side: an action that changes is admitted only if it carries the token and
  consent of the last preview the relay itself relayed for that family (read from `vanguard`'s output, not from what
  the window says), 2 seconds to 10 minutes after it, with nothing else running; admitting it consumes that preview
  and the list that offered it (a second send is refused: a new preview is needed). An action that changes is not
  interrupted (neither Stop nor closing the window). Its outcome is read only in `vanguard`'s exact forms (“done” with
  code 0; for an undo, “revenu” with 0 or “pas-revenu” with 1, said as such); a refusal makes a fresh preview be read;
  everything else is a failure or an unknown outcome, never a success. After a fix is done, “Undo this fix” is offered
  only if the reread list of “What Vanguard changed” offers its token. These bounds of the window and the relay add to
  those of `vanguard`, which judges everything again (log, delay, consent, lock), without replacing them: a window
  taken over can still chain list, preview and consent with nobody there, within the same limits (one account
  hardening at a time, at least 2 s each, written to the log); “Restore as before” is a security decrease with the
  same bounds. Under Windows, there is no relay: the bounds are those of the window and of `vanguard`. Tests:
  `rien_ne_s_accepte_avant_deux_secondes`, `appliquer_puis_remettre_de_bout_en_bout` (`fenetre/src/appli.rs`, a fake
  `vanguard`), `un_geste_qui_change_ne_part_qu_apres_son_apercu`, `seul_l_accord_d_un_apercu_montre_est_retenu`,
  `le_relais_ne_laisse_partir_que_l_accord_montre_apres_deux_secondes` (`fenetre/src/relais.rs`),
  `un_texte_plus_large_que_la_feuille_empeche_d_appliquer_d_ici` (`fenetre/src/dessin/bilan/correction.rs`),
  `le_bouton_qui_change_attend_deux_secondes` (`fenetre/src/dessin/captures.rs`), and the fuzz targets
  `fenetre_relais` and `fenetre_donnees`.
- **Updating Vanguard, shown then installed (command and window).** `vanguard self-update --voir --json` looks for the
  update (the VANGUARD key it runs from, otherwise GitHub: an Ed25519-signed manifest, never a version older than the
  highest already seen) and shows where it comes from, the target version, its SHA-256 checksum, its size and each
  program it would replace with its version today, with a consent that binds each of these fields; it only runs
  read-only and writes only, as a closed list, the preview log (`apercus.json`, its lock `apercus.lock`) and, like the
  terminal for any signed manifest seen, the highest version seen and the main key's revocation
  (`versions/plus-haute-vue.txt`, `versions/principale-revoquee.txt`), with the seal register, its witness and its lock
  (`sceaux.json`, `sceaux.temoin`, `sceaux.verrou`); nothing installed. If that floor cannot be written (seal lock held
  by another Vanguard), the preview says so: “not verified, try again in a moment”. “Up to date” is only said when
  verified: a manifest that is too old, a clock running behind or GitHub not answering give “not verified” (code 1),
  never “up to date”. `vanguard self-update --appliquer --accord <consent> --json` redoes the preview when acting and
  installs only if the recomputed consent is the same (another version, another checksum, a key changed in between:
  refused, nothing changed), consumes the preview log entry (2 s to 10 minutes after the preview, only once), then keeps
  every earlier check: signature, size and checksum, copy written alongside, read back, compared and tried (not yet
  tried on Windows: the window then only says “read back and compared”), put in place at once (otherwise the old one
  stays; on Windows, an old one still running is moved aside, `vanguard.exe.ancien`, erased later, when the state is
  read or after the next consent, only if the copy is a file at its name and that leftover a regular file (a link or a
  folder with that name stays); after a double rename failure, it is kept, with its path said: it stays under that name
  as long as nothing is in its place; tests `le_reste_du_programme_est_garde_sans_copie_a_sa_place`,
  `un_lien_au_nom_du_reste_n_est_pas_retire`, `le_double_echec_dit_ou_reste_l_ancienne` (`src/mise_a_jour.rs`) and
  `le_reste_d_une_mise_a_jour_s_efface_apres_l_accord` (`src/mise_a_jour/apercu.rs`)); it names each program replaced or
  not (code 0 only if all were). The Vanguard window placed next to a replaced program
  follows it, shown as one more line of the preview, so bound by the consent: GitHub's downloaded only after the consent
  and checked against the fingerprint engraved in the verified program (another one, or none received: nothing is
  replaced); once placed, it is read back through the temporary copy kept open under Linux (the same file, the bytes
  received), by its name under Windows (the bytes compared), otherwise a failure, and its result line reads the placed
  window back, without following a link. The key's follows only if it is the one its program engraves; there but not
  placeable (unreadable, a link, or another one), it is never counted as missing: the program is placed alone, the one
  here is not touched, and “the key's window not verified” is said (preview, terminal question), with the reason in the
  result. From GitHub (0.97), a window missing next to a replaced program is added where the launch looks for it (“its
  window, new here”), under the same consent, all or nothing; and at the same version number, a program here that is
  exactly the one the author signed (size and checksum from the manifest), without its window or with another one, is
  offered its window alone (“added alone”, “replaced alone”), checked against the fingerprint it engraves, without
  downloading the program again; a program built elsewhere at the same number gets nothing (its window cannot be judged
  from here, it keeps the menu). Two programs in the same folder share a single window: it is judged and placed once.
  What was at each window path (nothing, a SHA-256 checksum, a link and what it points to, a file the launch refuses
  with its checksum, or nothing readable) is in the consent without being displayed: changed between the preview and the
  click, refused, nothing downloaded. A link, or a file the launch refuses (permissions, owner), is never counted as
  “its window is right”, even with the right bytes: its window is offered as a repair; it is never read through a link
  (opened without following it). The window is judged by the launch's whole rule (the file, `lancer_fenetre::refusee`,
  and, under Unix, each folder of its path, `lancer_fenetre::dossiers_refuses`; under Windows, the launch does not judge
  folders): a folder the launch refuses (a link, another account's, writable by the group or others without the sticky
  bit) is not fixed by placing the window again; this is said in the preview and in the result, with the reason, never
  counted as “verified”, and no repair is offered (a lone window is not placed there).
  These folders are judged with the account that updates, as at launch (a deliberate, stricter choice): under sudo,
  a folder of the person is “another account's” for root; the update says so and ends with code 1, even if the
  launch by the person would accept it. The program is never blocked by
  its window (round 3 of 0.97): next to a window here that cannot be read (permissions, folder, pipe or special file,
  too large), or for a copy that is a link, the program is placed alone, and its window is neither touched nor
  downloaded; this is a separate gesture of the preview (“program alone, its window cannot be read: untouched, the menu
  will open”, “program alone, the copy is a link”), so in the consent: readable again, or the copy no longer a link (or
  one now), between the preview and the click, and nothing is done, the program included. A copy that is a link gets its
  window neither next to the link nor next to the file it points to, under Linux as under Windows, and this is said on
  its line; the link is checked again at placement time (a copy turned into a link since the preview: nothing is
  placed). The placed program replaces the link itself with a file (a rename onto its name, never through it, under both
  systems): its line says to run the update again, which then places the window (from the key, if the key's window is
  verified); a copy that is a link and already up to date (same version, nothing placed) says to put the copy itself in
  place of the link. From the key, the copy being a link is looked at before the key's window: even with the key's
  window not verified, the program is placed alone, never refused at every attempt; its line then gives both reasons
  (the copy was a link, the key's window is not verified, and why), without saying that another round will place the
  window. At the same version number, the lone window of a copy that is a link, unreadable or in a refused folder is set
  aside, with its line in the preview (so in the consent) and its reason. In all these cases, the
  result says “not verified” and why, never followed by a “nothing newer” check mark; when applied, the code is 1; a
  verdict that is not “up to date” (signed version too old, newer here) is still said. When only lone windows are left
  and the version is not verified up to date, the window's preview carries “not verified”, like the terminal. The new
  window is written under a random temporary name (`vanguard-fenetre.nouveau-<32 hexadecimal digits>`, 128 bits from the
  system's randomness source), created new (O_EXCL: never over a file, never through a link); a name already taken is
  never reused, another one is drawn. Only that file is ever erased, never someone else's: under Linux, recognized as
  the same file (device and inode); under Windows, by its bytes (erasing a copy with the same bytes loses nothing).
  Under Windows, the window still running is moved aside under a name drawn the same way (`.ancien-<32 hexadecimal
  digits>`), erased later; this cleanup and uninstalling only remove regular files with these exact names (a folder or a
  link with such a name stays). The cleanup removes nothing while the window is not a file at its name: after a double
  rename failure, that leftover is the last copy of the old one, kept, and its path is said. After a failure (the
  program not installing, or the lone window wrong when read back), what was there comes back, only over the placed
  window: a file with its bytes and its mode, never group or others write nor a special bit (mode & 0755); a mode or
  owner that does not come back as it was is said (“put back with its bytes, as a new file of this account”), a hard
  link to it is not kept (it comes back as a new file); a link as a link (under Windows, it is not recreated and the
  placed window stays, said); a file refused at launch with the permissions of a new file (0755, this account), said;
  what does not come back is said, with the reason; a failure before the rename, where nothing moved, says nothing was
  put back. Known residual: between the last reread of the window in place and the rename that places the new one, the
  time it takes to write and read back the temporary copy, a program of the same account can slip another file there; it
  is then replaced by the verified window (read back through its descriptor under Linux; under Windows, by its name, the
  bytes compared), and, if the program does not install, what comes back is what was read and shown, not that file;
  likewise between the reread that decides a restore and that restore, and between the reread of a folder and the
  placement. Such a program already has the account's rights: it gains nothing it did not have. The terminal installs
  through the same path (`vanguard self-update`, list and question). In read-only mode, `--appliquer` is refused
  outright (code 2). From the window: the settings' “Update Vanguard” card opens the preview sheet, read strictly
  (`fenetre/src/donnees/mise_a_jour.rs`: exact form, bounded texts shown character by character); “Install this update”
  waits 2 seconds and only sends back the consent shown. This gesture's token is fixed (`Empreinte::MISE_A_JOUR`): no
  list offers it, the frame and the relay refuse any other token for it, and the relay only admits it with the consent
  of the last preview it relayed itself, like a fix. The window downloads, verifies and writes nothing itself. What the
  consent does not prove: that a person clicked; a hijacked window can chain preview and consent, and only gets a
  version signed by the author, never older, that the menu would install the same way, logged. Tests:
  `la_cle_ne_pose_que_ce_que_l_apercu_a_montre`, `une_cle_changee_apres_l_apercu_est_refusee`,
  `github_ne_retient_ni_ne_telecharge_avant_l_accord`, `rien_de_verifie_n_est_jamais_a_jour`,
  `l_accord_lie_chaque_champ`, `github_propose_la_fenetre_seule_au_meme_numero`,
  `github_ne_pose_jamais_une_fenetre_seule_fausse`, `github_ne_propose_pas_de_fenetre_pour_un_programme_d_ailleurs`,
  `une_fenetre_changee_entre_l_apercu_et_le_clic_change_l_accord`, `une_fenetre_illisible_n_est_jamais_touchee`,
  `une_fenetre_illisible_ne_laisse_de_cote_que_sa_copie`, `deux_programmes_du_meme_dossier_partagent_leur_fenetre`,
  `une_fenetre_seule_garde_le_non_verifie_du_verdict`, `l_apercu_dit_le_geste_de_chaque_ligne`,
  `la_cle_pose_le_programme_seul_a_cote_d_une_fenetre_illisible`, `la_cle_dit_sa_fenetre_illisible_ou_en_lien`,
  `des_copies_laissees_de_cote_gardent_le_non_verifie_du_verdict`, `la_fenetre_de_la_cle_suit_ce_que_l_apercu_a_montre`
  (`src/mise_a_jour/apercu.rs`), `une_fenetre_montree_illisible_n_est_jamais_comptee_pareille`,
  `une_fenetre_seule_ne_se_pose_que_telle_que_montree`, `deux_programmes_du_meme_dossier_posent_leur_fenetre_une_fois`,
  `une_fenetre_illisible_laisse_poser_son_programme_seul`, `une_fenetre_laissee_puis_changee_ne_fait_rien_poser`,
  `un_lien_ou_une_fenetre_refusee_n_est_jamais_juste`,
  `un_lien_a_la_place_de_la_fenetre_n_est_jamais_lu_et_revient_en_lien`,
  `le_retour_d_une_fenetre_absente_n_efface_pas_un_fichier_etranger`,
  `une_fenetre_posee_mais_fausse_a_la_relecture_est_remise`, `un_nom_provisoire_d_un_autre_n_est_jamais_efface`,
  `seule_l_absence_vraie_compte_absente`, `une_copie_en_lien_laisse_sa_fenetre`,
  `une_copie_en_lien_pose_son_programme_seul_meme_si_la_cle_n_a_pas_de_fenetre_verifiee`,
  `une_copie_devenue_un_lien_ne_fait_rien_poser`, `un_dossier_que_le_lancement_refuse_est_dit_jamais_repare`,
  `un_dossier_refuse_ne_cache_pas_ce_qui_sera_fait_a_la_fenetre`, `un_nom_provisoire_deja_pris_n_est_jamais_repris`,
  `le_menage_ne_retire_que_les_restes_d_une_pose`, `l_ancienne_fenetre_revient_avec_ses_droits_ou_c_est_dit`,
  `rien_n_est_dit_remis_quand_rien_n_a_bouge` (`src/mise_a_jour/sa_fenetre.rs`),
  `remplacer_pose_le_programme_seul_a_cote_d_une_fenetre_illisible` (`src/mise_a_jour.rs`), `mise_a_jour_depuis_la_cle`,
  `l_apercu_d_une_mise_a_jour_hors_ligne_n_est_pas_a_jour_et_n_ecrit_rien` (`tests/programme.rs`),
  `mettre_a_jour_ne_part_qu_avec_l_accord_montre` (`fenetre/src/appli.rs`),
  `la_mise_a_jour_ne_passe_qu_apres_son_apercu` (`fenetre/src/relais.rs`), `la_mise_a_jour_n_a_que_son_jeton`
  (`fenetre/src/protocole.rs`), `non_verifie_ne_se_lit_jamais_a_jour` (`fenetre/src/donnees/mise_a_jour.rs`).
- **Colors: saved by `vanguard`, never by the window.** The Vanguard screen sets, for each theme, one of the six
  presets or the system colors, and the five bright colors (accent, serious, medium, to watch, healthy). The window
  shows them right away, writing nothing; “Save…” opens a confirmation (before, after) and only “Accept” runs the
  closed form `vanguard couleurs --theme <sombre|clair> --base <word> --vifs <5 × 6 hexadecimal digits> --json` (or
  `--defaut`), which the relay rebuilds from a frame of exactly 24 bytes. `vanguard` judges everything again (closed
  words, strict colors) and writes into parametres.json, sealed, under the parametres.lock lock that every change to
  this file takes (the window and the terminal do not erase each other), the previous value read in the same
  re-reading; “Back to the previous ones” puts back exactly that value (the value: starting from a missing file, a
  sealed `{}` remains, which reads like the absence, and keeps the seal that would make a file placed later be judged
  harshly). A color that would barely show on one of the theme's backgrounds (contrast below 1.5:1) is refused three
  times, by the window, by the relay and by `vanguard`, and a kept color that would be so does not count (Vanguard's
  colors); below 3:1, two severities too close or the accent (which also says “to fix”) too close to a severity is
  only a remark (warn, not forbid), repeated in the confirmation, “serious” taken for “healthy” first and in bold. A
  hijacked window can therefore only set ugly or misleading colors (a red “healthy”), never make an alert unreadable:
  every word of state, alert, severity or remark is written in the theme's ink, which cannot be set, and the settable
  color only marks its dot, bar or band (test `aucun_mot_n_est_ecrit_dans_une_couleur_de_gravite`,
  `fenetre/src/dessin/captures.rs`); a severity is therefore never told by color alone, always in words too. Each
  change made is noted in the event log (the theme, the preset before and after); accepted: no rate limit, and the
  sandboxed window gains a lasting channel there, a minimal one (twice 16 bytes of colors it chooses, kept sealed).
  The system colors are read by `vanguard` alone (the window's sandbox does not see the home folder): the colors.toml
  of the Omarchy theme (the first of the two locations that gives one), a regular file whose last component is not
  followed if it is a link (`O_NOFOLLOW`), bounded at 64 KiB, or the Windows accent color (the accent alone); a
  snapshot, read again at each opening. A parametres.json changed outside Vanguard (even with no colors in it),
  erased, unreadable or missing after seals were redone gives back Vanguard's colors, and the reason is said in the
  backstage view and on the Vanguard screen. Above all, `vanguard couleurs` never writes over an unreadable file (the
  other settings, a defense turned off by choice, the “no” to sharing, would silently go back to their default) nor
  over one erased or changed outside Vanguard (resealing would erase the trace): refused, nothing written, and the
  window offers nothing to save; it is up to Settings, which say what they ignored, to rewrite it. An open
  confirmation freezes the draft: what it shows is what gets saved. The “Reduced animations” setting follows the same
  path, with no confirmation (cosmetic, one click undoes it): the closed form
  `vanguard couleurs --animations <toutes|reduites> --json`, rebuilt from a frame of exactly 7 bytes, kept in
  `couleurs` (so reset to its default with them on a doubtful file), same refusals, same lock, each change noted
  (before, after); the window reads it again at opening in the same answer as the colors, and a refusal or a failure
  leaves it valid for this time only, said in the backstage view (tests
  `les_animations_ne_s_ecrivent_pas_sur_un_fichier_douteux`, `src/parametres/couleurs.rs`,
  `les_animations_de_la_fenetre_se_gardent_d_une_ouverture_a_l_autre`, `tests/programme.rs`).
  Tests: `les_couleurs_se_proposent_s_enregistrent_par_vanguard_et_s_annulent` (`fenetre/src/appli.rs`),
  `des_couleurs_passent_seules_et_lisibles` (`fenetre/src/relais.rs`), those of `fenetre/src/couleurs.rs`,
  `fenetre/src/donnees/couleurs.rs` and `src/parametres/couleurs.rs` (`un_changement_s_annule_exactement`,
  `une_demande_invalide_est_refusee`, `un_fichier_change_hors_de_vanguard_rend_les_couleurs_de_vanguard`,
  `un_fichier_illisible_rend_les_couleurs_de_vanguard`, `des_couleurs_gardees_invalides_ne_valent_pas`) and
  `un_fichier_douteux_ne_propose_rien_et_la_confirmation_fige_le_brouillon` (`fenetre/src/dessin/captures.rs`).
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
  it is not placed next to `vanguard`, when its fingerprint is not the one engraved in this `vanguard` (or it engraves
  none), when (on Linux) it is not a regular file owned by this account or root that neither the group nor others
  can modify, in folders that neither the group nor others can modify, when the in-memory file cannot be started (a
  kernel set to `vm.memfd_noexec=2`, an SELinux or AppArmor policy refusing it: never a fallback to the path), or
  when it does not say "open" within 20 seconds. `vanguard --menu` forces
  the menu.
- **Its libraries.** On Windows, like `vanguard.exe`, it loads its DLLs from System32 only: those it imports
  (DependentLoadFlags), and those a library opens by name after startup (SetDefaultDllDirectories, first line of the
  program; opengl32.dll for example). A DLL placed next to it, on the key or in Downloads, is never loaded. On Linux,
  it is linked to the system's glibc (its display libraries are loaded at run time): only the interpreter
  `/lib64/ld-linux-x86-64.so.2` is allowed, with no library folder written into the program (neither RPATH nor
  RUNPATH), checked by each run of `outils/verifier.sh` (`vanguard deploiement verifier-binaire --glibc`).
- **Limits.** Like the program, it assumes only you can modify its folder: a fake window placed next to it is no
  longer started, but whoever can replace `vanguard` can replace both. On Windows, the launch is checked under Wine
  only (not yet on a real Windows), and the process is not created suspended to compare its image with the held
  handle: the handle without write sharing is what guarantees the file. On Windows, the window and `vanguard` only check that the other one is a regular file:
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
  (`le_relais_n_impose_aucun_intervalle_entre_deux_changements`), each in the log and each can be put back (through the
  startup list or “Put everything back”: these removals are not in “What Vanguard changed”, `changements
  --json`). Vanguard's
  notes and their seals (`src/sceau.rs`) are a barrier against a file placed by another program, not a safe: a program
  of your account that keeps a copy of the notes with their seals can put it back later; “Put back” would then bring
  back an old noted value of a program that no longer starts (over a program that starts, it is refused:
  `notes_forgees_ou_rejouees`). The event log is bounded (13 months, 20 MiB in all, the oldest months go first):
  identical refusals are written only once per 10 minutes (`des_refus_repetes_ne_noient_pas_le_journal`), but requests
  for fingerprints that all differ are each written, and enough of them would push old alerts out of the log. Under Windows there is no relay: these bounds are
  those of `vanguard` alone, and closing the window also stops a change in progress (job object); since the previous
  value is noted before any change, it can still be put back.

## The read-only door for AI assistants

`vanguard mcp` is a read-only door for an AI assistant that the person connects themselves (an MCP client): it can
read what Vanguard has already written, and cannot change anything. **Linux only**: on Windows, the command refuses
to start (code 2) until it has been tried on a real Windows.

- **What it gives.** Five tools, a closed list: `etat` (journal verified or not, last scan of each tool, alerts of the
  last 30 days by severity, protection and switches), `evenements` (the journal, page by page), `constats` (the latest
  scan results), `bilans` (score and number of problems of each check-up) and `identite` (version number, without the
  build date, and SHA-256 fingerprint of the running program). A check-up is said to be verified only if it carries a
  fingerprint trusted by the chain; a history without any fingerprint is said `non-verifiee`
  (`un_bilan_sans_empreinte_n_est_pas_dit_verifie`). That fingerprint is an unkeyed BLAKE3: it shows that a check-up was
  not damaged, not who wrote it, since a program of the account can compute it again. None of them starts a scan, goes
  on the network (the whole process is put offline) or opens a file of the person's. A tool name is recognized only
  exactly: no capitals, no blanks, no path (`la_liste_des_outils_est_fermee`).
- **What it never gives.** No command lines, no paths (of a program, only the short name comes out), no process
  numbers, no accounts, no connection addresses, no computer or network name, no settings, no secrets, no file
  contents, no fix commands. A test plants these values (made up) in the journal, the scans and the history, then
  checks that none of them comes out, through any tool (`rien_d_exclu_ne_sort_de_la_porte`). The text from the
  computer, set apart (below), is the exception: it can quote a name.
- **It writes nothing, except its note.** It reads the sealed notes without adopting or repairing them; a test compares
  the fingerprints of the whole folder before and after a session (`une_session_entiere_n_ecrit_rien`). The only write
  is a session note in the journal: its duration, the number of calls per tool, the refusals by code and the reason it
  ended, never the arguments or the answers. It is written at the first call served, before its answer, then completed
  at the end; a requested stop (SIGTERM, SIGINT, SIGHUP) ends the session and notes it. Only a SIGKILL cuts it off
  without an end note, and the opening note stays. The door creates nothing: on an account where Vanguard has never run
  (no journal and no seals), nothing is noted. A brake bounds what a client can add to the journal: 12 notes and 1 alert
  per hour at most; the next ones are only counted in a small separate file and told by the following note. Nothing is
  written either once the month's journal has taken a quarter of its allowed size: Vanguard's alerts keep their room. A
  note cut in the middle is undone: the month's journal is put back to its previous size and its head taken back without
  the announcement, and the count of held-back notes is erased only after a note written in full
  (`une_note_coupee_de_la_porte_est_defaite`). So that a note is not cut, the door refuses to start under a file size
  limit (`ulimit -f`), or if that limit cannot be read (`la_porte_refuse_un_plafond_de_taille_de_fichier`), reads it
  again before each note (`sous_un_plafond_de_taille_la_porte_n_ecrit_rien`) and ignores the size-exceeded signal
  (SIGXFSZ): a refused write returns an error instead of killing the door in the middle of its note. Under a limit set
  during the session (`prlimit --pid`), nothing of this session is written: neither its note nor its alert, and what it
  held back is not counted either (the next session does not announce it). Whoever starts the door already has this
  power: they can also never start it and read Vanguard's files without it. Limit: if putting
  the size back fails itself, the cut line stays; Vanguard's next write notes it as a break in the journal, without
  adopting anything silently. Its own note does not make the journal "not up to date": it is read again right after
  (`la_note_de_la_porte_ne_rend_pas_son_journal_perime`). The person can thus see that their assistant reads Vanguard,
  and how often. It is a good-faith trace, not a barrier: a program of the account can read Vanguard's files without the
  door.
- **It listens to nothing.** No port, no socket: only the program that started it talks to it, through standard
  input and output. It asks for no rights and gives nothing the account cannot already read. It refuses to run as
  root (code 2, nothing on the output, nothing in the journal: `la_porte_refuse_root`) and refuses a terminal as
  input (`la_porte_refuse_un_terminal`): it is made for a program, not for a person at the keyboard. This refusal is
  a help against a typing mistake, not a guard: a program can always give it a pipe.
- **The client is treated as hostile.** A message is 64 KiB at most, bounded while it is being read, and must finish
  within 10 seconds; an answer must be written within 10 seconds, or the session ends (a client that does not read its
  output does not block the door). A session stops after 15 minutes of silence (a blank line does not break it:
  `les_lignes_vides_ne_rompent_pas_le_silence`), 8 hours or 10,000 requests; after a long pause, the assistant starts
  the door again (the tool may look stopped until then). More than 20 requests in one second (blank lines do not count,
  and the refusal carries the request's id), more than 64 blank lines in the session (`les_lignes_vides_sont_bornees`),
  a message that is not valid JSON, a wrong envelope (an unknown or repeated field, an `id` outside visible ASCII), a
  batch or three unknown notifications close the session; a request for an unknown method gets its refusal without
  closing anything. Parameters are an object, or absent (`null` counts as absent): a request with parameters of another
  shape gets its refusal, a protocol notification is counted as refused, without an answer
  (`les_params_sont_un_objet_ou_absents`). The next page of `evenements` is asked for with a cursor that points to an
  exact place: reading ends even when events carry the same id (`la_pagination_finit_meme_avec_des_ids_en_double`); an
  `avant` given as the id of a repeated event keeps the old meaning (the most recent one with that name). A hostile sign
  is also noted by a medium alert: an ordinary assistant waits for its answers and does not send one, so it is
  compromised, badly written or it is not the assistant
  (`une_session_n_ecrit_que_sa_note_et_le_client_hostile_est_note`). An answer is 256 KiB at most; a page that is too
  long is shortened and says so.
- **Everything it returns is untrusted.** An alert title, a finding message or a program name can quote an attacker (a
  file named to give orders to the assistant, for example). Every answer is marked `"teinte": "non-fiable"`, in three
  forms: in the `_meta` of a result, in the `error.data` of an error, and at the head of a tool's result, in its text as
  in `structuredContent`, before any content (`la_teinte_est_en_tete_de_chaque_reponse`, checked in the written line).
  Names (severity, family, rule, reason, end) come out of a closed list, or empty. The text that comes from the computer
  (title, message, category, program name) comes out apart, as `{"texte_externe": …, "non_fiable": true}`, through a
  word allow-list: only the words Vanguard writes itself in its own messages come out (the strings of its text macros,
  in French and English, taken from the code at each build through its syntax tree, following the modules as the
  compiler does, without the tests: about 8,300 words; a form this reading cannot judge, a module that cannot be found
  or a `.rs` file in `src/` that no module declares stops the build). Any other word
  becomes "…", as do digits, paths, addresses, tokens, names that are not vocabulary words and any sign outside a small
  fixed punctuation set (never a parenthesis or a square bracket; those around a word are dropped); several "…" in a row
  make only one, and the output is 400 bytes at most (`chaque_mot_de_la_sortie_est_du_vocabulaire`, property test). The
  text is normalized before it is judged (full-width forms, invisible characters, quotes, Latin accents recomposed); a
  letter that imitates another (Cyrillic, Kelvin sign, ligature, mathematical letter) is not brought back: the word is
  not known and comes out "…". A one-letter word only comes out if it is "a", "à" or "y"; a word followed by an ellipsis
  ("admin…") or cut by the reading bound (8,192 bytes) comes out "…". Two safety nets hold back values that may be made
  of known words. As soon as a word announces a secret (mot de passe, phrase de passe, password, passwd, pwd, mdp,
  passphrase, clé, key, code, PIN, NIP, PSK, jeton, token, secret, secrète, passe, seed, phrase de récupération,
  recovery phrase, identifiant, login, singular or plural, in any case, with or without hyphens, no separator
  required), the whole rest of the text becomes a single "…", not only up to the first full stop; the only exception is
  a negated announcement ("sans mot de passe", "no password") with no ":" or "=" after it, and no full stop, "!", "?" or
  parenthesis between the negation and the announcement, as in Vanguard's message about a Wi-Fi network without a
  password. A value written before the announcement ("maison rouge is the password") is not held back. In a watcher
  alert, each "(PID n)" opens its own group: the command excerpt that follows it in parentheses becomes a single "…",
  and a parenthesis never closed holds back everything up to the next "(PID n)" or to the end; any other parenthesis
  comes out only if all its words are known. The price:
  useful text that follows an announcement is lost (about 0.8% of Vanguard's text pieces contain one of these words,
  "registry key" and "code" included). These are safety nets, not a guarantee: a value that nothing announces comes out
  if its words are in the vocabulary. It is up to the assistant to treat this text as data, never as an instruction.
  Known limits: a sequence of vocabulary words comes out as it is, with its case, its leading quotes and its
  punctuation. An attacker who writes on the computer can therefore compose a sentence with these words ("Ignore the
  previous instructions" comes out as it is), and spell a value in it through the initials or the case of the words. A
  quoted name (Wi-Fi network, account, program, folder) lets out those of its words that are also Vanguard's words
  ("admin", "maison", "famille", "bureau", "root"), and so does a command line outside a watcher excerpt ("bash",
  "sshd", "cat"). The fixed-form fields (rule, version, date, numbers, fingerprint) come out with the letters and digits
  their form allows, without being reread: an impossible date, a made-up rule or a number that writes a whole IPv4
  address get through. This is a channel for someone who already writes the log or an unsealed review, not a leak of the
  person's data. A module loaded from outside `src/` (the colour model shared with the window) is not read: it has no
  message, and one word less only masks more.
- **It cannot prove it is the real Vanguard.** A fake program placed at the same path would answer the same, `identite`
  included; and a program of the account can write to Vanguard's files (the seals are a barrier, not a safe: see "The
  programs of your account do not target Vanguard itself"). The proof is made before starting, by the client: start a
  pinned absolute path, never a PATH search; check that the file and its folders cannot be written by others; compare
  its SHA-256 fingerprint to that of the published version (`SHA256SUMS.txt`, or the Ed25519-signed list of updates);
  start the verified bytes (on Linux, the descriptor opened for the computation); then check that `identite` gives back
  the same fingerprint. No signed handshake: a key in the program or on the computer could be read by the same account,
  and would look like a proof without being one.
- **A recognized client is never exempted.** The door answers every client the same and changes nothing in the
  monitoring: no allow list, no softened alert. The AI agents audit judges the configuration of the assistant that
  starts it with the same rules as the others.

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
fix yourself can only be declared normal if its rule records what the choice would be bound to: today, on Linux, only a line of a systemd user unit (under /etc/systemd/user, only if the file and every folder of its real path are root-only) or a launch line (exec-once, exec_on_start…) of a file in ~/.config/hypr, judged by its real path (a link that leads out of it, from the file, the folder or a subfolder, is not in it) (the author's decision, 10 Nov. 2026): a line of a shell profile, of environment.d or of the systemd settings, a Hyprland line that sets a variable or comes from a file included outside ~/.config/hypr, a .desktop launcher, a cron, preload or system unit line, and a session variable stay raised until the line is removed (the information about system services added by hand, which only root writes, keeps its bound choice) (the refusal names the file and the line, and says why), and an older choice outside this scope comes back at every check while the line remains, with that reason; detection, for its part, judges each line in the form its real reader runs, and what it cannot reduce to that form is raised ("not read", "not followed"), never counted as safe (adversarial review of 11 Nov. 2026): the shell (lines continued with "\"); systemd (a unit or a .desktop file the way systemd assembles it: "\" at the end of a line, "\r" and "\0" line endings, a BOM at the start of any line, comments in the middle of a continued line; "%" specifiers replaced, an unknown one being raised; escapes and quotes decoded; path simplified ("//tmp", "/var/../tmp"); each command of a line with ";"; every "@ - : + ! |" prefix; the settings that change what starts without an Exec line: LD_PRELOAD and LD_AUDIT always, PATH, LD_LIBRARY_PATH, ExecSearchPath and EnvironmentFile when they lead to a hidden or temporary folder; a ".d" drop-in folder that is a link, followed and reported); Hyprland the way hyprlang reads it (lines joined by "\" with no space; "$name = …" variables replaced on the whole value before it is split into fields, longest first, under any name hyprlang accepts, a variable without a known value in a line that starts something being raised; keywords inside a category; "bind…" shortcuts and gestures that start a command, exec and execr, "[ … ]" rules removed; "plugin" plugins; hypridle keys that start something (on-timeout, lock_cmd…); any other key that names an executable program in a hidden or temporary folder; "source" followed, relative to the file that includes it and whatever its extension, an include with a variable or quotes being raised); Lua at best (text split the way Lua reads it: long strings and long comments, "\ddd", "\xHH", "\z", "\u{…}" escapes, calls with or without parentheses; the commands of the calls that start something, o.bind, hl.bind, exec_cmd, exec_raw, o.launch, hl.plugin.load, os.execute, io.popen, whose launched argument must be literal (strings, joined by ".." or not; since the third check, a value set by "local x = \"…\"", os.getenv or a table is no longer enough); an argument that cannot be reduced that way, a launch function renamed or redefined, load, loadstring, package.path, a computed require, a computed "os[…]" access and anything beyond 4096 calls are raised; every .lua and .conf file of ~/.config/hypr is read, subfolders included); the unit folders systemd reads besides the usual ones (user.attached, every XDG_CONFIG_DIRS and XDG_DATA_DIRS the account can change, and /run/user/<uid> when XDG_RUNTIME_DIR leads elsewhere, the difference being reported); session systemd generators (any program in an account folder, which systemd 262 does not read but another version could; in a system folder, what is not root-only; in a user namespace, only what belongs to the account, root appearing there under another identity) and the units of the session folder (XDG_RUNTIME_DIR/systemd, systemd-run's transient/ included, judged by their content): shortcuts, plugins, what is raised as "not read" or "not followed", the units of the extra folders or of the session and the generators cannot be declared normal (a launch line of an account unit or of ~/.config/hypr that Vanguard reduces to its final form is declared as if it were written plainly); since the second adversarial check (11 Nov. 2026), also: each simple command of a shell line (Hyprland hands its exec lines to "/bin/sh -c", Lua its exec_cmd calls: after "&&", ";", "|", "&", inside "( )", "{ }", "$( )", behind "cd", an assignment, an input redirection or a known wrapper such as env, gamemoderun, xdg-terminal-exec, hyprctl dispatch exec or sh -c), what cannot be split safely being raised; a unit's "%u", "%t"… specifiers and variables ("$A", "${A}", "$$") replaced the way systemd replaces them; unit settings that lead to a hidden or temporary folder (WorkingDirectory, StandardInput, RootDirectory, BindPaths, variables that load code, variable file); ~/.config/systemd/user.conf and user.conf.d; session D-Bus services written by the account (~/.local/share/dbus-1/services, never declarable); a "source" include beyond 64 files, through a wildcard in the folder or from a temporary folder, reported; Lua read with its scopes (parameters, loop variables, "_G", "_ENV", a library passed as a value), Omarchy's helpers that start something, require and dofile resolved the way Omarchy's loader resolves them (~/.local/state, ~/.config, /usr/share/omarchy, then ~/.config/hypr), a module that cannot be found or is taken outside the files read being raised; the modules that loader takes outside ~/.config/hypr (~/.local/state/default, ~/.local/state/hypr, ~/.config/default, the current theme, the toggles, the layouts), never declarable, a module that shadows another being reported; a module subfolder that is a link followed and reported, a folder more than 8 levels deep reported; an exact copy of Omarchy's library (same relative path, same SHA-256, root-only original) reported as one information line, its lines not counted; beyond the 6 lines shown, the others counted by file; since the third adversarial check (11 Nov. 2026), detection is an allowlist: it stays silent only on a line whose whole form it recognises as safe, everything else being raised "not read" with its reason (form, program, launcher, variable, relative path, unit setting, environment file, length), never counted as healthy: in the shell, only simple commands (no pipe, redirection, substitution, wildcard, block, unknown variable or shell builtin), each program being an absolute path outside a temporary, hidden or /proc folder, or a bare name found in the system or account folders (~/.local/bin, ~/.local/share/omarchy/bin, ~/.cargo/bin, flatpak exports), and each known launcher (env, setsid, nohup, uwsm app, flatpak run, systemctl, hyprctl, xdg-terminal-exec…) read according to its options, an unknown option or launcher being raised; a textual safety net, independent of that reading, also raises at high level any line naming a temporary or hidden folder (/tmp, /dev/shm, /run/user, ~/.x, ./, ../, %t); in systemd, a closed list of keys per section, an unknown key or a value that cannot be checked being raised, Environment= read only in [Service] and [Socket], ".d" drop-ins merged into the unit before its variables are replaced, the units it depends on followed, StandardInputText= and StandardInputData= raised, an EnvironmentFile= with a wildcard, relative, unreadable or too large raised, user.conf read with its spaces; for D-Bus, also $XDG_RUNTIME_DIR/dbus-1/services and the XDG_DATA_DIRS folders the account can change, a "unixexec:" address raised; /var/run, /proc/self/task/<n>/root and /proc/self/cwd brought back to their real path; variables that change what starts (HOME, PATH, LD_*, BASH_ENV…) raised; in Lua, only the launched argument is judged and it must be literal (the others, exec_cmd rules or io.popen mode, are text), a dotted module name raised (Omarchy then loads a/b.lua); a line longer than 8192 characters raised without being read; root-only system files skipped, except inside a user namespace, where root is not trusted; limits of detection: the allowlist accepts any absolute path outside a temporary, hidden or /proc folder, so a program stored in ~/.config/x or ~/bin and started by a plain unit is never reported (~/.local/share/x is, in a unit, not in Hyprland); a variable that leads to a visible folder of the home folder is not raised; an argument of a program that is neither an interpreter nor a known wrapper is read only by the safety net (temporary or hidden folder): a program outside the lists that would start its argument is not known; a bare name is looked up first in the system folders, while the session's real PATH may put ~/.local/bin first (an account program shadowing a system one is not reported); what is stored in the accepted account folders starts without being reported; a D-Bus service's Exec= line is read the way systemd would read it (the bus replaces neither "%" specifiers nor variables: such a word is raised, never silent); a "source" to a hidden folder of the home folder ("~/.dotfiles") is followed and judged without being reported; a moved XDG_STATE_HOME is followed only for Omarchy's modules; SYSTEMD_UNIT_PATH and the other systemd folders set through a variable are refused, without reading the folders they name; Lua is not run: values set in every scope are pooled, without following the program's order, hl.env is not judged, Hyprland's real module path is assumed to include ~/.config/hypr and the search order is the one of Omarchy's bootstrap.lua (reread on 11 Nov. 2026), "./?.lua" (current folder) is not resolved (a module that would only be there is reported as not found), OMARCHY_PATH is judged where it is set (a variable that loads code) and not followed, and the root-owned files of /usr/share/omarchy are not read; a copy of Omarchy's library is recognized only if the original is root-only, which is never trusted inside a user namespace (unshare -r): there, its lines stay raised, and root-only system files (".d" drop-ins of /etc/systemd/system) are judged too, hence lines that do not appear outside it; the drop-ins uwsm writes for the session (/run/user/<uid>/systemd/user: "%I" specifier, EnvironmentFile=-%t/uwsm/env_session.conf) are raised: known noise, to be silenced one day by their exact form; a Lua value set apart ("local terminal = \"kitty\"" then exec_cmd(terminal)) is raised "not read": the intended price of the allowlist; a critical alert to fix yourself cannot be declared, nor can a line shaped like
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
- **The read-only door for AI assistants** (`vanguard mcp`) sends nothing: it only talks to the program that
  started it. But a connected assistant can pass on what it reads to an online model: this is why it returns as
  little as possible (no paths, command lines, accounts, addresses or secrets), and it is up to the person to
  choose the assistant they connect to it.

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
