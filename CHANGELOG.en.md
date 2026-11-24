# Version history

*[Français](CHANGELOG.md)*

What each day brought to Vanguard, most recent first. Since October 19, 2026, Vanguard has, as a rule, a single release
a day, gathering the day's work; October 21 had two, 0.82 in the morning and 0.84 in the evening, which takes over 0.83,
delivered just before it. Since November 7, 2026, more than one release on the same day is allowed; they follow each
other in their day's paragraph. Only the latest version has its download page and keeps its tag in the repository.
Each version's commit carries its number at the end of its title: `git log --oneline -F --grep '(v0.62.0)'`, for
example, finds it, to rebuild it if needed.

## 0.99 (in preparation)

- **Windows: the window no longer holds the terminal's files.** Started by `vanguard 2> errors.txt`, the window kept
  that file open for as long as it lived, even without writing to it: it could not be deleted, nor the same command
  run again. The input and outputs received from the terminal are no longer passed to the window. Any other file the
  program starting Vanguard may have left it to inherit, besides those three, is not touched.
- **Linux: an unreadable name no longer hides a program.** A program can put bytes that are not text in its name, or in
  the name of a file or a mount point. Vanguard then refused the whole system file showing them: the program vanished
  from its lists, a frozen program was reported as finished, or every mount became invisible. Those bytes now read as
  the “�” character, and the rest still counts; a test spots the most common form of a strict
  reading of /proc. A program of another account that erases its command line stays in the list, and a frozen program
  whose file is renamed is still followed.
- **What could not be read is said, never counted as healthy.** The hosts file, a browser profile's extensions, a
  session startup launcher, the list of accounts, the keyboard reading group or the mounts that exist but cannot be read
  now give an impossible or partial check instead of “nothing found”.
- **Remote control: the green tick has to be earned.** After a removal, Vanguard reads again what is left: a startup
  that could not be read, a file to delete by hand or a program still running prevent the tick, and are named. A
  launcher whose name is not text is shown, to delete by hand; the suggested commands always quote the path.
- **Launch guard (Linux).** Each reading of the mounts marks every file system again, instead of trusting an
  already-seen number the kernel can give to another one. Mounts that could not be read give a medium alert in the
  checkup, with the command that shows them.
- **Bounded reads.** Decoy files, browser versions, logs read directly and the hash of a very large program are read
  with a limit and only if they are real files: a pipe or a huge file put in their place no longer freezes the check.
- **Window: green has to be earned.** “Watching” only appears if monitoring and real time are on, and read as such; the
  “no alert” tick also asks for a fully verified log. Otherwise it is said. The checkup score carries its letter, the same as in
  the terminal, and the checkup legend no longer breaks in the middle of a group.
- **Messages that say what to do.** When the window does not open, the message says why in plain words and how to
  continue. What the window does not do yet points to the right command (“vanguard --menu”, “vanguard fix”).
- **The commands quoted exist, and in the right language.** Some English texts gave the French name of a command, and a
  few texts a command that does not exist; a test now reads every quoted command again. `disclose` has its options in
  English (`--tool`, `--program`, `--language`, `--delete`).
- **USB key: the Linux opener knows more terminals.** With no terminal found, a message says so instead of doing
  nothing. The key's instructions mention the window.
- **USB key: a recovered image is no longer forgotten.** The copy of a damaged image is written in the sealed
  reference before the image is removed, and reported until it is replaced; a power cut in between recovers by itself.
  Two images with changed bytes, or two failed copies, mark the key as to be replaced: nothing more is copied to it by
  itself. An unreadable image or an unwritten note is no longer followed by “up to date”. Updating the key keeps these
  notes, and a program that does not recognize the key says “not recognized”, never “nothing to do”.
- **Release: a failure no longer passes for a success.** A failing key, icon or test machine no longer stops the
  version page, and a page that is not online is no longer counted as delivered. An unreachable GitHub is no longer
  taken for “the page does not exist”: nothing is published or deleted when in doubt. The page only goes out if a real
  Windows has tried the program CI built from that same code. A page left as a draft, or a signed update whose page is
  missing, is reported with the command to run.
- **Checks and audit: a green that tried nothing is a failure.** A filter that finds no test, a skipped test
  in the nightly canary checks or a fuzzing run without a single execution make the check fail. Audit exceptions of a
  test dependency no longer cover the published programs; the remaining one carries a review date. A source whose
  address disappears counts as a changed format.

## November 24, 2026: version 0.98.0

- **Only one window.** Running `vanguard` again while its window is open asks that window to come back to the front
  instead of opening another one, on Linux and Windows; on Hyprland, Vanguard says it came back only if Hyprland
  accepted it. Commands (`vanguard bilan --json`…) do not change. The channel is private to your account (Linux: a
  session folder only you can use; Windows: a pipe reserved to your account and session), and nothing is sent on it
  before checking that it really is the Vanguard window speaking (same account, same fingerprint, and on Windows the
  pipe created by your account for itself alone), and the answer must repeat the request's random number. If it is
  not, or if the channel cannot be made safe, a new window opens as before, and Vanguard says so. Two launches at the
  same time open only one window; if their order cannot be guaranteed, it is said. What remains outside the guarantee
  is written in the threat model.
- **The “/” key everywhere.** In any menu, “/” opens “Search Vanguard”: all the tools, settings and guide, opened
  as from the home menu; Esc brings you back to the menu you came from. In a checklist, “/” only filters the list,
  to keep the boxes already checked.
- **Badges on guide commands.** A command's page shows “⚠ changes the system”, “Administrator”, “Window” or
  “Long”, drawn from what the guide already knows about it.
- **Windows guide: administrator commands say so.** Commands that Windows refuses outside an administrator terminal
  (netsh, chkdsk /f, powercfg, sc.exe, pnputil, reagentc…) now say so, and sfc and DISM are marked as long; a test
  stops a new one from being added unmarked.
- **Guide: by topic.** The guide menu gains “By topic” (10): packages, network, disks, security, services,
  hardware, accounts, boot, tools. Each topic shows your system's programs first, then those of the others, each
  with its path (“6.11 ipconfig”), which opens the same page.
- **Guide: Linux commons folded.** A distribution's menu shows its step-by-step guides and programs, then a single
  line “Commands common to Linux” that opens them. Their numbers do not change: “1.20.3” still works, in the menu
  as in vanguard guide, which still shows them all.
- **Catalogue sources checked before each release.** The software Vanguard offers to install is checked at its
  source: Arch package present and not flagged out of date, Flathub app neither end-of-life nor relicensed, winget
  ID still there, Debian and Fedora packages (current stable release, read from Fedora) present. A degraded source,
  or one that could not be checked, stops the release; an incomplete, cut or too slow answer, a missing field, a
  damaged winget index never count as healthy. The check uses its own certificate store, and its output is shown in
  full. Releasing anyway takes `VANGUARD_PUBLIER_SANS_CONTROLE_SOURCES=1` (no other value): the check still runs,
  and its result (code, degradations, unverified sources) is stated in the release notes and kept in the signed
  history. An accepted degradation only holds for the exact value noted, with its date.
  Already fixed thanks to it: Thunderbird comes from its maintained Flathub app (the old one is end-of-life), and the
  qBittorrent and GIMP licenses are the ones their publishers state.
  After an attack campaign, the check is stricter: it judges the list the released program prints itself (not a
  file that could be changed next to it), reads its code and the accepted list from the released commit while
  re-checking the hash of every git object, and the whole run has a time limit (10 min for the sources, 15 min in
  all). The winget index is read without ever running code from the database, a winget ID in another case is
  reported, licences must match both ways, and Ubuntu is said to be not covered. The signed release page is now
  created before the code page: a failure no longer leaves half a release.

## November 22, 2026: version 0.97.0

- **Troubleshoot with Claude, from the key: an option, off by default, and a verified download.** Claude Code,
  Anthropic's assistant, can travel on the key to troubleshoot a relative's computer; `CLAUDE_CLE=oui` in
  `~/.config/vanguard/images-cle.conf` turns it on. Every day (vanguard-claude-cle.timer, turned on by itself at the
  next placement if it is missing), Vanguard takes the version Anthropic announces as "stable" and checks it:
  Anthropic's signature on the checksum list, with the key pinned in Vanguard and recognised by its fingerprint, never
  a key read from the server (a key expired or revoked in this copy is refused), then the size and checksum of each
  binary. A version older than the last verified one is refused, at download as on the key, and notified once per
  announcement. `outils/claude-cle.sh --etat` tells what the cache holds and tells "no longer verifies" (code 1) from
  "verification impossible here" (code 3, a full temporary folder for example), which erases nothing; a failure that
  comes back after a success is notified again. The placement puts Claude Code on the key with its troubleshooting
  instructions: diagnose read-only, explain the cause before fixing, change nothing without consent, never lower
  security, respect the relative's privacy.
- **On the visited computer, the launcher checks before running, then erases.** "Depanner avec Claude.bat" on Windows
  (10 version 1809 or later), `bash -p …/Claude/depanner.sh` on Linux or on SystemRescue booted from the key. The
  launcher first asks the computer owner's consent, then checks the copied program again: on Linux, Anthropic's
  signature on the checksum list and the checksum; on Windows, the Authenticode signature checked by Windows, made by
  "Anthropic, PBC" (name, country, company number and Delaware registry, read field by field from the certificate's
  bytes, each exactly once and with its exact value), and the checksum. Nothing is installed: the program runs from a
  temporary folder of one's own, erased on exit, and the login to the Claude account is never written to the key. The
  account's connectors and MCP servers are not loaded, this computer's browser does not open (the login address is
  opened on the phone), and Claude Code's logs of the session go away with the folder. On exit (/exit, Ctrl+C, closed
  terminal; on Windows, a watchdog if the window is closed with its cross), the launcher logs the account out, within
  a time limit: "Logged out" is only shown if Anthropic confirmed that the login ended, otherwise it asks to end it on
  claude.ai. Whatever could not be erased is named, never counted as erased; a relative's disk mounted in the session
  folder is never erased, and this is said. A session left unfinished (crash, killed terminal) is logged out and then
  erased at the next launch.
- **What the launcher refuses.** A shared temporary folder (/tmp, /var/tmp), or one under a folder another account
  can write to; instructions left for Claude above the work folder (CLAUDE.md, CLAUDE.local.md, AGENTS.md, .mcp.json,
  a .claude folder); settings imposed on Claude Code by the computer (/etc/claude-code, C:\Program Files\ClaudeCode,
  registry policies). Only exception: the .claude folder of the home folder (Claude Code already used on this
  computer), where only instructions cause a refusal; on Windows, only if the path from the home folder to the session
  folder goes through no link or junction. On Windows, these are refused too: a temporary folder outside a local NTFS
  or ReFS drive, a TEMP longer than about 140 characters (Claude Code would cut the name of its log there, and the log
  would stay behind), and any PowerShell command that does not come from Windows: the checks go through the Windows
  modules, taken by their path, and a module placed in the account or a command loaded in memory causes a refusal.
  Before any Claude Code command, the PC's environment that would choose the server, the account, the proxy, the
  certificates, the tracing or code to load is removed, and this computer's Anthropic profile is not read. On Linux,
  the launcher restarts itself with `bash -p`: no bash function or option exported by the PC is followed, nor given to
  Claude Code and its commands, and its own commands (gpg, sha256sum…) come from the system folders, never from the
  PC's PATH. Under WSL, settings imposed by Windows cause a refusal; the registry policy is not read from there: this
  is said, and consent is asked.
- **On the key, each binary is read again on return, and only one outcome is reported.** Each binary put there is
  noted (its checksum) and read again in full at the next placement, as before resuming a stopped deployment. A binary
  changed during the trip is reported and notified before the copy, even if the placement then stops, then replaced by
  the verified copy; with no copy to put back, it is removed, unless it belongs to a signed version that verifies in
  full ("signed and verified, left"). A binary with no placement note is reported "left on the key, NOT checked or
  replaced". Each binary gets a single outcome (replaced, removed, left or kept), never a "replaced" that did not
  happen. A key carrying a signed version newer than the cache, placed from another computer, is kept without raising
  this computer's protection against going back; with the cache missing or empty, a signed version on the key is
  checked against its own signed manifest and reported signed and verified, but not placed from here. These alerts
  exit with code 2, which `outils/deployer.sh` reports as an alert on a binary of Claude/, without claiming "replaced".
  When turned off, only what Vanguard put there is removed from the key, and only if this key's note exists.
- **Lifting a version block: `outils/claude-cle.sh --accepter-version X`, and `--annuler-acceptation`.** The "stable"
  pointer is not signed: a newer authentic version, taken once, then blocks the older ones. Only the owner lifts this
  block. In a terminal only, the command requires a version written plainly (2.0.6, not 2.00.6), present in the cache
  or the last refused announcement; it shows what changes, asks you to type "ACCEPTER X", then for the administrator
  password (polkit window that shows "Vanguard : baisse de protection, Claude Code X"); a refusal changes nothing. The
  log (~/.local/state/vanguard) is written before lowering, otherwise nothing changes; the cache's higher versions are
  moved aside, never deleted, and no longer taken back if the server announces them again (notified once, shown by
  `--etat`); every lowering is notified. `--annuler-acceptation`, in a terminal by typing "ANNULER", with no polkit
  since it raises the protection, puts back, from a trace kept outside the cache, the previous note and the versions
  that still verify; a check that is not possible for now makes the undo "partial" (code 2), the trace is kept and the
  command must be run again; an empty or damaged note is never rewritten. Both commands first go through a gate, at
  the very top of the script, made only of assignments, expansions and `[[ ]]` (no function replaces it) and read in
  the C locale: an exported bash function, BASH_ENV, ENV, SHELLOPTS, BASHOPTS or an unreadable environment cause a
  refusal, nothing changed, no polkit window asked. They then restart in a clean bash (`env -i`, a closed list of
  variables) and check it: any other variable, a bash option, a function, an alias, a trap or a disabled builtin
  cause a refusal as well.
- **Limits stated, also in the key's instructions.** On the visited computer, the launcher proves "signed by
  Anthropic", not "latest version": a key left in a drawer, or reloaded with an older but signed version, passes;
  Vanguard sees it on return. A revocation published later by Anthropic is only known with a Vanguard update. The
  launcher travels with the program: it sees a damaged copy, not a key rewritten in full. On Linux, run without `-p`,
  what the PC exported for tracing or BASH_ENV runs before the first line; without gpg, Anthropic's signature cannot
  be checked: this is said, and consent is asked. On Windows, the checksum list is not checked by a signature (only
  the program's Authenticode signature is), Claude Code trusts the certificates installed in Windows, a C:\.claude
  that appears during the session is not seen, and Set-StrictMode and Import-Module, taken through their .NET type,
  were tried under Windows PowerShell 5.1 on a real Windows 11, on their own and then within the whole launcher (with
  a fake claude.exe). A virus already running under the same account can read the login during the session. The
  `--accepter-version` gate stops a trapped environment, inherited or set by mistake, a timer or a program started
  with nobody at the screen, not a program that already has the account: it can move the cache folders by hand, and
  such a lowering is neither reported nor logged (only those made by the command are); the polkit window is pkexec's
  general request, which a program of the same account can imitate. Windows and Linux 64-bit (x86-64) only. The batch
  went through several adversarial reviews and an attack campaign, and the Windows launcher was tested on a real
  Windows 11, as well as PowerShell on Linux with stand-ins.
- **The error log and the `vanguard signaler` draft go through the common masker**, the same as sent texts: serial
  numbers, passwords after `-p` or `--password`, `net use`, Wi-Fi keys, tokens, MAC and IP addresses (all of them, as
  "<mac>" and "<ip>"), paths ("<chemin .ext>") and web addresses ("<url>"). The text shown is the one written and then
  sent; a fake marker written in a message ("<ip>" inside a token) is disarmed. The command written to the log is
  reduced argument by argument: only subcommands, known options and words from the help remain; a file becomes
  "<chemin .pdf>", a link "<url>", a free word "<valeur>"; the log, the gate and the draft use the same marker. A bare file name ("CV-Bob-Exemple.pdf", "Zoé.Tremblay.docm") is masked from a closed list of extensions
  (documents, archives, sounds, programs…); the extension shown is always a known one, never the rest of a name
  ("jean.tremblay") nor that of an account folder ("first.last" under /home); a personal folder is replaced by "~" before
  masking, even with a space; a path under a personal folder (home, "~", "Users\x", "/run/media/x", "Documents/…",
  a "file://" address in a home) is removed up to the end of the line, or up to the quote that closes it; elsewhere, a
  name with spaces is taken up to the closing quote or parenthesis, or up to ":"; a path cut on the left by "…" is
  removed up to the end of the line, and a cut excerpt starts with "…" and then at the start of a word; "//host/…" is
  a web address only right after `"` `'` `=` `(`, elsewhere it is a network share; a web address is removed whole,
  whatever its scheme, when it starts with "www." or "//", or with a single slash ("https:/…"), a query glued to a
  path leaving with it up to the end of the line, even when glued
  to an option ("--url=https://…"); a secret is masked before and after
  anonymization, which could hide its start ("-u alice:…"); a file or program field of the draft is replaced whole; a
  value that is too long is cut at a space before masking; only the kernel version is kept, without its suffix.
  Entries written before 0.97 are no longer sent to GitHub on their own: they wait for the author's approval
  (`--accord`), and this is said. Limits: diagnostics lose the MAC vendor prefix, paths and IPs; error tickets already
  open may come back under a new signature; a secret made only of common words ("-p 'red house'") or with no keyword
  before it may remain; in free text, an unquoted file name with spaces outside a personal folder may keep its end, and a web address with no scheme, "www." or "//" ("example.com/page") remains; after a personal path, the rest of the line is lost (up to the line's last closing quote, if one was opened before it); not read as personal, so a name with spaces may keep its end there: a personal folder written through another variable than "~", "$HOME" and "%USERPROFILE%" ("${HOME}/…", "$env:USERPROFILE\…", "%HOMEPATH%\…"), an address with another scheme than "file://" ("smb://", "sftp://": it stops at the first space) and an account folder under another head than the known ones ("D:\Profils\…", "/srv/comptes/…", except this computer's home); a path glued behind "<" or "*" ("sort </home/…") is not read, a relative path whose first element is the account ("alice\\Mes documents\\…" between quotes) keeps that account, what follows a written break ("\n", "\r", "\t", "\u000a"…) may be read as a path ("src\nettoyer\mod.rs" becomes "src\n<chemin>"), and a path behind "account@host:" ("scp bob@nas:/home/…") is cut at the first space; when in doubt, more is masked: every "\/" becomes "/" again, and a sed expression, a regex or a web route written that way ("sed 's/\/usr/…'", "^\/api\/v1") loses its "\" or is masked, "//" counts as a slash ("total.size//chunk.size", a "//" comment), "10$US/mois" or "s/$PREFIX/usr/" are read as paths, a slash behind a character written as a code ("\x41/…", "\0/…") or behind a glued option ("-I/…") opens a path, an element shaped "first.last" ("projets/zoe.martin/notes") is enough to mask a relative path, the last element of a relative path may run to the next word with an extension ("Documents/rapport et la suite.pdf"), a line carrying a terminal sequence (colour, OSC 8 link, title), even a written one ("\x1b[0m"), is removed whole ("[ligne retirée : séquence de terminal]"), a web address whose query has a raw space ("?nom=Zoé Martin") keeps the end of the name, a cut excerpt "… (2/3) terminé" loses its end, and in compact JSON the next value holding "=" or "&" may go with an address, and an address between escaped quotes ("\"https://…\"") may take the next field along or leave the end of a path glued behind it; a share with spaces in a folder, behind a never-closed quote or "What=" ("mount -t cifs "//nas/Photos de Zoé Martin", "What=//nas/Photos de …"), and a "file://" address to a host ("file://nas/partage/…") keep the end of the name; a home followed by a space that starts another account name (the home of the account "Zoé" before the folder of the account "Zoé Dupont") is replaced, and the end of the name ("Dupont") stays; the detail is cut at 3000 bytes (a draft value at 4000 characters) before masking, whose cost
  grows quickly with length; a text the masker cannot stabilise is replaced whole by "[texte retiré : masquage
  instable]".
- **The system journal is read in full, like `journalctl`.** After a reboot, the journal can give a new entry the
  number of an older one. Vanguard took it for a copy and skipped it. An entry is now recognized by its whole header
  (number, time, boot, hash), and the files are merged in writing order, not by time alone, which can go backward when
  the clock is set at boot.
- **New read-only door for AI assistants (`vanguard mcp`), on Linux only.** An assistant you connect can read Vanguard's
  state, events and findings, and cannot change anything. It uses only the program's standard input and output, with no
  port and no network, refuses to run as administrator and marks everything it returns as untrusted. A text that comes
  from the computer (a finding's message, an alert's title, a program's name) only leaves it made of the words Vanguard
  itself writes in its messages, in French and English; any other word, digit or sign becomes "…", which holds back
  paths, addresses and any value made of digits or signs. These words are read from the code at each build, through
  its syntax tree, following the modules as the compiler does, without the tests; a form this reading cannot judge
  stops the build. Each word must also be found as is in the published programs, or nothing is published: a text the
  compiler did not keep (a trick the reading would have missed) shows there. After a word that announces a secret (password, key, code, PIN, NIP, token, secret, seed, recovery
  phrase, identifier, login…), the whole rest of the text is held back, and so is the command excerpt of each program in
  a watcher alert; the price: a useful sentence that follows one of these words is lost. Limits, stated in the threat
  model: a name made of Vanguard's words ("admin", "maison") comes out, with its case; a value written before the
  announcement ("maison rouge is the password") is not held back; an attacker who writes on the computer can compose a
  sentence with these words; fixed-form fields (rule, version, date, numbers) come out without being reread. A session
  served is noted in the journal, without ever filling it; a program that sends it abnormal messages is cut off, and an
  alert says so. It refuses to start under a file size limit (`ulimit -f`), which could cut its note in the middle; a
  note cut anyway is undone, and the journal stays readable. After 15 minutes of silence, it closes; the assistant
  starts it again. On Windows, the command refuses to start until it has been tried on a real Windows.
- **The address masker, shared by the error journal and the report draft, holds back more.** When in doubt, it
  masks. An IPv4 address carried inside an IPv6 one ("::ffff:…"); an IPv4 address followed by a port (".443",
  ".123456") or by stuck letters (".443x", "23abc"), whatever word comes before it ("packet", "rule", "version", "-v");
  a full IPv6 address followed by a full stop, a port ("…:ef01:443") or an IPv4 address ("…:abcd:198.51.100.23"); an
  IPv6 address followed by a colon ("fd12:…:6: Connection refused", "fe80::1%eth0: …", "%eth0:546"), preceded by a
  stuck label ("addr:fd12::7") or by a full stop ("fd12::7.fd12::8", "...10.0.0.5"); a zone written with hyphens,
  underscores or a full stop followed by a digit ("%br-lan", "%eth0.100"); ideographic full stops ("。"): all of these
  are now masked whole. A word stuck after the full stop ("5::6.The rest") keeps its place. IPv6 addresses are read by
  a strict grammar, without looking at what surrounds them: any run of hexadecimal digits, colons and full stops with
  at least two colons and one digit is masked, whatever label is stuck before it ("remote_addr:", "X-Forwarded-For:",
  "nas.lan:") or word stuck after it; any word stuck after it is masked with it, up to the space, because a last
  group made of letters a-f cannot be told from the start of a word (accepted price: "…::7:Connection refused" gives
  "<ip> refused"). The only exception, to keep the timeline: a time of exact shape (HH:MM or HH:MM:SS, two
  digits per group, hours 00 to 23, minutes 00 to 59, seconds 00 to 60, maybe followed by "." and 1 to 9 digits),
  bounded on both sides by a character that is neither hexadecimal, nor ":", nor "."; "12:34:56" and
  "08:15:02.123456" stay readable, but not "12:34:56:78", "24:00:00", "12:34:5a" or "12:34::1". Accepted price: a
  time followed by a sentence period ("12:34:56."), a ratio ("1:2:3"), a colon version ("7.6.7:1:80") or a PCI device
  address ("0000:00:02.0") are masked too; in a measured desktop journal, about one line in sixteen keeps a mask this
  way (instead of two in three when every time was masked). A label ending with a hexadecimal letter loses it ("node:fd12::7" gives "nod<ip>"). Only numbers that cannot be
  an address with its port stay readable: a version with a known suffix ("1.2.3.4rc1", "4.19.0.0beta", "alpha",
  "esr"); after "version", "build", "section", "control", "driver", "release" and their French forms, a fifth number of
  one or two digits behind a first number under 100 ("version 1.2.3.4.5"); a run of six numbers or more
  ("1.2.3.4.5.6"). Known limits: "version 10.0.0.5.22" therefore stays in clear (a private address and a two-digit
  port after one of these words), as does an address followed by two numbers or more (".443.80"), taken for a version;
  an address stuck behind letters or a digit ("host198.51.100.23", "0198.51.100.23") stays in clear; an IPv6 address
  written without any digit ("fd::ab") looks too much like a word to be recognized; a full stop followed by letters
  ends the zone ("%eth0.vlan5" leaves ".vlan5"): no address byte comes out of it; a four-number version is
  taken for an address even when named ("version 6.1.0.2" keeps its name, not its numbers). Through the assistants'
  door none of these forms comes out: they are not Vanguard's words.

- **Missing window: the menu says so and offers to add it.** When nothing else keeps the menu, it says in one line
  that the window is missing and points to "Update Vanguard", which adds it after showing it, checked against the
  built-in fingerprint. Over SSH, Remote Desktop, as administrator or without a screen, nothing is offered; offline,
  from the key or in a folder that cannot be written, the reason is given.
- **Window: a section as list and page, in one click.** In a wide window, a section shows the list of its commands
  (title and state) on the left and the chosen command's page on the right; a click in the list changes the page without
  adding anything to Back, ↑ and ↓ change command, Enter or F5 rerun it, never while typing. A narrow window keeps its
  cards. A quick read (3 min at most, that changes nothing), never read or read more than an hour ago, reruns by itself
  once when its page opens. A long read and the network scans (devices, network audit, hidden cameras, NAT) never start
  by themselves: they wait for the "Run" button.
- **Window: it only runs the `vanguard` that opened it.** It ran the same path again for hours without looking at its
  content again: a `vanguard` replaced by this account made it show its answers and received its actions. `vanguard` now
  gives it the SHA-256 fingerprint of its own program; for each command, the window reads the file again, copies it into
  a sealed in-memory file, compares its fingerprint and runs only that copy, never the path. Replaced since the window
  opened (by an update too): nothing is run, the reason is given, and reopening the window is enough; after a successful
  update, it says so at once. On Linux, the `vanguard` started from that copy receives, in its environment only, the
  checked path (`VANGUARD_ORIGINE`): it only trusts it in that strictly recognised image and towards a file with its
  exact bytes, and its update, its key and its task keep the right file; with that path missing or refused, it stops
  and says to reopen the window, with no fallback. It recognises itself by its file or its bytes, never by the name
  `/memfd:vanguard` nor by a path alone: another program started from a memfd with that name or rebuilt at its path
  is still shown and treatable, what a program had started before becoming Vanguard is still judged (a Vanguard that
  still has a child at the exec, or already running with a child when the watcher starts, has everything it starts
  judged: that child can give it siblings or its orphans; a root that has gone and whose number is reused after lost
  events no longer passes the mark), a flood of same-size copies no longer makes it forget a Vanguard already
  recognised, and two `vanguard` from the window no longer report each other. pkexec runs the checked path there, only
  if it is owned by root and protected; otherwise it is not offered. On Windows, the file is held and its fingerprint
  compared, but the path is still what is started (limits stated in the threat model). Opened alone, without
  `vanguard`, the window trusts its neighbour on first use.
- **The update also places the missing window.** When `vanguard` is already at the version published on GitHub
  but its window is missing next to it, is not its own, or would be refused at launch (a link, wrong permissions),
  the update offers to place it. Only if the program here is exactly the published one, and always checked against
  the fingerprint engraved in `vanguard`; shown in the preview, placed only after your consent, and put back as
  before if reading it back fails (with its permissions, or this is said). The state of each window shown is part
  of the consent: if it changes between the preview and the click, nothing is done.
- **A window that cannot be read no longer blocks updating the program.** If the window here cannot be read
  (permissions, a folder with its name), if the copy is a link, or if the window on the key cannot be checked, the
  program is updated alone: its window is not touched, this is shown in the preview as a separate step, and said
  again in the result as "not verified". A folder that the launch refuses is said, with no repair offered (placing
  it again would fix nothing). Temporary files get a random name, never a guessable one.
- **Window Console: ten more readings, and a typed value.** agent, camera-micro, logiciels, nettoyer, desinstaller,
  sites-dangereux, parametres, blocage, verifier-sauvegarde and ordinateurs can be typed in the Console, always run
  read-only (`--json`); every word that acts (on, off, annuler, --appliquer…) is refused there. These commands, with
  `--liste` when they have one, give a JSON alone without changing anything; `--json` is refused (code 2) as soon as
  it goes with a change, including at the tail of a `parametres` setting, where it was swallowed and let the
  language change. Eight readings take a value (`vanguard console <command> -- <value>`: chercher, lien, evenements
  --incident, dernieres-failles, journaux-windows, verifier-fichier, courriel-suspect, verifier-moi): the value is
  bounded and judged twice, by the window then by `vanguard`, with no leading dash, control character or direction
  override; a path is only allowed after resolving its real path, for a regular file under the account's Downloads,
  Desktop or Documents, or on a removable drive; the rest is offline and the value is masked in the log. A given file
  is opened only once, and what is checked is exactly what is read (no more gap between the two).
- **Console: linked or declared folders, judged more accurately.** On Linux, an allowed place that is a symbolic
  link (~/Documents to ~/Nextcloud/Documents) is followed once, when the places are built, and only if its target is
  a visible folder under the home folder: a link changed afterwards is not followed, a link leading out of the home
  folder is never followed, not even to check its target, and a link to a hidden folder or to the home folder is
  refused with that reason. A folder declared in ~/.config/user-dirs.dirs only counts if its name, regardless of
  case, is one of those xdg-user-dirs gives to Downloads, Desktop or Documents (a closed list, taken from
  xdg-user-dirs 0.20): `XDG_DESKTOP_DIR="$HOME/Projects"` no longer makes a project an allowed place. A home folder at
  the root ("/") yields no allowed place, and a path on a removable drive is refused with its cause when the account
  is not in /etc/passwd. On Windows, these three folders come from Windows itself (SHGetKnownFolderPath); Desktop and
  Documents backed up to OneDrive are accepted, but the whole of OneDrive (even moved under another name), Pictures,
  Videos, Music and the other known folders are never allowed; each folder on the way is opened under the previous
  one and held so that nobody renames it while it is read (checked under Wine, not yet on a real Windows).
- **Console on Windows: three more cases on the VM test bench.** `outils/test-windows/test.ps1` creates, on the
  VM's real Windows, an "online-only" OneDrive file (a placeholder from the cloud files API, without a OneDrive
  account) and a file marked offline: the Console must refuse them, without downloading anything. For a few seconds it
  also denies the session's account the listing of the profiles folder, then moves Documents into OneDrive the way
  OneDrive backup does: the Console must still read Documents, and refuse OneDrive itself. Each change is put back
  exactly and read again; otherwise the bench says so, with the command that puts it back.
- **Linux: an update that cannot be checked says why.** Firmware: an error returned by fwupd is named, otherwise
  fwupd is said to be unreachable, with its cause; the often wrong "fwupdmgr refresh" remedy is no longer given.
  Flatpak: "offline?" becomes the real reason (no answer within 40 s, return code and first line of flatpak's error,
  for example an unreachable remote). Never "up to date" on an error, as before.
- **Linux: a `journalctl` witness cut in the middle of an accented letter no longer looks empty.** Before, every
  entry of the journal files seemed hidden by journalctl (a false alarm). An unreadable witness is said "not
  verified", never counted as healthy.
- **A Vanguard stopped at the wrong moment no longer makes others wait two minutes.** To stay compatible with versions
  before 0.87, Vanguard also creates their old lock file, created empty and then marked. Stopped in between, it left
  an empty file, which everyone took for a 0.86 still open: the journal, the settings notes and the device list stayed
  blocked for two minutes. The file is now born already marked, in one step (a hard link; on a FAT key, as before). A
  test watches it 3,000 times and must never see it without its mark.
- **Vanguard's principle, rewritten: Vanguard acts, you stay in control.** What protects, maintains or improves the
  computer will be done on its own, with the previous state recorded, logged, exactly undoable and reported
  afterwards; only lowering a protection waits for your choice, and any action that cuts a connection, deletes or
  moves your data, turns something off or cannot be undone exactly is still asked. This is the direction: nothing
  changes in the program yet, every fix still waits for your consent. The threat model gains an “Autonomous mode”
  section that says what is planned and its brakes (a closed list of actions, a ceiling and a circuit breaker, a
  sealed switch, nothing automatic on the network or remote control).
- **Texts sent to improve Vanguard mask more forms.** The common cleaner now catches: an announced serial number, in
  its usual spellings ("Serial Number:", "serial-number", lsusb's "iSerial", "S/N", "N° de série", "Seriennummer",
  "DiskSerialNumber"…), even written in several pieces; a passphrase or a secret announced by `:` or `=`, in French,
  English or German ("password:", "pass-phrase:", "wifi_psk=", "PGPASSWORD=", "mot de passe :", "Passwort:", the Wi-Fi
  key shown by `netsh wlan show profile key=clear`), up to the end of its sentence, even with spaces; a password given
  to its option, stuck or in quotes, spaces included (`-pXXX`, `-p 'XXX YYY'`, `-p=XXX`, `-uNAME:XXX`, a Python list)
  or to `net use`, even with a quoted path; a MAC address with dashes or underscores stuck to a word, with dots
  (`abcd.ef12.3456`) or hidden in an interface name (`enx…`, `wlx…`); an IPv6 written as a reverse name (`….ip6.arpa`)
  or with dashes; an IPv4 stuck to a word (`host198.51.100.23`) or with dashes in a host name (`ip-10-1-2-3`,
  `ec2-…`); a relative path to a file or through a personal folder (`Documents/taxes.pdf`, `../Marie/notes`,
  `project/.ssh/…`). The relay, which refuses a text where a secret remains, recognizes the same secret announcements;
  the other forms are masked by Vanguard before sending. Versions, times, dates and the files of Vanguard's repository
  (`src/…/mod.rs`, `outils/verifier.sh`) stay readable. Limits: a relative path without an extension, a dot or a
  personal folder (`projects/Marie`) stays readable, as do four dash-separated numbers with no host name around them;
  a passphrase takes the rest of its sentence with it.
- **The nightly watch judges each crate by its own exceptions.** It ran `cargo audit` on four `Cargo.lock` files with
  Vanguard's list of accepted advisories only, and from the tree, where `.cargo/audit.toml` silenced those advisories
  for every crate. It now reads each `Cargo.lock` of the repository, the window and the proofs included, from an empty
  folder, and an advisory is accepted only by the `deny.toml` of its own crate (`outils/failles-programmes.sh
  --exceptions-depot`, the same mapping as the full check). A fix proposed by the nightly AI can no longer touch any
  `deny.toml` or any `.cargo/` folder, wherever they are: the window's was missing. It is also refused if it adds a
  symbolic link, or moves a protected file out of its path (a rename used to hide the original path). An unreadable
  `deny.toml` no longer stops the audit of the other crates: only its own advisories all count.
- **Dependency security.** wasmtime 48.0.9 (advisories RUSTSEC-2026-0566 to RUSTSEC-2026-0573: unbounded memory
  growth in wasi, aborts on missing features, stale garbage-collector pointer, panics), brought in by YARA-X;
  url 2.5.9 (advisory RUSTSEC-2026-0592: a nested `blob:` URL overflowed the stack when computing its origin),
  brought in by reqwest.
- **Rust 1.100.0.** The programs are now built with the latest Rust release, which brings its fixes; its new
  clippy remarks are fixed in the code, without silencing any of them.

## November 15, 2026: version 0.96.0

Version 0.95 was not published: all its work is in this version.

- **The Vanguard window ships, safely.** On a graphical desktop, `vanguard` now opens the window (`vanguard-fenetre`),
  otherwise the terminal menu, as before; `vanguard --menu` forces it. The window is only started if its SHA-256
  fingerprint is the one engraved in `vanguard` at build time: since `vanguard` is signed, that fingerprint is too.
  The verified bytes are started, not the path: on Linux, a sealed in-memory copy (memfd); on Windows, the file held
  open without write sharing during the launch, and its folders too (neither renamed nor replaced meanwhile). A fake
  window placed next to it is never started: the menu, with the reason given (a launch refused by the system also says
  why). A program built without a fingerprint (`cargo build`, the tests) starts no window. `vanguard -h` says "No
  argument: the window on a graphical desktop, otherwise the menu".
- **Nothing from the account gets into the window.** It only receives a closed list of environment variables (display,
  language, XDG folders, proxies) and a clean PATH; if a library injected into the session's programs is reported
  (`LD_PRELOAD`…), the window is not started: the menu, which does not run it. `VANGUARD_ORIGINE` is only trusted in
  the temporary copy `vanguard` makes of itself on a key; elsewhere the variable is ignored. The window is given the
  program to start (`--vanguard <path>`) and keeps its own checks on that path, even when it is not UTF-8.
- **Fix, restore as before and update from the window.** "See the fix" shows Vanguard's whole preview;
  "Apply this fix" becomes active 2 seconds later, only for an account fix that can be undone exactly and whose text
  is fully visible (otherwise the reason is given). The "What Vanguard changed" screen shows each change with its
  state, and "Restore as before" on each fix that can be put back, through the same preview and the same delay. One
  action at a time, which is not interrupted; the window only sends back the preview's token and consent, and Vanguard
  judges everything again on its side. The "Update Vanguard" card first shows where the update comes from, the target
  version, its fingerprint, its size and each program replaced; nothing is installed before "Install this update". In
  each section, a command's whole card is a button (mouse, or Tab then Enter) that opens its page; in the audit,
  "What is fine" wraps instead of overflowing.
- **The window travels with the program.** The release page, the update repository and the key carry the Linux and
  Windows window, judged like the program (fingerprint, known vulnerabilities, privacy, SHA256SUMS). An update from
  GitHub (terminal or window) downloads the new version's window after consent and checks it against the fingerprint
  engraved in the new program, all or nothing; from the key, the key's window follows if it is its own, and if it
  cannot be placed, the program is placed alone and this is said. The preview shows it as one more line. The placed
  window is read back (the same file, the bytes received, otherwise a failure); a window that appeared, disappeared or
  changed since the preview is never replaced: nothing is placed for that program, and the reason is given.
  Uninstalling also removes the window.
- **Coming from 0.94, the window is placed once by hand.** The 0.94 update does not know the window: it places the
  program alone, which opens the terminal menu; a later update does not add it (it only replaces a window already
  there). To get it, take `vanguard-fenetre-linux-x86_64` or `vanguard-fenetre-windows-x86_64.exe` from the release
  page and place it next to the program (the VANGUARD key already carries it).
- **Limits of the window** (stated in the [threat model](MODELE-DE-MENACE.en.md)). Windows: verified under Wine only,
  with no suspended launch or process image check; folders behind a junction and a redefined drive letter (`subst`)
  are not held. A kernel that refuses executing a memfd (`vm.memfd_noexec=2`, SELinux, AppArmor): the menu, no
  fallback. The window does not yet re-check the content of the `vanguard` it starts: an account replacing that file
  is not stopped by it.
- **Update Vanguard after seeing what gets installed.** `vanguard self-update --voir` says, without installing
  anything, where the update comes from (the VANGUARD key, or GitHub, signed by the author), the target version, its
  SHA-256 fingerprint, its size and each program it would replace, with its version today. `--appliquer --accord
  <consent>` installs only what was shown, 2 s to 10 minutes after the preview, once: another version, another key or
  a changed copy in between is refused. The temporary copy is held open from start to finish: read back, tried and,
  once in place, checked again (the same file, the same bytes; on Windows, the bytes only) before saying "done". The
  usual checks stay; "up to date" is only said when verified, otherwise "not verified". Commands left out of the online
  help.
- **Apply an audit fix, then put it back as before (Linux).** `vanguard correction --show <token>` (the token comes
  from `audit --json`) shows the fix and its consent; `--apply <token> --agreement <consent>` does it, one at a time,
  2 s to 10 minutes after the preview, once. Only account fixes that undo exactly are allowed: the permissions of a
  file in the home folder. `vanguard changes --show <token>` shows what "put back as before" would do, and `--undo
  <token> --agreement <consent>` does it. On Windows, these actions are not offered yet; in read-only mode, they are
  refused.
- **What protects these actions.** Everything is read and judged again when acting: a state changed since the
  preview, or a replaced file (recognized by its kind and inode number), is refused without changing anything.
  Several files: all or nothing. The "What Vanguard changed" trace is written before touching a file: Vanguard
  stopped dead leaves an "interrupted" line, which is put back like any other; nothing in it proves Vanguard set the
  value, and the gap with what is there is shown before putting back. A note written by a version before 0.95, without
  the file's identity, is not put back on its own: the value to put back by hand is given. Account file permissions are
  read, set and put back without a shell or a followed link (putting back used `chmod`, which follows links). The event
  log keeps no file name and no command; each sealed file is written in two steps, like the settings seal.
- **A more honest update.** A copy swapped by another program during the update is no longer left in place: the old copy
  is put back (rewritten from what Vanguard holds of it if its second name was deleted in the meantime), or Vanguard
  says exactly what is in place ("do not run it"). The old copy is recognised by what Vanguard holds open, no longer by
  a file number the system can give to another file, and it is said to be "put back" or to "stay in place" only if its
  bytes are still the ones Vanguard read when setting it aside (BLAKE3 fingerprint); a copy that is a symbolic link is
  recognised by what it points to and by the file at its end, held open the same way. Rewritten (or, at the end of a
  link, replaced) in the meantime by another program, it is reported as changed, not to be run: Vanguard checks it again
  just before putting it in its place, and does not put it there if it sees it changed (left under its set-aside name,
  it is to be moved before redoing the update); a change made in the instant between that check and the move is only
  seen afterwards, and reported the same way. If it cannot be set aside before the replacement (for example, it cannot
  be read, exceeds 512 MiB or is a link to nothing, or its set-aside name, `vanguard.precedent`, is taken by a folder or
  by another file), the update of that copy is refused before anything is replaced, and the path at fault is given, with
  what to do; what is under that name is never deleted, except a second name of the copy in place. If putting it back
  fails, the old copy is kept under a name the message gives, to be moved somewhere safe, only if it is still unchanged
  there (for a link, the file at its end too); otherwise, or if even that fails, the message says it is lost. A new copy
  held open for writing ("Text file busy") is reported as such; a provisional name already taken (a folder) is reported
  with the path to remove. Every refusal of the installation says "nothing is replaced", also when the copy for this
  computer is first set up. Limits: a change made after this last check is not seen; on a file system without hard links
  (FAT, exFAT), or for a copy owned by another account when the system forbids them (fs.protected_hardlinks), the old
  copy cannot be set aside: the update of that copy is refused ("Operation not permitted").
- **Undo without touching another file.** "What Vanguard changed" no longer puts wider permissions back on a file
  that is no longer the one Vanguard fixed (replaced, other inode): the restore is refused, with its reason, and the
  line shows today's permissions and those that would be restored.
- **Clearer refusals.** "It changed since the preview" also gives the possible cause: a preview made in another
  language (VANGUARD_LANG, system language).
- **A help writes nothing.** `vanguard --help`, `-h`, `help` and a command's help no longer create any file (seals)
  in the data folder.
- **Startup programs: the consent is now required.** `vanguard startup --remove` and `--put-back` now require
  `--agreement`, the one `startup --json` gives for that action: without it, nothing is removed or put back (code 2),
  and a program whose name, command or scope changed since the list is refused. The consent binds the whole name and
  command, not the cut text on screen. "Put back" no longer overwrites an entry rewritten by hand since its removal:
  it is refused, the reason is given and the content is kept.
- **Startup programs: where Vanguard does not write, it says so.** An autostart folder that the group or everyone can
  change, or that carries a special bit, is no longer written: its entries stay shown, without a button, and the
  folder is named once with its permissions and the exact `chmod` command, if fixing it is your choice. The folders
  Vanguard creates are created 0700 whatever the umask: the first removal also works on Ubuntu and Fedora, where it
  was refused. The report, the event log and `--json` write the home folder as "~".
- **Startup programs: what was not read is said.** /etc/xdg/autostart is always read, even when XDG_CONFIG_DIRS does
  not name it. An account service file is read up to 64 KiB, without following a link; otherwise it is reported "not
  read". The command shown is the one systemd starts, with its ".service.d" drop-ins applied. "Why is it slow?" names
  the folders it could not read instead of "no program found", and `startup --json` only counts a verification when
  a source was actually read.
- **Desktop entries and units read the way launchers read them (Linux).** A startup entry (.desktop) is read the way
  systemd reads it and the way GLib (gio, gnome-session) starts it: lone carriage returns, NUL bytes, BOM, escapes,
  "%f" stuck inside a word, "%c". A form that two launchers would read differently is raised, naming the form. An
  ExecStart= written with "\xNN" or octal escapes is read as bytes, like systemd; what cannot be decoded safely is
  reported as not verified.
- **A line that writes into a startup place is raised.** A line started at boot that names ~/.config/autostart,
  ~/.config/systemd, ~/.config/hypr, ~/.bashrc or a folder holding one (~/.config, ~/.local) can place a launch there
  each time it runs: it is raised, also through a link, a relative path read from its real working folder,
  /proc/self/cwd, a hard link or another desktop's place (KDE, Sway, i3…). A path that cannot be followed with
  certainty is reported as not verified. Limit: a copy onto the whole home folder is not counted.
- **The automatic backup, harder to hijack (Linux).** It now starts the system's rsync and findmnt through "env -i";
  a backup set up before 0.95 is reported, with what to do (undo it, then set it up again). It is kept quiet in the
  check only if rsync, findmnt and env can be changed by root alone. It is raised if its disk is a FUSE mount, an image
  owned by the account, or missing from /sys (not verified), and when declaring it normal is refused, the message says
  what changes it and how to remove that.
- **Variables and settings that change what a program starts.** The check reads the session manager's variable files
  (environment.d, user.conf and user.conf.d, uwsm): HOME, LD_*, RSYNC_* or XDG_RUNTIME_DIR set there raise the backup,
  and a moved unit folder is read again. ~/.pam_environment is read by the backup only (the same variables raise it),
  not judged by the check: pam_env reads it only with "user_readenv=1", which is not its default setting.
  environment.d and user.conf are read as systemd reads them: a lone carriage return or a NUL byte splits a line, a
  "\" line continuation also joins with CRLF, and only space, tab
  and line ends may come before a comment ("#" or ";"). In a shell profile and in uwsm files, only "#" starts a comment:
  a line that begins with "//", "--" or ";" is no longer one. These files are also read where their readers look outside
  ~/.config (the session's XDG_CONFIG_HOME or one set for the manager, and for uwsm every XDG_CONFIG_HOME,
  XDG_CONFIG_DIRS and XDG_DATA_DIRS folder, from the session or set for the manager, that the account can change, even
  outside the home folder; a relative folder is read from the home folder, as uwsm reads it), by the check and by the
  backup alike. An uwsm file is skipped only if only root can change every entry crossed to reach it, links included; an
  uwsm folder, entry or file that cannot be read is reported, not checked, by the check as by the backup. An uwsm folder
  placed under a folder the check already reads for something else (~/.config/systemd, for example) is judged too. uwsm
  plugins ("uwsm/plugins/*.sh" under ~/.local/share, /usr/local/share, /usr/share and every XDG_DATA_HOME and
  XDG_DATA_DIRS of the session or set for the manager) are judged like its files, by the check and by the backup alike;
  a plugin folder that cannot be read is reported as such, not checked, and raises the backup; every ".sh" counts, even
  those uwsm will not load for your desktop. A wildcard ("*", "?", "[") in the session's XDG_CONFIG_HOME,
  XDG_CONFIG_DIRS or XDG_DATA_DIRS is not expanded: the check reports it, not checked, it cannot be declared normal, and
  it raises the backup; the same goes for a line break, which uwsm may remove at the end of a value. The session's
  XDG_DATA_HOME is read as is, as uwsm reads it. A piece set for the manager that starts or ends with a blank does not
  resolve (reported, not checked), nor does an XDG_CONFIG_HOME or XDG_DATA_HOME set there that contains ":" (systemd
  takes it whole, uwsm may split it), except the whole form "${XDG_DATA_HOME:-/folder}" in a root-only environment.d
  file, read as systemd reads it (in user.conf, /etc/environment or pam_env.conf, which do not expand it, it stays
  unresolved, reported); "~/x" or "$HOME/x" set there is read both ways: replaced by the home folder, and as written,
  from the home folder. The files uwsm reads count: "env" and "env-<desktop>" in the uwsm folder, every file in its
  "env.d" and "env-<desktop>.d" except those uwsm skips ("*.bak", "*~", "*.disabled", "*.example", "*.sample",
  "*.broken"), and "~/.config/uwsm/default", which Omarchy's uwsm file includes. Hidden files of a ".d" (".cache"),
  which uwsm's pattern only sees when bash's "dotglob" option is set (a BASHOPTS inherited from the session), are judged
  to raise only: a preload, a hidden or temporary folder, a relative PATH, or what changes what uwsm reads next (uwsm
  variable, HOME, special shell variable such as BASHOPTS or IFS, desktop name, inclusion, "eval") is reported, high,
  with that condition, and raises the backup; a healthy hidden file, or one bash itself refuses (a NUL byte in its first
  line, like vim's ".10-x.swp"), stays silent; a hidden file Vanguard cannot read safely (a NUL byte further on, which
  bash removes, non-UTF-8 text, over 1 MiB, unreadable, a line that is not simple) is reported, not checked, with the
  same condition, raises the backup, and what it sets that is suspect is still raised; "default-id", notes or a working
  copy ("env.bak", ".env.swp") at the top of the folder are no longer judged. A desktop name outside letters, digits,
  "_", "." and "-", in the session's XDG_CURRENT_DESKTOP or in the DesktopNames of an uwsm session (wayland-sessions),
  or a DesktopNames line with a control or non-ASCII byte, is reported, not checked (uwsm derives from it an "env-…"
  file elsewhere, which Vanguard does not read), cannot be declared normal and raises the backup. An uwsm variables file
  (in every folder it reads) or a plugin the account can change, and each file they include, at every level and whoever
  owns it, is judged only if it has nothing but simple lines: blank line, whole comment, "NAME=value" or "export
  NAME=value", "export NAME", and ". path" or "source path" with an absolute or "~/…" path spelled out, up to 64
  included files. The value has no quote, "$", backquote, backslash, parenthesis, ";", "&", "|", "<", ">", "#", "~",
  brace, wildcard ("*", "?", "[", "]") or blank; or is wholly within single quotes; or is wholly within double quotes,
  without quote, backquote, backslash or control byte, "$" being used there only for "$PATH" or "${PATH}" forming a
  whole piece between ":" (or the whole value), and for "$HOME" or "${HOME}" at the very start of a piece, followed by
  "/" or the end of the piece; anywhere else ("/$HOME/.x", "$PATH/.x", "$HOMEx"), the line is not simple. The value is
  computed before it is judged: "$HOME" becomes the home folder in its normal form, "$PATH" the PATH set earlier in the
  same file (otherwise the system one), then the whole value, blanks and ";" within double or single quotes included, is
  judged as if spelled out (`export PATH="$HOME/.local/bin:$PATH"` as "/home/alice/.local/bin:…"). Vanguard does not
  read shell code: a file with any other line (eval, function, condition, "~+", "{a,b}", end-of-line comment, NUL byte,
  non-UTF-8 text…), that sets a variable uwsm's shell or its programs read to change what follows (IFS, EXECIGNORE,
  BASH_ENV, BASH_*, ENV, GLOBIGNORE, CDPATH, LANG, LC_*…), or that reads "$HOME" or "~/" while an uwsm file sets HOME,
  is not judged: it is reported separately, not checked (never counted as safe, with no guessed severity), with what to
  rewrite, and it raises the backup. In a judged file, a line that writes XDG_CURRENT_DESKTOP is reported, not checked,
  high and not declarable, since uwsm reads this name again for each following folder, except with a fixed value of
  letters, digits, "_", "." and "-" ("sway", "GNOME:sway", quoted or not), reported as information; the same goes for an
  uwsm variable (`__NAME__`) or HOME, and for a relative inclusion or one of a folder. A shell profile or an uwsm file
  that contains a NUL byte, which the shell removes before reading, is reported too, not checked; and an "env.d" that is
  a link to a folder is followed everywhere, as uwsm follows it: the backup judges what it holds instead of being raised
  because it cannot be read as a file. In a profile, a value within double or single quotes is no longer cut at the
  first blank it contains, only at the first blank outside quotes. Wherever Vanguard judges a search or injection
  variable (PATH, LD_LIBRARY_PATH, SSH_ASKPASS, GIT_SSH…; uwsm files, profiles, environment.d, user.conf, units,
  Hyprland, commands), the value is judged under several readings, and a single suspect one is enough: as written;
  without any quote or backslash, wherever they are (`/usr/bin:"/home/alice/.x"`, `"$HOME"/.x`); each piece between ":"
  simplified ("..", "//", "."), whether or not the value reads "$HOME" or "$PATH"; and the whole value simplified as a
  single path ("/home/alice/a:b/../.x/demande" of an SSH_ASKPASS, which is not a list). "/home/alice/a b/../.x" is thus
  raised like "$HOME/a b/../.x". Each format only makes its own cut: environment.d keeps the whole rest of the line,
  blanks and ";" included, as systemd does (before, the value was cut there at the first blank, as in the shell);
  user.conf, for its part, splits DefaultEnvironment= and ManagerEnvironment= into words as systemd does, quotes
  included, and each word sets one variable ("DefaultEnvironment=PATH=/usr/bin LANG=C"); user.conf, user.conf.d and
  units' Environment= join a line ending in "\" exactly as systemd does (measured on systemd 262): the backslash becomes
  a space, a comment in the middle is skipped, an empty line ends the continuation, "\\" (two backslashes) and "\"
  followed by a space do not join (a line ending in "\" followed by a blank is reported as not checked: systemd does not
  join it to the next one; what is written before the backslash stays set) (before, they were joined like a shell, and
  "DefaultEnvironment=A=1 \", then "# note \", then "PATH=/home/alice/.x" stayed silent). Some false highs step back,
  faithful to systemd (measured: the suspicious variable is never set there): "DefaultEnvironment=B\" followed by
  "ASH_ENV=…", which systemd reads as ASH_ENV, and "DefaultEnvironment=A=1 \\" (two backslashes) followed by "PATH=…",
  which systemd rejects as an unknown key, are silent; a line ending in "\" followed by a blank, then a suspicious line,
  goes from high to not checked; in a profile, each command of the line, cut outside quotes at ";", "&" and "|", is judged up to the comment
  ("true && export PATH=…"); in fish, each word without its quotes, up to the comment or the ";" (before, "set -gx PATH
  /usr/local/bin $PATH # my tools" was wrongly raised). BASHOPTS or SHELLOPTS set for the session (environment.d,
  user.conf, a profile) is reported high: "dotglob" makes uwsm read the hidden files of its ".d" folders. A PATH with an
  empty or relative piece (".", ".x", "::", ":" at the start or end), which makes every program started by name be
  looked up in the current folder, is reported high in an uwsm file, a shell profile (fish included), environment.d and
  systemd's user.conf. The "exec" lines of popt settings (~/.popt, /etc/popt) are judged as launches. A file that a
  profile or an uwsm file reads with "." or "source" is also judged line by line, with the same rule as ~/.bashrc (a
  line that names LD_PRELOAD is reported, even if it only reads it), when the inclusion is spelled out in command
  position and its path is absolute or under "~/" or "$HOME/", up to 64 included files. A home folder written another
  way ("/home/alice/.", "/home//alice") is read in its normal form; a HOME with ".." is not followed (the folder taken
  from the account database replaces it, and without it, no relative or empty path stands in for it) and the check
  reports the home folder as unknown, not checked. Limits: in a profile, an inclusion written another way (relative path
  or one computed from a variable, loop over a folder, eval) is not followed, and the check does not report it, an
  included file that cannot be read, is too large or is not UTF-8 is not judged, and a quoted value written over several
  lines is not followed from one line to the next, and can hide the line after it; root-only system uwsm files, and what
  they include, are not judged this way; ~/.profile, which uwsm reads before its own files in the same shell, is not
  judged with the uwsm rule (the author's choice): a line there that changes the desktop name or an uwsm variable,
  defines a function or an alias, or starts any command, is not checked; a PATH set by a simple line is judged only for
  its hidden folders and its empty or relative pieces: an ordinary folder of the account placed before the system ones
  can change every program that uwsm, or what it starts, then finds through PATH (tr, sh, env, systemctl,
  xdg-user-dirs-update…); Vanguard does not read the session's "dotglob" setting: a hidden file of a ".d" is judged
  under that condition, stated; a line there that is not simple is read only command by command, without reading shell
  code; bash 5.3 also refuses a file with a NUL byte on the second line after "#!", which Vanguard reports unchecked to
  be safe (an ELF program, with a NUL byte in its first bytes, stays silent as binary); a relative PATH set by a systemd
  unit or a Hyprland "env =" line, and a relative LD_LIBRARY_PATH, are not reported; outside a simple line, a PATH piece
  that reads a variable ("$…"), starts with "~" or "%", or a value containing "`", "\", "{" or "(" (Arch's
  "${PATH:+$PATH:}$1") is not judged relative; a "~" within single quotes (`export PATH='~/bin:/usr/bin'`) and zsh's
  "path=(. $path)" are only reported as not checked, and ~/.cshrc is not read; a condition or loop in a profile ("if …;
  then export …; fi") is read command by command, without reading shell code; XDG_DATA_DIRS, XDG_CONFIG_DIRS,
  GIT_EXEC_PATH or TMPDIR set to a hidden folder are not reported, nor is a hidden folder deeper than the first level of
  the home folder ("~/tools/.x", common rule); an inclusion cycle between uwsm files is not reported by the check (the
  backup is raised); in a profile, a line that is not simple is not computed ("/$HOME/.x" is not read there as the home
  folder): it is reported as not checked. A variable set during the session or by a Hyprland "env =" line is not
  checked; a folder moved by a shell profile (HOME, ZDOTDIR, XDG_CONFIG_HOME) is reported, but what is read under it is
  not judged.
- **What Vanguard cannot read safely is reported as not checked.** In a shell profile (bash, sh, zsh, fish), an uwsm
  file, environment.d and user.conf, a line that touches a watched variable (PATH, LD_*, BASH_ENV, BASHOPTS,
  SSH_ASKPASS, EDITOR, PAGER, PERL5OPT…; FPATH, MODULE_PATH, PROMPT_COMMAND and ZDOTDIR are added, and in a profile HOME
  and XDG_CONFIG_HOME, which decide the files read next) stays silent only in a simple form that Vanguard computes
  entirely: "NAME=value" or "export NAME=value", the value literal, in double or single quotes or not, reading only
  "$HOME" at the start of a piece and the variable itself ("$PATH"), without "$(", "`", "${…:-…}", "&", "|" or
  backslash; in fish, each instruction on the line, "set -x NAME word…" or "fish_add_path folder…", with "~" and "$HOME"
  at the start of a word ("set -q", "set -e", "set -n" and "set -S" set nothing: the rest of the line is judged); in
  environment.d, "NAME=value"; in user.conf, each word of DefaultEnvironment=. A simple form whose value is suspicious
  is reported high. In the shell (bash, sh, zsh, uwsm), any other line stays silent only if each of its commands, split
  by a strict splitter, is one of the forms of an allowlist, closed and written in a single place: a program or a
  function run by its name (without a "$…=…" argument); a command without effect (":", "true", "echo", "test"…); "[[ …
  ]]" with nothing after its "]]" and "(( … ))" alone; "for NAME in …", "for (( … ))", "case WORD in" and a function
  definition; "export", "declare", "typeset", "local" and "readonly" of ordinary names written as they are, without
  "-n", "-i" or "-T", the value without "$" or "`" outside quotes; "read" and "mapfile -t" of an ordinary name; "set",
  "shopt", "unset", "setopt", "unsetopt" and "zmodload" with fixed words, without "-A"; "let" without a calculation that
  sets and "getopts" with fixed words; "bind" without "-x", "bindkey" without "-s", "zstyle" without an option, "emulate
  -L" or "-R"; zsh's "autoload" and "zle" with fixed words; "trap" and "alias" with a safe body; "printf" and "print"
  with a literal format; "wait" without "-p", "hash -r", "enable -a", "-p" or "-s", "command -v", "exec" of a safe
  command; a common activation tool (`eval "$(mise activate bash)"`); "source" or "." of a fixed path that reads only
  HOME, XDG_CONFIG_HOME, XDG_DATA_HOME, ZDOTDIR, OMARCHY_PATH, NVM_DIR, ZSH or __fish_config_dir. A command that runs
  apart (before "|" or "&", inside "( … )") stays silent too. The splitter reports the line as not checked as soon as it
  is in doubt ("$'…'", "`", "\" outside quotes, a quote or a parenthesis it does not close). It reads each line on its
  own (only lines ending in "\" are joined): a quoted value left open over several lines is not followed and can hide
  the line after it (the limit written above holds for this allowlist too). A bash-completion function that sets a
  variable by its name ("_comp_upvars", "_comp_get_words" and any "_comp_…", "_upvars", "_get_comp_words_by_ref",
  "_init_completion"…) called with a computed argument ("_comp_upvars -v $a$b …") is reported as not checked; a watched
  name written plainly among its arguments ("_upvars -v PATH …") already was. Everything else is reported by the check
  as not checked, naming the file and the line, never counted as healthy: "builtin export", "command export", an alias
  to export, eval or source ("alias e='x=1 export'" included), "declare -n", "read -a", "mapfile -d", "printf -vPATH",
  `printf "-v"`, "compgen -V", "wait -p", "hash -p", `eval "$(f)"` of a function from the file, ". $f" of a variable set
  in the file, "set -A", "emulate sh -c", "- eval", zsh's "if [[ … ]] { … }", a command name that is computed
  ("ex${z}port", "$X"), ". <(…)", "source /dev/stdin". fish is no longer read in detail: as soon as a fish configuration
  exists (config.fish, fish_variables, conf.d, functions, completions in ~/.config/fish or in the fish folder of
  XDG_CONFIG_HOME; vendor_conf.d, vendor_functions.d, vendor_completions.d and generated_completions in
  ~/.local/share/fish or in the fish folder of XDG_DATA_HOME; config.fish, conf.d, functions, completions in /etc/fish
  and in /usr/local/etc/fish; config.fish, functions, completions in /usr/share/fish and in /usr/local/share/fish;
  vendor_conf.d, vendor_functions.d, vendor_completions.d of fish under /usr/share, /usr/local/share and each
  XDG_DATA_DIRS folder), the check says "fish: not checked", naming what is present
  (eight places at most, then the count of the others): lazily loaded functions, universal variables, completions and
  packages' conf.d are not read, and what fish sets or runs is not judged; places outside this list are not counted
  (~/.config/fish/fishd.*, ~/.cache/fish, the fish of a Nix profile, a fish_function_path set by a shell profile).
  Simple suspicious fish forms stay high. A
  system fish folder only root can change is reported only if fish is there (an account place is present, or the fish
  program is installed): without fish, the vendor_*.d folders other packages install are not reported. The price: a
  ~/.config/fish/conf.d filled by another program, with fish not installed, is enough for "fish: not checked" to show,
  with that folder and the vendor_*.d folders of /usr/share/fish. In fish, environment.d and user.conf, any line outside
  the simple form that touches a watched variable, by its name or by a computed name ("set -gx $n …", "… | source"), is
  reported the same way. If a reported line can still be read without doubt as suspicious ("true && export
  PATH=.x:$PATH", "fish_add_path ~/.x" inside an "if"), it stays high, in environment.d and user.conf too
  (`PATH=/home/alice/.x:"$PATH"`, a decoded name such as "DefaultEnvironment=P\x41TH=…", read as PATH); in
  environment.d, where a variable not set there is empty, "${NOPE:+x}/home/alice/.x", "/home/alice/${NOPE:-.x}" and
  "$NOPE/home/alice/.x" are high. A HOME, ZDOTDIR or XDG_CONFIG_HOME set elsewhere than its usual place is reported as
  not checked, and high toward a hidden or temporary folder. In a session environment file (environment.d, user.conf,
  uwsm), such a line also raises the backup: what it sets is not read. Common activation tools (`eval "$(mise activate
  bash)"`, "zoxide init fish | source") and ordinary forms ("[[ -f ~/.x ]] && source ~/.x", "for ((i=0; i<$n; i++))",
  "command -q zoxide", "autoload -Uz compinit") stay silent. Before, these forms were read in several guessed ways, and
  some stayed silent ("export PATH=${NOPE:-a&b}:/home/alice/.x", `export "PATH=/home/alice/.x:$PATH"`,
  `PERL5OPT="-I/home/alice/.x -MX"`, "SSH_ASKPASS=/home/alice/.askpass", "shopt -s dotglob; export BASHOPTS", "set -q X;
  set -gx PATH /home/alice/.x" and "fish_add_path" inside a fish block). Two false high reports go away:
  "PATH=/usr/bin:/a/.." (each piece is simplified on its own) and environment.d's "PATH=/usr/bin # /home/alice/.x" (a
  single literal value, under /usr). Limits: what an allowed activation tool writes is not read; a file included through
  a path that reads one of the allowed variables (`source "$OMARCHY_PATH/default/bash/rc"`, `.
  "${OMARCHY_PATH%/}/default/uwsm/default"`) is not followed, and the line stays silent; in environment.d and user.conf,
  HOME and XDG_CONFIG_HOME are not judged as a moved folder: Vanguard only reads the systemd units under the folder set,
  and an XDG_CONFIG_HOME or XDG_DATA_HOME set there is not followed for fish (only the session's are); in
  environment.d, a variable set earlier (HOME, XDG_CONFIG_HOME or any other, in the order of the systemd generator:
  by file name, ~/.config/environment.d, /etc, /run, /usr/local/lib then /usr/lib) is followed: a watched variable that
  reads it ("$HOME", "${HOME}", "${X:-…}", "${X:+…}") is reported as not checked, naming the variable and the line that
  sets it, and high if its value, expanded as the generator expands it, is suspicious ("HOME=/home/alice/.x" then
  "PATH=$HOME/bin"); "export HOME=…" sets nothing for the generator, and "%h" is not expanded there; if the file and
  those that set are changeable only by root, nothing is reported; an environment.d file with a line ending in "\" (one
  backslash or more, followed or not by a blank or a carriage return), which the generator does not join the way
  Vanguard reads it, is reported as not checked as a whole and raises the backup, unless it is root-only; an
  environment.d file of /etc, /run, /usr/local/lib or /usr/lib that reads a variable the account can change is reported
  as not checked as a whole and raises the backup; nothing is computed there: it is enough for the name to be written
  right after "$" or "${" on a single line of the file, a comment or the continuation of a quoted value included, in
  the word of a "${X:-…}" or "${X:+…}" too, nested or not, the variable itself included ("PATH=$PATH:…" when the
  account sets PATH); a variable the account can change is set by an environment.d file of the account, by
  ManagerEnvironment= or DefaultEnvironment= of a user.conf or user.conf.d of the account (a value written with a
  double quote, an apostrophe or "\" is not read: it stands for every name), by a system file (environment.d,
  user.conf, user.conf.d) that is not root-only, or by a line that reads one, whatever file writes it; a system file with a line that reads one also
  counts for everything it sets; a line of a root-only file never hands such a variable back to root; those of the
  session (profiles, ~/.pam_environment) are not counted; limits: a name parted from its "$" by "\", '"' or "'"
  ("$\A", '"$"A') in a root-only file is not picked up, and "%" ("%u") in ManagerEnvironment= or
  DefaultEnvironment= is not expanded; zsh's ": ${PATH::=/home/alice/.x}" and
  environment.d's "PATH =…" (a space before "=") are reported as not checked, not high; in the shell, a variable set
  earlier in the file is not followed ("PATH=$X:$PATH" is reported, not high); a value read inside a calculation, or
  built in pieces over several lines, is not followed; a non-simple line in a file only root can change is not reported
  (Omarchy's, such as "${EDITOR:-…}", therefore stay silent); in an account file, common forms are reported as not
  checked without being wrong: "[[ … && … ]]" and "[[ … || … ]]" ("[[ -z $DISPLAY && $XDG_VTNR -eq 1 ]]"), "[[ x =~ (x)
  ]]", NVM's `\. "$NVM_DIR/nvm.sh"`, `for f in …; do source "$f"; done`, Omarchy's "zd()" function, "local x=$(…)",
  "command ssh …", "source <(kubectl completion bash)", "enable -n kill", "autoload" in a bash file, `export
  VISUAL="$EDITOR"`, "${EDITOR:-…}", "PATH=~/bin:$PATH", zsh's "path=(…)", "ZDOTDIR=$HOME/.config/zsh",
  `PROMPT_COMMAND="history -a; …"`, `eval "$(dircolors -b ~/.dircolors)"` and Debian's lesspipe "eval", an alias that
  runs "$EDITOR", the body of a "<<", a line inside a "case", "shopt -s dotglob"; in environment.d and user.conf, a "%h"
  or a final backslash is reported as not checked; a non-simple line in a session file may raise the backup for a
  harmless form.
- **System programs, taken by their path.** The check, traces, monitoring, the backup and the other machine readings
  start pacman, systemctl, journalctl, ss, crontab, ping and the rest from the system folders, never through the
  account's PATH: a fake program placed in ~/.local/bin can no longer hide a connection or a journal line. The
  self-test does the same for its cross-checks (id, dpkg-query, sshd and the others). On Linux,
  they no longer receive the account's environment (PATH, BASH_ENV, LD_PRELOAD…): a system script such as checkupdates
  no longer starts a fake pacman placed in ~/.local/bin, and "System up to date" is no longer said without checking.
  Tools you install yourself (docker, podman, git, nmap, trivy, gitleaks) are still looked up in the PATH, on purpose,
  like xdg-open, which opens a page or a file with the application your account chose.
- **Machine readings, taken from the system.** clamscan and upnpc are run and reported present from the system folders,
  never through the account's PATH. checkupdates works in a new private folder, deleted afterwards: a database planted
  in advance under the known name no longer makes it say "up to date". A system tool written in Python (ufw,
  firewall-cmd, dnf) no longer loads the account's Python packages. A Docker daemon named by a variable (DOCKER_HOST,
  DOCKER_CONTEXT other than "default", DOCKER_CONFIG), even one set to blanks or to non-UTF-8 bytes, or by a context
  chosen in ~/.docker/config.json, is reported as not checked instead of being read, for published ports as for image
  flaws; a container port exposed to the network, already seen by the system daemon or through the processes, is still
  reported. config.json is read almost the way the Docker CLI reads it (what differs is reported as not checked): empty
  or made of blanks, it leaves the default context, as for the CLI; the context key regardless of case, every duplicate
  included, a linked file (stow, home-manager) followed; a HOME or DOCKER_CONFIG that is relative or contains ".." makes
  the daemon not checked (the CLI removes ".." from the path text, the system follows it after a link: it would not
  always be the same folder). When the Docker API does not answer, the CLI that Vanguard starts targets the system
  socket, without the home folder's settings, for ports as for images. Limit: a daemon chosen for real (Docker Desktop,
  rootless Docker, colima, remote host) is no longer read at all; a port it publishes is no longer reported, only said
  to be not checked.
- **The window size without an account program.** Without a terminal, Vanguard no longer runs `tput` (looked up in
  the account's PATH) to learn the screen size.
- **ClamAV scan: only the file actually examined is touched.** Each reported file is checked again on its own before
  Vanguard offers to quarantine or delete it, and the action only targets that exact file. A file with a booby-trapped
  name (one containing a line break) can no longer make it target another of your files. The quick scan once again
  reads Downloads and the other risky places even when /tmp holds recent files. Anything that could not be scanned or
  confirmed is shown as "not verified", never as "clean".
- **Quarantine: restoring a file can no longer be used to write elsewhere.** A file is only put back in its original
  place, from the quarantine folder; on Linux, never through a shortcut (link) placed by another account. On Windows
  too, every folder of the path is checked and held during the restore, and a folder deleted since the isolation is
  recreated. When a record exists, Vanguard checks that the restored content is the one that was isolated; otherwise
  the file stays in quarantine and Vanguard shows both fingerprints. On Windows, when Vanguard runs as administrator,
  nothing leaves the quarantine any more: Vanguard explains how to do it by hand, safely. When Vanguard refuses to
  restore a file for a safety reason (original folder, fingerprint, administrator), it says how to take the file out
  yourself. A file's special permissions are not restored, but Vanguard says so and gives the command to restore them.
  Set-aside entries are shown by name and reported in the incident traces. A path that contains ".." is resolved
  before isolation. A YARA scan started on a relative folder ("vanguard yara .") quarantines what it finds again.
- **The record of changes no longer loses an entry.** Two Vanguard processes writing at the same time (monitoring
  and a command) each read the record then wrote it back: one entry could vanish, for example the one that lets a
  quarantined file be put back. Each entry is now written under a lock, from reading to writing; if the lock cannot
  be taken, nothing is written over and this is said.
- **Windows: an update blocked by a folder says so.** A folder named like the temporary copy
  (`vanguard.exe.nouveau`) is named, with what to do, on a real Windows too, which answered "Access is denied" where Wine
  and Linux say "File exists".
- **Windows: a root added to the account alone is shown.** A root certificate added to the user's own account only,
  for example by a program that intercepts HTTPS traffic, is now reported in the checkup whatever its name, at medium
  level or higher. If that store cannot be read, the checkup says "not checked" instead of "nothing added". A root
  placed in the account can no longer hide the computer's one, and the checkup no longer offers a removal that
  Vanguard would then refuse.
- **Secret search: a received project no longer starts anything.** The search for secrets in git projects can no
  longer be trapped by a received project (for example an unpacked archive): neither git nor gitleaks starts a program
  chosen by that project's settings any more, and nothing is downloaded. With a git older than version 2.31, gitleaks
  is no longer run (and this is said), and a project that gitleaks only read in part is no longer counted as checked.
  In the guide, git commands, "yay -Qua" (which can run git) and "claude mcp list" are no longer started from Vanguard
  and no longer described as harmless: they can start programs chosen elsewhere, and are typed in a terminal.
- **Linux: the sharing check sees every share.** It now sees folders shared from the file manager ("Share this folder"
  with guest access) and NFS shares stored in /etc/exports.d. A share file written in an unusual way, or an NFS share
  written over several lines or with no client listed, no longer fools it. When it cannot read these settings, it says
  "could not check" instead of "no open share".
- **/etc/ld.so.preload read the way the Linux loader (glibc) reads it.** This file makes libraries load into every
  program, root included. The glibc loader does not always ignore a line that starts with "#": from the second "#" in
  the file on, a "# /path.so" line may be loaded. Vanguard follows its reading as it is, on the bytes, and adds the
  "a # closes its line" reading: a name seen by either one counts. A name ending with a carriage return is judged as
  the file it names, which is not the package's file; a note at the end of a line no longer counts as a library. The
  audit, the removal of a line after confirmation and the startup notice read this file the same way.
- **Removing a line from /etc/ld.so.preload refuses what would change more than that line.** It refuses a line that
  loads nothing (empty, or a comment the loader ignores). It also refuses, without asking and without writing
  anything, a removal that would make the loader load a name it did not load: what it blanks from a "#" depends on the
  file size, and removing a line can wake a hidden "# …" line. The refusal names what would be loaded (each name once,
  paths first, five at most, a lone "#" counted apart) and asks to fix the file by hand. If the removed line stopped
  the loader (a NUL byte), the following lines, already shown in the audit, will be loaded afterwards: the question
  says so before the yes.
- **A line that cannot be found is no longer a success.** When removing a startup line, or commenting out a proxy
  line, cannot find the named line (file changed since the audit, a line that is not UTF-8 text), it is a reported
  failure, "not done", no longer "already done". A flagged line that is not UTF-8 text is no longer offered for
  automatic removal: the alert says it must be removed by hand.
- **A flagged line of a startup file is now removed alone only in a file made of simple assignments.** A line ending
  with "\" (even followed by blanks), or following such a line, is never removed alone: the shell and systemd join it
  to the next one (systemd, even after a comment). In a file read by a shell or as a variables file (/etc/profile,
  /etc/profile.d, bashrc, zsh, fish, /etc/environment, environment.d…), Vanguard does not read shell code: a line is
  removed alone only if it is "NAME=value" or "export NAME=value" and the WHOLE file, in UTF-8, is made only of empty
  lines, whole comments ("#" at the start of the line, after spaces or tabs) and lines of that form. The value is made
  of letters, digits and "/ . _ - : + , = @ %" (empty allowed, with no "=" at the start or after a ":", which zsh
  expands), or is entirely inside single quotes with those signs and spaces; after it, only blanks (no comment, no
  "\r"). Lines are split at "\n" only: for bash and sh, a final "\r" is part of the value. A file written on Windows
  ("\r\n") is therefore not of that form, and "LD_PRELOAD=\r", which preloads a file named "\r", stays flagged. The
  NAME is made of capital letters, digits and "_", is set only once in the file, and is not a variable the shell
  reads, sets or keeps itself (IFS, PATH, ENV, HOME, PWD, OLDPWD, LANG, UID, EUID, PPID, GID, EGID, USERNAME, TMPDIR,
  GLOBSORT, TERMCAP, TZ, and those mksh keeps read-only such as KSHUID… 118 names, and any NAME starting with BASH_,
  LC_, SHELL, ZSH, ZLE, COMP, READLINE_, HIST, PROMPT or RPROMPT). For bash, sh, dash and ash (tried), such a file
  runs, opens, reads and tests nothing another of its lines would see, and always returns 0. A line of more than 1,000
  bytes anywhere in the file makes every removal refused: pam_env from Linux-PAM 1.4.0 to 1.5.3 silently stops reading
  /etc/environment at a line of 8,191 bytes or more, and removing a line would wake up the following ones.
  /etc/rc.local, which the system runs itself, keeps the removal only if its first line is "#!/bin/sh" or
  "#!/bin/bash" (or /usr/bin/sh, /usr/bin/bash), with no option or only "-e": for another interpreter, "NAME=value" is
  not an assignment. Everything else stays flagged, at the same level, with the fix to make by hand: the audit no
  longer offers it, and the removal refuses it, without asking and without writing anything, if it gets it anyway. One
  such line drops the automatic removal of ALL the flagged lines of the finding: the alert says so. A file of more
  than 100,000 lines or 4 MiB is not judged: removal refused, said in the alert. The "\" rule applies to every file
  other than /etc/ld.so.preload. Outside /etc/ld.so.preload, Vanguard now removes only one kind of line itself: an
  assignment of LD_PRELOAD or LD_AUDIT that really preloads, in a simple assignments file as above. Another suspicious
  variable (PYTHONPATH…) or a command stays flagged, at the same level, to fix by hand: the removal accepts it only if
  the audit offers it, by the same rule. A line that empties LD_PRELOAD or LD_AUDIT ("LD_PRELOAD=",
  "export LD_AUDIT=", "UnsetEnvironment=LD_PRELOAD") preloads nothing: it is no longer flagged. A systemd unit (and
  its ".service.d/*.conf" drop-ins), /etc/crontab, /etc/cron.d, /etc/anacrontab, a .desktop shortcut and the GDM, SDDM
  and LightDM settings are never fixed line by line by Vanguard itself: a line there can hold back another one
  ("ExecStartPre=" or "ExecCondition=" that fails stops "ExecStart="; "SHELL=" or "PATH=" makes the cron jobs after it
  fail), and a login manager reads several files, each in its own way, the last value winning. The alert says so, the
  fix is by hand, and Vanguard refuses it even when asked, whether removing a line or commenting one out. These files
  are recognised by their exact name; a script stored elsewhere in those folders stays shell. The judgment is made
  once per file, in linear time. Limits: in a real bashrc or /etc/profile (a command, an "alias", an "if"), no line is
  removed alone, the fix is always by hand; a NAME set twice makes the whole file refused, even if both lines go
  together; "LD_PRELOAD=''" (empty quotes), "Environment=LD_PRELOAD=" in a unit and "Exec=env LD_PRELOAD= …" in a
  .desktop file stay flagged (by hand). The rule does not see what other files read before define (an "export"
  function or alias, "readonly", "set -e"), nor what the code read after the file does with the removed variable (the
  file that reads it, a launched program). Replayed with bash, sh (bash in POSIX mode), dash and busybox ash: zsh,
  fish, csh, ksh and mksh were not tried, and fish does not read "NAME=value" the way bash does: a .fish file always
  keeps the fix by hand.
- **A proxy line is now commented out only where a line can be removed safely.** Since 0.92.0, the browsing repair
  commented out the "http_proxy=…" lines of the system startup files (/etc/environment, /etc/profile, /etc/profile.d…)
  by looking at the line alone: a line that opened a quote without closing it got commented out, and the command the
  quote held then ran at every login. A commented-out line is a removed line for whoever reads the file: commenting
  out now follows the removal rule above, at the audit and when applied, even when asked. Only a simple assignment in
  capitals (HTTP_PROXY, HTTPS_PROXY, FTP_PROXY, ALL_PROXY) in a simple assignments file is commented out by Vanguard;
  never in a unit, cron, anacron, a .desktop file, a login manager setting or /etc/ld.so.preload. The rest (lowercase
  "http_proxy", double quotes, a real /etc/profile, an /etc/environment that sets PATH, like Ubuntu's) is flagged, the
  file named, to comment out by hand.
- **Automatic login is no longer turned off by Vanguard itself.** Since 0.92.0, Vanguard removed the line that opens
  the session without a password in GDM, SDDM or LightDM. Each reads several files, SDDM with its own reader, and the
  last value wins: removing the line seen could leave, or wake up, the one in another file. The alert stays, at the
  same level; the fix is by hand (the desktop's user settings, or the line in the file named), with the reason given.
- **Automatic login is read more closely, and a doubtful cancellation is no longer believed.** Files read: SDDM, every
  file of /usr/lib/sddm/sddm.conf.d and /etc/sddm.conf.d, whatever its name, then /etc/sddm.conf; LightDM, the ".conf"
  files of /usr/share, /usr/local/share, /etc/xdg then /etc/lightdm, and the guest session ("autologin-guest"); GDM,
  custom.conf (/etc/gdm, /etc/gdm3) and daemon.conf (Debian); each file counted to its login manager by its folder. An
  SDDM line is read the way SDDM 0.21.0 reads it, from its source: "#" cuts the line, and "[Autologin] # note" does
  open the section. A login set in a file is taken as cancelled only by a line further down the same file, same
  section, same key; cancelled anywhere else (another file, another section, another case, a value the login manager
  does not understand), it is reported as "not checked", the file named, not as "no automatic login". A file or folder
  of these login managers that cannot be read (permissions, not text, more than 1 MiB, more than 1,000 files) is
  named, not checked. Limits: GDM, SDDM and LightDM were not run (the sources of SDDM 0.21.0, LightDM 1.32.0 and GDM's
  settings were read); Vanguard also reads hidden files and the GDM files of every distribution, so it may report a
  login the login manager does not read; what SDDM and GDM do with a UTF-8 mark (BOM) at the start of a file was not
  checked (Vanguard skips it); /run/gdm/custom.conf is not read; Vanguard does not yet read a line exactly as GLib and
  Qt do: a Unicode space at the start of a line, a NUL byte after a section title, a UTF-8 mark at the start of a line
  other than the first, a GDM file that stops at an error; in these rare cases, which require writing in /etc, a login
  may go unseen.
- **The startup notice no longer goes silent on /etc/ld.so.preload.** A byte that is not UTF-8 silenced it; so did an
  unreadable file. Unreadable (a link to a missing target included), it is now reported as "not verified", with the
  reason; too large to be read in full, the unread rest is reported.
- **The audit no longer goes silent on an unreadable startup file or folder.** An /etc/ld.so.preload that is present
  but unreadable (permissions, a folder in its place, a link loop, a link to a missing target) left the audit green;
  it is now raised as "not checked", with the same reason as the startup notice (the audit raises it as high, the
  notice reports it as medium). The other startup and configuration files the audit reads (shell, environment, cron,
  session startup) and their folders (/etc/cron.d, /etc/profile.d, unit and session startup folders…) are raised too,
  unless they are root-only (an /etc/crontab at 600 or an /etc/cron.d at 700, for example): reported as information. A
  link in one of these folders whose target cannot be seen (a closed folder on its path) is raised too. Not raised:
  what is absent, a link to a missing target in one of these folders, a link to /dev/null (a masked file), an
  impossible path (a file in place of one of the path's folders); a folder in place of one of these other files is
  reported as information.
- **A service's `EnvironmentFile=` files are read the way systemd reads them.** A comment ends at the end of its line,
  and a lone carriage return also ends a line. A line ending with "\" continues only inside a value: a comment or a
  line without "=" no longer hides the next line. Escapes in a value are undone the way systemd undoes them ("\x"
  outside quotes, "\" \\ \` \$" inside double quotes, nothing inside single quotes); both the written and the undone
  form are judged, and a variable used as "${VAR}" in an Exec= line is expanded there in the form the service
  receives. A variable such as LD_PRELOAD set right after a comment, or hidden by an escape, is seen.
- **An error text cleaned with a single accent rule.** Cleaning an error text (the local record, and the relay, ready
  but not in service) and its final check now follow the same rule for separately written accents (U+0300 to U+036F):
  an accent is only kept after a letter, two in a row at most; after a digit, punctuation or nothing, it is removed,
  and U+034F, invisible, is never kept. The two separately written rules had drifted apart; the relay keeps a copy,
  tested on the same texts.
- **Sturdier.** Every Unicode format character (those that change reading direction or hide text) is shown as "�",
  following Unicode 17's table. A name that is not UTF-8 (lock, report, WireGuard interface) is opened under its real
  name and shown with its bytes as `\xFF`. When the system refuses a thread, Vanguard goes on in "reduced mode", says
  so, and what could not be done is not verified. A file included in the sshd configuration that cannot be read back
  is reported as not verified instead of being kept quiet.
- **A program in a temporary folder is suspicious again on Windows.** Since 0.95, a scanned folder
  (`vanguard yara <folder>`, the antivirus) goes by its real path, `\\?\C:\…` on Windows, which never started like
  `%TEMP%` or Downloads: an unsigned program found there was no longer reported as suspicious. Each folder is now
  compared in its written form and by its real path, ignoring the prefix and case; a folder declared through a
  symbolic link also counts on Linux. Found by the Windows VM test, before release.
- **The colours line closes in the console.** On opening, the window reads back the saved colours
  (`vanguard couleurs --json`); the command finished at once, but its line stayed "running" and its timer kept
  counting. It now closes ("colors read", or the error), like the line of a colour change. A test requires every
  finished command to close its line, successful or not.
- **Verification and publishing.** The repository tools no longer say green without checking: a skipped step is a
  failure on GitHub (except named exclusions), and skipped tests are counted down to the last line. shellcheck,
  cargo audit on the separate crates' lock files and the README numbers compared to the code are added. SECURITY.md
  no longer promises "at most one version a day": a fix ships in the next version, sometimes the same day. Every
  Python tool of the repository (privacy guard, Git hooks, verification, publishing) runs isolated (`python3 -I`): a
  module placed in the tool's folder or in PYTHONPATH can no longer disarm the guard before a commit or a push.
- **The Windows VM tests carry the window.** `outils/vm-tester.sh --exe vanguard.exe --fenetre vanguard-fenetre.exe`
  deposits the window with the program; without `--exe`, it is built with it and its fingerprint engraved. The deposit
  is refused, with the reason, if the window is missing while `vanguard.exe` names one, if it is not the one whose
  fingerprint it carries, if its marks contradict each other, or if the VM watcher is older than version 3. A job's
  fingerprints and signature are taken on the files prepared on the Linux side, never on their copies in the shared
  folder, which the VM can rewrite. `test.ps1` has a "Window (0.96)" step: the window in place must be the one whose
  fingerprint `vanguard.exe` carries, then `vanguard-fenetre --version` is run (30 s at most); a missing, different or
  unreadable window is a problem, never a skipped step, and a different window is never run. `outils/vm-tester.sh
  --verdict`, the release gate, requires a signed job that carried the window.
- **The features page looks like the window.** The features page (GitHub Pages) takes the colours, tabs and cards of
  the 0.96 window, read from its code at each render. A "Prise en main" (getting started) tab walks through it in ten
  steps, in the order of a first use (home, checkup, fix shown then read back, restore as before, alerts, devices,
  guide, command page, console). The "Coming next" section is drawn from the public roadmap issue (#1). The console
  searches the page: a typed word (accents and case ignored) hides the sections without it and highlights the
  passages; Enter goes to the next one, Escape resets everything. The screenshots show the window, no longer the
  terminal.
- **README screenshots taken in the window.** Six screens (audit, home, alerts, devices, outgoing connections,
  guide), in French and English, drawn by the window's tests, without a screen, on made-up data: nothing from the
  computer is read. They replace the screenshots of the terminal menu and are redone at each published version.
- **Issues follow each version, on their own.** At each published version, `outils/tickets-version.py` ticks the
  version's bold points in the roadmap issue (#1), replaces its "in preparation" section, and closes the "journal"
  issues that the version's commits say they fix. Each text first goes through the privacy guard; an empty body, or
  one shortened by more than 20%, is refused.

## November 12, 2026: version 0.94.0

- **"This is normal for me", bound to what is really there (Linux).** For an alert to fix yourself, Vanguard shows
  before the choice each flagged line (file:line, the whole line), the SHA-256 fingerprint of the file that holds it
  and of each program it starts; from the high level up, you have to type "normal". The choice lasts 90 days, from a
  terminal keyboard only, and silences the alert only for that exact state: a started program changed, a line added, a
  link put in its place or a file deleted, and it comes back naming what changed.
- **What can be declared, what never can.** Only a systemd user unit (a short list of allowed settings, each Exec line
  bound; a unit from /etc/systemd/user only if root alone can change it) and a launch line in a ~/.config/hypr file,
  read by its real path, can be declared normal. Never: a critical alert (a library outside any package preloaded
  everywhere), a backdoor, an ambiguous line (variable, pipe, relative path, `bash -c '…'`), more than 12 lines or a
  line too long to be shown in full, nor .bashrc, .profile, environment.d, .desktop, crontab or the session's
  LD_PRELOAD: the reason and the file:line are given, with "remove or move the line". On Windows, nothing changes.
- **What comes back.** An older choice outside this scope comes back at every check while the line remains, with the
  reason; an older choice made without the exact state of its files also comes back, to declare again after reading
  the details. Detection now sees a preload split with "\" at the end of a line, a Hyprland variable that hides what
  it starts, a launch in a file included from outside ~/.config/hypr, and a unit replaced by a link no longer
  disappears from the check.
- **What restarts a program at startup, read the way the system reads it (Linux).** Each line is judged the way
  systemd, Hyprland or its Lua configuration really runs it: variables replaced, lines split with "\" joined, escapes
  decoded, paths simplified. Also read now: Hyprland key bindings that run a command, systemd generators, session
  units and unit folders missed until now. What Vanguard cannot read to the end is reported, never counted as safe,
  and none of it can be declared normal.
- **The SSH client configuration read the way SSH reads it.** The check (risky settings) and the post-quantum check
  now split each line like SSH, expand Include files as they are read and follow the scope of Host and Match down into
  included files; a header that SSH may apply to all hosts counts as global for the alert. ForwardAgent,
  StrictHostKeyChecking and WarnWeakCrypto are judged by the values SSH accepts. What Vanguard does not read to the
  end (a form it does not interpret, an Include pattern it does not resolve like SSH, an included file too large,
  unreadable or too deep, a pipe or special file in ~/.ssh) is reported as "not read" or "unchecked", never as safe. A
  non-UTF-8 byte no longer hides a key without a passphrase or readable by others, and a configuration that includes
  itself no longer fills memory.
- **SSH edge cases, read like OpenSSH 10.** The "Match host=…" form (criterion=value) is read like OpenSSH 10; a
  list pattern of 1023 bytes or more under "Match host" or "originalhost", which SSH never compares, makes the scope
  uncertain instead of certain. Wildcard matching no longer calls itself: a giant KexAlgorithms value no longer
  crashes Vanguard, and a list longer than 4096 bytes is reported as not read. A value that rules out post-quantum,
  placed after an uncertain header that offers it, is reported as a doubt ("may rule out"). /etc/ssh/ssh_config is
  read for post-quantum only: agent forwarding or disabled host key checking written there is not reported.
- **Preview of a fix, without changing anything.** In `audit --json`, each finding that can be fixed carries a token;
  a read-only command rereads its single rule and says what the fix would do (commands, rights, previous values,
  undo), without running or recording anything.
- **Sixteen more tools in `--json`** (for scripts): integrity, latest flaws, updates, startup,
  antivirus and its status, YARA, memory, secrets, self-check, changes, rules, hidden cameras, NAT type, Wi-Fi channels
  and containers. No question, nothing changed (no quarantine, no install); what could not be seen makes the whole
  result unchecked. `secrets` never gives the value of a leak, `nat` does not write the public address,
  `wifi-channels` not the network names; without Internet, nothing goes out (no STUN, no arch-audit).
- **Advanced commands.** `vanguard startup --remove <fingerprint>` removes a single program from startup, named by
  the fingerprint that `startup --json` gives with its name and command: typing the command is the consent, with no
  other question; never a program to keep nor a firewall, and it stays installed. The previous value is recorded
  first, and `--put-back <fingerprint>` puts it back exactly as before. `vanguard colors` (left out of the help)
  already sets the colors of the upcoming window, kept in parametres.json. `vanguard --menu` (or `--terminal`) always
  opens the terminal menu, and `audit --json` says whether its score is reliable.
- **The mouse in the terminal menu.** A click opens a row (or ticks it in a list), hovering lights it up with its
  preview, the wheel scrolls, right-click goes back, and the keys of the help line can be clicked. A double click no
  longer opens two screens at once. Shift and drag still selects text; outside menus, the mouse goes back to the
  terminal.
- **Dashboard** (`vanguard dashboard`). A night background, cyan for what is fine, amber for what is waiting; the
  logo opens on a radar then joins the left rail, a 30-day alert curve, an icon for each part of the menu. Still with
  no JavaScript; without animation when reduced motion is requested.
- **Trapped text.** Blanks that are not blanks (Korean fillers, empty Braille, grapheme joiner) and rare invisible
  characters become "�" on screen: a network or device name no longer looks empty or the same as another. Spaces of
  another width (non-breaking, thin…) are shown as an ordinary space, without turning a normal file name into a
  trapped one. Variation selectors are removed from the display (the emoji one stays), and an access accepted for a
  name no longer covers a name that differs from it only by one of them.
- **Blocklists.** When working offline is requested, the screen no longer asks Cloudflare or the lists for the public
  address, even after a yes; it says so.
- **Fixes.** Antivirus: clamscan is no longer run when it has nothing to scan (it read the current folder), and a
  ClamAV database older than a week is no longer called up to date. Secrets: a history or a search cut at its limit is
  reported instead of a ✔, a repository read halfway is unchecked, the search stops after 20 minutes and its reports,
  which name the commit authors, are deleted. Containers: no more "run again with sudo". Alerts declared normal: two
  declarations at the same time (blocking, a release from quarantine, the menu, the reset) no longer erase each
  other; a lost release from quarantine sent the file back there at the next pass.
- **Hardened after an attack campaign.** `vanguard` with no argument starts no “vanguard-fenetre” program, even one
  placed next to it: it opens the terminal menu. The check does not take the watcher unit that Vanguard installs
  itself for a suspicious one (a percentage value, such as `CPUQuota=20%`, is not a systemd specifier). The automatic
  backup unit is kept quiet only as Vanguard writes it, word for word, and only if nothing Vanguard looks at can
  change what rsync starts: no ~/.popt file (rsync reads it at start, and a line in it can make rsync start another program), no
  drop-in for the unit in the account, a destination that is a real folder on the disk. Otherwise it is reported like
  any rsync copy in an account unit (into ~/.config/autostart, for example), and it cannot be declared normal; a
  system popt settings file written only by root is reported as “not checked”, as information. With the disk
  unplugged, its destination cannot be seen: information, not an alert (nothing is copied without the disk), checked
  again at the next check with the disk plugged in. Not looked at yet: a home folder (HOME) changed for the session
  manager, which would make rsync read another .popt file; that setting already gives the account a whole fake home
  folder, and will be judged later.
  `demarrage --retirer` and `--remettre` no longer follow any folder that is a link (~/.config or its autostart folder
  replaced by a link): nothing is written outside the home folder. An entry kept behind a link, or itself a link or a
  pipe, is not offered, and the list says it is “not verified” (in `--json` as in the terminal checklist), never “no
  program”; a `systemctl --user` that does not answer is said too. An enabled service that systemd reads outside
  ~/.config/systemd/user (an account folder read before the system's, such as ~/.local/share/systemd/user, even under
  the name of a system service), or a system service that the account completes (“name.service.d”), is said not
  verified too. A single read makes what is shown, noted and written: an entry changed between this read and its
  writing, within the same run, is not written (the fingerprint of a list shown earlier only names the path). Entries
  are read within bounds, without waiting on a pipe, at startup as in `vanguard slow`: an entry of 64 KiB or more is
  neither removed (it was removed with no way to put it back) nor put back over, an entry that, once hidden, would
  exceed this bound is refused before being written, a file replaced by a pipe no longer freezes the list, and a
  rewritten entry keeps its permissions; `vanguard slow` states how many entries it could not read, instead of
  counting them as absent. The settings seal is written in two steps: a hard stop between a file and its seal no
  longer raises a false tampering alarm.
- **Dependency security.** rustix 1.1.6 (advisory RUSTSEC-2026-0486: in its extended attribute functions, bytes
  never written were marked as initialized for an empty buffer), brought in by crossterm.
- **Tests.** Five new fuzzing targets (what a startup line starts and, for the upcoming window, the answers it reads,
  its console, its relay and its progress), which found real defects that were fixed.
- **Kept for 0.95.** The Vanguard window, its screens and its actions (view, apply or undo a fix from it) are not
  shipped yet: `vanguard` opens the terminal menu, as before.

## November 9, 2026: version 0.93.0

- **Real-time file scanning (Linux).** The watcher now scans each file written to the risky folders (Downloads,
  Desktop, ~/.local/bin, ~/.config/autostart) as soon as it is closed after writing or arrives by rename, without
  administrator rights (fanotify, one group per folder, no link followed). A certain file goes to quarantine, undoable,
  according to the settings; a known family is handled in one click; a suspect file raises an alert. It all fits in
  128 MiB of memory (YARA rules, heuristics, fingerprints of the last 48 hours). A lost file (full queue, kernel
  overflow) is counted then taken up again by a new reading of the folder; what could not be checked is reported,
  never counted as clean, and the hourly pass goes over the folders again. A single consent when the watcher is turned
  on. Tried under floods of thousands of files in real Arch, Fedora and Debian VMs.
- **ClamAV becomes optional.** Vanguard no longer offers to install it: its own engine does the scan and still reads
  the installed ClamAV database itself. clamscan becomes an adjustable second opinion (Settings › second-opinion, run
  by default when present; when off, every scan says so). The "pua" option adds unwanted programs to on-demand scans
  only, never to continuous protection, where a fingerprint quarantines by itself.
- **Antivirus status** (6.1.5, `vanguard antivirus --status`): the engine used, the databases and their date, what the
  engine does not read (7z, RAR, ClamAV bytecode…), the second opinion, PUA and real-time file scanning. Nothing is
  run or changed; `--detail` counts what the ClamAV database skips (about 10 s).
- **Safer quarantine.** It isolates only the file scanned, never a hard link to another one; content already in
  quarantine does not go in twice, and content taken out of it does not go back by itself.
- **Redesigned dashboard** (5.8, `vanguard dashboard`). An overview in lime on black, or light with one click, still
  with no script and no request: network monitoring, the last check (grade, network, problems, chained history),
  alerts of the last 30 days by severity (ring and chart), protection (watcher, real time, quarantine) and new
  devices. Every feature of the terminal menu is listed, with its place and its command, which one click selects for
  copying.
- **Backstage** (Settings, off by default, `vanguard settings backstage yes|no|show`): each command run by Vanguard
  shown as one grey line (program, shortened arguments, secrets hidden, duration, outcome); the last 200 stay in memory
  only, never on disk or in the log.
- **Fixes.** Scan a device: Enter alone goes back, a mistyped target is reported without going to the log.
  Post-quantum: the profile left by an uninstalled browser is not applicable, no longer "unreadable version". Restore
  network (Windows): no administrator window when no rule cuts the program any more.

## November 8, 2026: version 0.92.0

- **New actions for each threat.** Besides Block: **Suspend** (the program frozen, resumed with
  `vanguard blocking resume`, recalled at each check), **Cut its network** (the program runs but talks to no one,
  restored with `vanguard blocking restore-network`; on Linux, that process alone; on Windows, two firewall rules on its
  file), **Watch more closely** (Linux: an alert each time it starts, for 7 days) and **Trust** (a typed word, tied
  to the file's hash, 90 days). An action refused by a safeguard stays visible, greyed out, with its reason. Each
  alert type (ransomware, command server, attack tool, known malware…) has its own sequence of actions, taken from a
  closed list. A notified alert can be reopened with `vanguard alert <id>`: read back from the sealed log, the threat
  is judged again before any action.
- **Isolate the computer from the network** (`vanguard blocking isolate`, Linux and Windows). Everything is cut,
  incoming and outgoing, except the remote session in progress, DNS and Vanguard's servers; the cost is stated before
  consent, and `vanguard blocking lift-isolation` puts the network back exactly as it was. With one more consent
  (`vanguard watcher isolation on`), a near-certain ransomware frozen by the watcher also gets the computer isolated
  before it is stopped. Tried on a real Windows: remote session kept, Internet cut then restored, firewall identical
  after lifting.
- **The watcher stops known malware when it starts (Linux).** With active protection and a separate consent
  (`vanguard watcher known on`), a program of the account whose hash is that of known malware is frozen along with
  what it started, its evidence collected, then stopped and quarantined. Only a file placed in the account's folders:
  never a system or installed program, a critical process, Vanguard or remote access during a session. A launch guard
  running as root (fanotify, from the Linux kernel) ships in preparation, hidden: it will appear in the menu and the
  check only once finished.
- **A common analysis engine, with its own heuristics.** Each scanned file gets a single verdict: certain
  (MalwareBazaar hash, reliable ClamAV signature, EICAR test file), family (YARA rule, ClamAV signature), suspicious,
  clean or not checked. "Clean" only if everything was read. ClamAV databases already installed are read by Vanguard
  itself, without running clamscan, and only if no ordinary account can modify them. Heuristics (unsigned program in
  Downloads, content compressed as by a packer, double extension, macro that runs on opening, encoded PowerShell,
  script that downloads then runs…) give "suspicious" at most, never a quarantine on their own. `vanguard
  check-file`, downloads, suspicious email and extensions go through this engine.
- **Published programs built with zig.** Linux and Windows are built with zig and cargo-zigbuild, pinned and checked
  by their hash, here as in CI: two builds give the same program, byte for byte. The Windows program imports the
  UCRT, provided by Windows 10 and 11 with nothing to install.
- **Fewer false findings.** Post-quantum protection in Zen, Floorp and Waterfox is now read (their engine's version);
  without the docker group, a stopped Docker daemon is recognised as clean; a disabled, empty Windows event log is no
  longer called "cleared or replaced"; expected "not checked" results (a person's choice, the computer's state) no
  longer go to the error log or into a ticket, but stay "not checked" in the check.

## November 7, 2026: version 0.91.0

- **Vanguard no longer targets macOS.** No more Mac program, no more builds or tests on GitHub's Mac, no more MACOS
  partition on new rescue keys (a key already written keeps its own until it is next rewritten). Deployment removes the
  macOS program, its guide and its launcher from the key. A Vanguard for Mac already installed no longer finds updates,
  without errors; nor will it receive a key change: uninstall it. The SBOMs are produced and attested by the
  "nomenclatures" job of `ci.yml`, and `outils/publier-version.sh` still checks that attestation before publishing.
- **The header frame spans the whole window, and so do titles.** In menus, it follows the window when resized,
  preview pane included (the last column stays free, for the old Windows console); on other screens, it takes the
  width at display time. In a narrow window, it shrinks instead of overflowing: the right-hand detail is cut ("…") or
  dropped before the title. "━━" titles and "──" subtitles do the same, in menus, checklists and search; next to the
  preview pane, they stop one column before it. List text keeps its width. Without a terminal (pipe, report), frame
  and titles keep their 76 columns.
- **Checked arithmetic everywhere (ANSSI rules for Rust).** On Linux, the whole program refuses arithmetic overflows
  and truncating number conversions: every computation is checked, and an out-of-range value gives a stated error
  instead of a wrong number. Every program error has a readable message; the passphrase and the session key are wiped
  from memory after use. The Windows parts remain to be reviewed (CONFORMITE-ANSSI.md).
- **Menus remember the tool you ran.** Coming back to a group, the highlight returns to the tool last run, found by
  itself rather than by its number.

## November 6, 2026: version 0.90.0

- **Defense options, on one screen** (`vanguard defense-options`, tool 4.10 on Windows, 4.9 on Linux). What defends the
  computer, each option read along with what enforces it and adjustable from here:
  - on Windows: Microsoft Defender's settings, its exclusions and allowed programs; the 19 attack surface reduction
    (ASR) rules, each one to block, audit or off; Windows Firewall for each profile and its existing rules; the
    policies (GPO, Intune) that enforce a value, a third-party antivirus, a managed PC;
  - on Linux: the firewall (ufw, firewalld or nftables), its state, turning it off or back on.

  Strengthening is done after consent. **Lowering is the person's choice, never Vanguard's**: the lowering is shown by
  the administrator process (root on Linux), confirmed by a typed "y" (Enter alone means no), its previous value
  recorded first; the check-up calls it "your choice" and "Turn back on" restores it. MODELE-DE-MENACE.en.md has a
  "Lowered by choice" section that also says what Vanguard refuses no matter what: bypassing tamper protection,
  stopping the Defender or firewall service, closing the firewall on the network of an ongoing remote session,
  removing the iptables-nft tables of Docker, libvirt or fail2ban.

- **Confirmed defense actions, on Windows and Linux.** Much of what the check-up and threat hunting find is no longer
  advice "to do by hand": Vanguard undoes it itself, as administrator (root on Linux), after judging again what it
  sees, showing the action and getting a yes. The previous value is recorded and "What Vanguard changed" undoes it; an
  action that cannot be undone is called "cannot be undone" before the question.
  - Windows: SmartScreen, memory integrity, LSA protection and Credential Guard turned back on; weakening policies
    removed outside a domain or management; Defender exclusions removed; local account disabled; password set on an
    account without one, typed in the administrator window only; Sticky Keys restored by `sfc /scanfile`; OpenSSH
    fixed; added certificate roots removed; hidden launches (Run, tasks, Startup folder, WMI subscriptions) removed,
    the real Defender recognized by its location and signature, never by its name alone; a remote control tool
    launched but not connected removed (connected: refused).
  - Linux: hidden account locked (never deleted), account removed from a sensitive group, passwordless sudo
    tightened (validated by visudo), suspicious setuid or capabilities removed, secretly added service or startup
    undone, SSH server hardened (validated by `sshd -t`, open sessions stay), suspicious program stopped after its
    traces are copied, Vanguard program replaced outside Vanguard restored (the impostor kept in quarantine). An action
    that could lock the person out of their computer gets a WARNING, and the question defaults to no.

- **Blocking safeguards.** Blocking never touches the ongoing remote session (judged by the program's ancestry and by
  the actual Remote Desktop port); a Microsoft signature only ever refuses an action, never allows it for another
  program; Edge, Office and Teams signed by Microsoft are not quarantined, with no immunity for a program taking their
  name; an administrator quarantine never follows a link; a short (8.3) path is also judged in its long form.
  `vanguard blocking juger` says what blocking would do, without doing anything.

- **Less PowerShell, on Windows and Linux alike.** Accounts, certificate roots and shares, persistence (Run, tasks,
  common Startup, WMI subscriptions) and Defender go through Vanguard's administrator process without PowerShell; on
  Linux, services are handled by systemd over the bus, with polkit, without `sudo systemctl`.

- **Small things.** In menus, the terminal cursor no longer jumps from one line to another. A fix returns an exit code
  that says what was done. The .evtx log reader follows evtx 0.15.1 (RUSTSEC-2026-0431).

## November 3, 2026: version 0.89.1

- **Vanguard Agent (no AI).** A part of Vanguard that helps it run better on your computer, with no AI and without
  sending anything. It has four missions, each with its own switch (Settings › Vanguard Agent,
  `vanguard settings auto-tuning`):
  - **time limits and second attempts**: a check-up rule that comes close to its time limit two weeks in a row, or
    goes over it twice in 7 days, has its limit raised once, never higher; a rule whose passing "not checked" is most
    often resolved by the next check-up is run again once at the end of the check-up, within the total time limit;
  - **hourly pass cache**: the monitoring's hourly pass reuses, at most every other time, the recent result of a few
    slow checks, with its age ("checked 40 min ago"). A check-up started by hand checks everything afresh. The
    firewall, antivirus, remote connections, ports and persistence are never reused. A duration that proves wrong
    gets shorter, and too many mismatches turn off the cache for that rule;
  - **local record** (see sharing, below);
  - **notes on fixes**: a fix that fails twice says so, and answering "all" leaves it out of the batch to offer it on
    its own afterwards; a fix that does not hold says so too.

  The rules and what they judge never change: turning off a mission, or the whole Agent, removes no check. Each
  change is logged with its previous value in a sealed journal and can be undone (`undo <rule>`, `reset`).
  `vanguard agent` shows its missions, their last run and its journal, read-only; `--json` gives the same view for a
  script, without any personal data. Check-up rules also start longest first, so that the check-up does not end
  waiting on one.

- **Sharing with the author, prepared: nothing leaves in this version.** Settings › Sharing with the author
  (`vanguard settings sharing yes|no|see`). Each day the local record notes, on the computer and as aggregated
  counts, Vanguard's errors, its slowdowns, the result of fixes, the choices made in Vanguard, the hardware (no
  serial number) and the name and version of the software, services and drivers involved.
  - Never a password, file content, visited site, typed text, command argument or software inventory; an error text
    is cleaned or dropped whole.
  - The author's relay is not in service: Vanguard has no address to send to and opens no connection for it.
    MODELE-DE-MENACE.en.md describes what will leave the day it is, and how.
  - "See what would be sent" shows the next queued batch or, failing that, the batch of the latest record rebuilt to
    see it, byte for byte. "No" stops the record and erases it, along with the sending queue and the installation
    identifier. `VANGUARD_ENVOI=0` always wins.

- **Going back to 0.89.0, then to 0.89.1.** Nothing dangerous, but two things show:
  - 0.89.0 rewrites the self-test measurements (`autotest/mesures.json`) without a seal. Back on 0.89.1, the check-up
    reports it with a high alert ("Vanguard's state was changed outside Vanguard"), with its possible cause: version
    0.89.0 or older has run here. The measurements start over, and the alert goes away when the next check-up rewrites
    the file with its seal. No alert is silenced, no check removed;
  - a setting changed in 0.89.0 rewrites the settings file without the sharing answer. A "No" is not lost, though:
    it is also noted separately (`partage-non`, in Vanguard's folder), which 0.89.0 does not touch, and it holds
    until you answer "Yes". Without a "No", it is as on first launch: the sharing notice shows again.

  The Agent's files (`agent/`, `autotest/cache.json`, `autotest/reglage.json`) are not touched by 0.89.0.

- **For the author.** The error journal is sorted into causes followed from one night to the next, and the nightly
  watch alerts on these causes and on a self-test slowdown. The relay's code (`relais/`, not deployed), the
  collection of its batches and the fleet signals are ready: each batch is re-read there as hostile data, a source
  votes only once a day, and a likely false positive never goes to the AI, only into a ticket.

## November 1, 2026: version 0.89

- **Windows services handled by Vanguard itself, without PowerShell.** Vanguard stops, starts, disables or restores a
  service directly through the Windows service manager, without launching PowerShell. This covers Remote Registry,
  SSDP discovery, Windows Update, time, telemetry, the print queue, the Temp folder and the Windows Update cache.
  Vanguard's administrator window does it.
  - Each service has only the actions meant for it: none can turn off a Windows protection.
  - The services that depend on it are stopped first, then started again afterwards.
  - An emptied folder never follows a link that would lead elsewhere.
  - An optimizer setting that cannot send anything is reported as "not done", instead of being counted as done.

- **Firewall and network type without PowerShell.** Turning the firewall back on, public Wi-Fi mode and the network
  choice (public or private) go directly through Windows, and every change is read back.
  - No line can turn the firewall off.
  - "Block all incoming connections" is refused during a remote connection (Remote Desktop, SSH), or when Vanguard
    cannot tell whether there is one.
  - "Block the port" never targets SSH or Remote Desktop, nor the port of an open remote session.
  - What makes the PC less protected, such as reopening incoming connections or setting a network back to Private, is
    said as such before it is done.

- **Registry fixes without PowerShell.** Eleven fixes go directly through Windows: turning off Remote Desktop, NetBIOS
  and SMBv1, Internet time, Winlogon, booby-trapped debuggers (IFEO), "always install as administrator", and more.
  - Just before writing, Vanguard reads the value back and judges it again.
  - A value that is already right is not rewritten, and Vanguard says so.
  - The previous value is noted, for Undo.
  - NetBIOS is turned off on every network adapter, and Vanguard says a restart is needed.

- **Service quotes added automatically, and said.** A service's path can
  contain an unquoted space: another program could then slip in its place. The accepted fix adds the quotes itself and
  says so: "Vanguard adds the quotes to the path of service X".
  - It does so only if the quotes are the only change and the named program exists.
  - The path's folders (%ProgramFiles%, %SystemRoot%, %SystemDrive%, %ProgramData%…) are asked of Windows, never taken
    from a program's settings, which another program could have changed.
  - An unknown variable leaves the fix to be done by hand, and nothing is written.
  - The change goes through the service manager, as Windows intends, not by writing directly to the registry.

- **Seals: no more false "redone" alert.** Vanguard seals its state files to see whether another program changes them.
  Before, a lock left on its own made Vanguard wrongly say the seals had been redone, with a high alert. This happened
  with a Vanguard stopped at the wrong moment, a full disk, or two Vanguards started together on first use.
  - 0.89 puts down a witness right after the first real seal. That witness, together with the event log, shows that a
    sealing version has already run on this computer.
  - The lock left by 0.86 to 0.88 still counts as a witness if it is from before November 30, 2026. An update from
    those versions therefore keeps its protection.

- **SVG images attached to an email: hidden traps are seen.** An SVG image can contain a script or a link, like a web
  page.
  - A script hidden other than by a plain `<script>` tag (prefixed name, `onload` handler, `javascript:` address,
    embedded HTML, animation, DTD entities) makes the image "active".
  - A compressed image (.svgz) is decompressed, within size and time limits, then judged; its links and forms are
    examined.
  - A UTF-16 image is read like any other.
  - An image too slow to read is stopped after 5 seconds and reported as "not fully checked".
  - An ordinary SVG from Illustrator or Inkscape no longer says "contains a script": it only keeps a note.

- **Attached zip archives: read without trusting what they claim.**
  - An archive preceded by other bytes (self-extracting program, padding, behind a PDF) is still opened, and Vanguard
    says so.
  - The content is read back entry by entry, without trusting the archive's table of contents.
  - A cut or unreadable archive is reported as "not checked".
  - The name of each file in the archive is judged in full, invisible characters and reversal (U+202E) included: an
    ".exe" at the end of a very long name is no longer lost.

- **File names trapped with invisible characters.** "invoice.pdf[U+200B].exe", with an invisible character between ".pdf" and
  ".exe", passed for a document. Invisible characters are now removed before the name is judged, and reported as a
  "trapped name". This applies to downloaded files, attachments and names inside attached archives. Accents and
  other scripts give no warning.

- **Microsoft Defender scans: no more wrong "✔".** Defender can find a threat, remove it, and still answer "all good"
  with its code.
  - Vanguard now reads what Defender writes, and compares it with the threats Defender recorded during the scan. A
    recorded threat always counts.
  - An exclusion that covers the scanned file or folder removes the "✔": nothing is guaranteed, and Vanguard says so.
  - Without administrator rights, exclusions are hidden: the result is "cannot be checked", never "✔".
  - A file that Defender skipped because it is excluded is reported as "impossible to check", no longer as "known
    malware".
  - Defender is started from its real folder, and one line per minute shows that the scan is moving.
  - The full scan says that, on Windows, Defender scans the whole computer.

- **Windows restore point really created, and checked.** Before, Vanguard could say "OK" with no point kept.
  - The point is asked of Windows the way Windows itself does it, then Vanguard reads the list back: only a new
    point counts.
  - If the point is skipped or refused, the reason is given, then the question "continue without a point?".
  - Answering no stops everything and says "stopped at your request: nothing changed", not "a step failed".

- **Vanguard's administrator window: no more program picked by chance.** What Vanguard runs as administrator can no
  longer be replaced by a program planted in the account.
  - DISM, sfc, chkdsk, netsh, w32tm, ipconfig, net accounts, powercfg and Defender are started from the Windows
    folder, with fixed settings, never by name alone. winget is taken from Microsoft's App Installer.
  - PowerShell and these programs start with an environment reduced to what Windows provides; the account's settings
    (variables, moved folders) no longer follow them.
  - The whole list is checked before the administrator prompt; a malformed list is refused without doing anything.
  - Each failure is told in sentences, with what to do, and the technical detail in brackets.
  - Removing Defender threats also goes through this window: there is now only one kind of administrator prompt,
    the one that names Vanguard.

- **Disk check (chkdsk): no more false promise.** When chkdsk cannot check the disk, Vanguard no longer says "failed"
  or "to finish at restart": nothing is scheduled. It says "disk to check" and what to do (run `chkdsk X: /f` as
  administrator), with the real letter of the Windows disk.

- **Windows hosts file: never left empty.** Windows or the antivirus sometimes holds this file for a few seconds.
  Vanguard tries again instead of failing, writes the file in one go, and puts the old content back if writing fails.

- **Router UPnP: a failure is no longer "nothing open".** When the `upnpc` tool is installed but fails, or the router
  does not answer, the result is "not checked". Before, it said the tool was missing, or that UPnP was on with
  nothing open.

- **Root certificates (Linux) and the VANGUARD key: an unreadable file is never counted as empty.**
  - A certificate file that cannot be read, or whose name Vanguard cannot read, is no longer "no certificate added":
    it is named, with the command that removes it.
  - A folder of the VANGUARD key that cannot be opened no longer leaves the key "unchanged".

- **VANGUARD key: a copy no longer passes for it.**
  - Two keys with the same identifier are reported as "duplicate": unplug one. Neither is chosen by plug-in order.
  - The same key seen through two paths no longer counts as its own copy.
  - The boot partition (VTOYEFI) that became unreadable, renamed or missing is reported, instead of being skipped
    without a word. A key rebuilt on purpose without Ventoy is accepted with `--accepter-vtoyefi`.

- **Updates: the program's folders checked all the way up.** An update done as root checks every folder above
  the program, not only the last one: an account can no longer slip its own folder in its place. A signing key
  withdrawn by the backup key stays withdrawn, even if the seals are redone.

- **Replaced locks: reported in the report.** A folder, a link or a file with its rights removed, put in place of a
  Vanguard lock, stopped the event log, the list of network devices or the alerts from being written, without a
  word. It is now a high finding in the report, which says what is no longer written.

- **ClamAV: signatures found, nothing installed without asking.**
  - The signature folder set in freshclam.conf is passed to the scan: it no longer fails for lack of signatures.
  - The command that installs ClamAV and the one for its signatures are shown before the question that accepts them.
  - Without a keyboard, or with a closed input, the answer is "no": nothing is installed or turned on by itself.
  - Checking a file without ClamAV still gives its verdict.

- **Damaged MalwareBazaar list: reported.** A copy of the full list that no longer opens is no longer taken for an
  empty list: the warning says so, instead of saying "scanned" with only the recent fingerprints.

- **Menus: a preview on the right.** When the window is wide enough (110 columns or more), a panel to the right of the
  menu shows the description of the chosen line and what it opens. Search also shows the result's preview. Small
  windows stay as before.

- **Programs' protections checked before they leave.** `vanguard deploiement verifier-binaire` (former name:
  `verifier-pe`, kept) reads from their headers, without running them, the protections of the published programs: on
  Linux PIE, full RELRO marking (PT_GNU_RELRO in the data and over the dynamic section, BIND_NOW), non-executable stack, no writable and executable segment;
  on Windows high-entropy ASLR (with LARGE_ADDRESS_AWARE, which it requires), DEP and relocations, on top of System32
  DLLs and the manifest; on macOS every slice PIE, a 4 GiB __PAGEZERO and, on arm64, a single signature that fits in
  the slice. Each must also be of the shipped system and architecture (64-bit little-endian x86-64 ELF, PE32+ AMD64,
  arm64 and x86_64 Mac slices): the scripts say which one they expect (`--attendu linux|windows|macos`), and an .exe
  replaced by a Linux program, or a 32-bit program, is refused. verifier.sh always checks the debug program it has
  just built, and the release programs only if they are the ones built from this commit (`outils/compiler-version.sh`);
  deployment, publishing and CI check the ones that leave, before sending them, and refuse a program that loses one.
  CFG and CET are shown without being required.

- **RELRO really applied on Linux.** The Linux program (musl static-pie) carried the full RELRO marking, but musl's
  startup does not apply it: the GOT and `.data.rel.ro` stayed writable for the whole life of the process. Vanguard
  now makes that segment read-only itself at launch, as glibc's loader does; a failure is logged without stopping
  the startup.

- **Sturdiness.** Internal work, with no visible change: the code can no longer crash on unexpected data ("no-panic"
  rules everywhere), risky code (`unsafe`) is refused everywhere except in named places with their reason, readers of
  hostile data make no overflow or careless conversion, some are proven by Miri and Kani every week, dependencies are
  reviewed with cargo vet, and the code is reviewed against ANSSI's Rust guide.

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
