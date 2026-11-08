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
| Known malware on the computer | The system antivirus as a second opinion, YARA rules, MalwareBazaar hashes, program memory, startup entries, signs of a rootkit; blocking after consent, or on its own for what leaves no doubt (active protection). |
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
- **Everything, in real time.** Apart from the two Linux watchers (programs and connections, anti-ransomware; both off
  by default), the live integrity monitoring of critical files and Defender's blocking, monitoring runs every hour,
  between two checks.
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
