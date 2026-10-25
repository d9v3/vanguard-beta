# Threat model

*[Français](MODELE-DE-MENACE.md)*

What Vanguard protects, against whom, and what it does not protect. This page sets the frame for the features: each
one should be able to say which threat on this page it covers. Vulnerabilities in Vanguard itself (a flaw in the
program, the USB key or the update) belong on another page: [SECURITY.md](SECURITY.md#security).

## What Vanguard protects

- **The computer it runs on**: its security settings, its updates, what starts with it, what runs on it and what
  talks to the Internet. Linux, Windows and macOS.
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
| A weak setting or an unpatched vulnerability | A security check graded A to F, missing updates, actively exploited vulnerabilities from the CISA catalog, end of support; every fix after consent, undoable except one that turns a protection back on. |
| Exposure to the Internet | Ports the router opens (asked of the router itself, UPnP openings included), public IPv6 without a firewall; in the logs, guessed passwords and Remote Desktop connections from outside. |
| An intruder on the local network or the Wi-Fi | Inventory of the devices and of newcomers, fake access point, hijacked DNS and certificates; public Wi-Fi mode when traveling. |
| Someone close who spies on the person | Spyware, remote control (fake technician). |
| A scam | Links examined without opening them, downloaded files checked, leaked accounts. |
| An AI agent that does too much | AI servers open to the network, agents that act without asking, poorly protected MCP servers. |

Each threat in detail, menu by menu: [What Vanguard does](README.en.md#what-vanguard-does).

## What Vanguard does not protect

- **An attacker who already has administrator rights.** They can stop Vanguard, erase their traces or skew what the
  system tells it. Vanguard does not protect itself against being turned off: it only reports that its monitoring
  was turned off. When Vanguard itself runs as administrator, it blocks nothing on its own, because its blocking
  settings can be written by any program of the account.
- **The kernel and the firmware.** Vanguard loads nothing into the kernel. It reports the signs of a rootkit (hidden
  processes, kernel modules that hide or are unsigned), but a well-made rootkit can lie to the system that asks it.
  Secure Boot is checked and the firmware (BIOS, UEFI) updated after consent, but nothing watches it live.
- **A new threat, still without a signature.** Detection relies mostly on known lists; what is not on them yet can
  get through. Vanguard complements the system antivirus (Microsoft Defender, XProtect, ClamAV): it does not replace
  it.
- **Everything, in real time.** Apart from the two Linux watchers (programs and connections, anti-ransomware; both off
  by default), the live integrity monitoring of critical files and Defender's blocking, monitoring runs every hour,
  between two checks.
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
- **What a borrowed computer reads.** Write protection keeps the key from being changed, not from being read: the
  logbook is safe only when encrypted.

## What Vanguard assumes

- **The program is the real one.** Check its SHA-256 checksum when downloading (`SHA256SUMS.txt`); every update is
  signed with Ed25519 and refused if it is badly signed, older, or if its size or checksum does not match. The
  program does not have a code signing certificate yet.
- **The system answers truthfully at the time of the check.** A computer already compromised at the administrator
  level can deceive all of its readings (see above).
- **The lists and third-party tools are right.** The threat, version and vulnerability lists (abuse.ch, CISA,
  vendors) and the tools Vanguard runs without having written them (ClamAV, trivy, gitleaks) are trusted as they
  are; a list that is too old is reported as not checked.
- **The person decides.** Nothing is changed without their consent. What they accept can be undone one fix at a
  time, except what turns a protection back on and the stopping of a program; a fix whose previous state cannot be
  read is reported as “not undoable” before it is applied.
- **Testing has its limits.** Vanguard is tested on the author's computer, a Windows VM, a second Windows PC and
  GitHub's machines (Windows, Mac, real Linux distributions). It has never run on a real Mac; other cases are still to
  be tried on real hardware (other distributions, a real UPnP router, booting the key).

## What leaves the computer

The threat, version and vulnerability lists are downloaded in full, the same for everyone. What Vanguard sends
itself:

- **On Windows and macOS**, the list of installed software does not leave: their versions are judged against these
  lists.
- **On Arch Linux**, the check sends aur.archlinux.org the names of the packages installed outside the official
  repositories (rule LNX-MAJ-006), to learn their latest version.
- **After consent**: the email address to the services that look up its leaks, the public Internet address to the
  four blocklists (Spamhaus, SpamCop, DroneBL, PSBL), the domain name of an examined link.
- **A checked password**: only 5 characters of its hash, to Have I Been Pwned; never the password.
- **With an abuse.ch key**: the key, to abuse.ch.
- **In public Wi-Fi mode**: DNS queries, to CIRA's Canadian Shield.
- **The update check**: a request to GitHub.
- A vulnerability report prepared by Vanguard is never sent by it: the person reads it and sends it themselves.
