TROUBLESHOOT WITH CLAUDE — Claude Code on the VANGUARD key
==========================================================
Français : LISEZMOI.txt

Claude Code, Anthropic's assistant, helps find the cause of a problem on a relative's computer (slowness,
crashes, viruses, network, startup). It reads the computer, explains and proposes; it asks before any
command that changes something. Some read-only commands run without asking, and what they show is sent to
Anthropic too. It uses Vanguard, on the same key, for the diagnosis.

You need: a Claude account (Pro or Max plan, or Anthropic Console), Internet, and the consent of the
computer's owner: what Claude reads (logs, settings, file names) is sent to Anthropic.


1. START

   Windows (10 version 1809 or later): double-click "Depanner avec Claude.bat" at the root of the key.
   Linux: in a terminal,   bash -p /run/media/$USER/VANGUARD/Claude/depanner.sh
          (or /media/$USER/VANGUARD/… on Ubuntu, Debian, Mint). The "-p" keeps bash from taking code from
          the computer's environment before the launcher's first line.
   Computer that no longer starts: boot SystemRescue (key menu), then the same command as on Linux. Claude
   mounts the disk read-only there, under /mnt, to diagnose. A disk still mounted in the session folder is
   never erased: the launcher says so, and asks to unmount it.

   The first time, Claude gives a login address (this computer's browser does not open): open it on YOUR
   phone, never in this computer's browser (it would keep your account signed in after you leave), sign in,
   and paste the code back if asked.


2. FINISH

   Type /exit in Claude. The launcher logs out and erases from the computer Claude Code, the login, the
   conversation and Claude Code's logs of this session. "Logged out" is shown only if Anthropic confirmed
   that the login ended. If it shows "Logout NOT confirmed" (offline, or a version of Claude Code that
   does not tell) or "The logout could NOT be started", end the session on claude.ai (Settings › Account).
   Window closed with its X: on Windows, a watchdog still erases; if in doubt (or on Linux),
   run the launcher once more, then /exit: it first erases what was left. What it cannot erase (a file
   still open, a mounted disk) is shown, with its path, never counted as erased.
   After a doubtful computer (possible virus), or if it shut down or crashed during the session: also end
   the session on claude.ai (Settings › Account), so the login is worthless anywhere else.
   Signed in in this computer's browser by mistake: sign out of claude.ai there before leaving.


3. WHAT IS PROTECTED

   - Nothing is installed: the program is copied to a temporary folder, run from there, then erased.
   - The login to your Claude account is never written to the key; it only lives in the session's temporary
     folder (your account's only; on Windows, refused on a drive without Windows permissions, FAT or
     network), erased at the end.
   - Before it runs, the program is checked: on Windows, its digital signature, checked by Windows, made by
     "Anthropic, PBC" (name, organization, country, company number and Delaware registry of the certificate,
     read field by field), and its checksum; on Linux,
     Anthropic's signature on the checksum list, and the program's checksum.
   - Your Claude account's connectors (mail, online files, calendar) are not loaded, nor any MCP server.
     This computer's browser never opens.
   - Instructions left on the computer for Claude, in a folder above the temporary folder (CLAUDE.md,
     CLAUDE.local.md, AGENTS.md, .mcp.json, a .claude folder), or settings imposed on Claude Code by the
     computer (/etc/claude-code, C:\Program Files\ClaudeCode, registry policies): the launcher refuses to
     start, and says why. Only exception: the .claude folder of the home folder (Claude Code already used on
     this computer), where only instructions (CLAUDE.md, AGENTS.md, rules) cause a refusal; on Windows, only
     if the path from the home folder to the temporary folder goes through no link or junction.
   - The computer's variables that would choose the server, the account, the certificates read by Claude
     Code, the proxy, tracing or code to load are removed before any Claude Code command.
   - On Windows, the PowerShell commands that do these checks are taken from the Windows modules, by their
     path; a module placed in the account never replaces them (otherwise, refused).
   - Claude gets troubleshooting instructions (CLAUDE.md, in this folder): diagnose read-only, explain the
     cause before fixing, change nothing without consent, never turn off the antivirus, the firewall or
     updates, respect the relative's privacy.
   - No automatic update: the verified version is the one that runs. Vanguard updates the key on its
     owner's computer.

   What you still accept: Claude can be wrong. Read each command before saying yes.


4. LIMITS

   - 64-bit Windows and Linux (x86-64). On Windows ARM, the x86-64 version runs under emulation.
   - The Windows launcher is tested under PowerShell on Linux, with the Windows-specific calls (permissions,
     signature, drive, watchdog) replaced by stand-ins, and also on a real Windows 11.
   - On Windows, a temporary folder (TEMP) whose path is longer than about 140 characters is refused: Claude
     Code would cut the name of its log, which could then no longer be found and erased.
   - On Linux without gpg, Anthropic's signature cannot be checked: the launcher says so and asks.
   - On Linux, started without "-p" (bash depanner.sh), the launcher restarts itself with it at once; but bash
     has already read the environment before its first line (tracing, BASH_ENV): hence "bash -p".
   - Under WSL (Linux inside Windows), Windows' imposed settings (C:\Program Files\ClaudeCode) cause a
     refusal, but the Windows registry policy is not read from there: the launcher says so and asks. Better:
     the Windows launcher ("Depanner avec Claude.bat").
   - On Linux, Claude Code may leave an empty socket (cc-socks…) in the user's runtime folder
     (XDG_RUNTIME_DIR): it holds neither the login nor the conversation, and goes away when the user logs
     out. The launcher leaves it alone (it could belong to another Claude Code).
   - On Windows, the checksum list is not checked by a signature (no gpg): only Anthropic's signature on the
     program is.
   - On Windows, the computer's certificate variables are removed, but Claude Code trusts, like the browser,
     the certificates installed in Windows: a computer that inspects connections (antivirus, company, or
     malware that added its own) can read them.
   - On Windows, any account can create a C:\.claude folder: the launcher refuses if it exists at the start,
     not if it appears during the session.
   - The launcher lives on the same key as the program: it sees a damaged copy, not a fully rewritten key.
     A key that left your hands goes through Vanguard (on your computer) again before use.
   - On the visited computer, the launcher proves "signed by Anthropic", not "latest version": a key left in
     a drawer for long, or reloaded with an older but signed version, passes. Vanguard refuses older versions
     on its owner's key; update the key before leaving.
   - Vanguard takes the version Anthropic announces as "stable"; that announcement is not signed. Only the
     program's authenticity is proven, not that it is the stable version. A newer version set this way then
     blocks older ones (Vanguard says so). To lift the block, on the Vanguard computer, in a terminal:
     outils/claude-cle.sh --accepter-version 2.1.0 (the wanted version); it shows what changes and asks
     you to type "ACCEPTER 2.1.0", then for the administrator password (polkit window, which shows
     "Vanguard : baisse de protection, Claude Code 2.1.0"). Newer versions are moved aside (not deleted),
     this is first written to the log (~/.local/state/vanguard), and a notification says so every time.
     To put everything back: outils/claude-cle.sh --annuler-acceptation, in a terminal, typing "ANNULER";
     only versions that still verify are put back. If a check is not possible for now (a passing fault),
     the undo is called "partial": the record is kept, run the command again later. Scope: this stops a
     timer or a program started with nobody at the screen. A program already running under the same
     account can still move those folders by hand; such a lowering leaves no notification and no log
     line. Only lowerings made by this command are notified and logged.
   - Malware already running under the same account can read the login during the session: nothing stops
     it. On a computer believed infected, boot SystemRescue instead (key menu), and end the session on
     claude.ai afterwards.
   - On Windows, Claude Code may ask for Git for Windows for some commands: install it only with the
     owner's consent, from git-scm.com or winget.
