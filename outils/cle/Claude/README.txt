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
   Linux: in a terminal,   bash /run/media/$USER/VANGUARD/Claude/depanner.sh
          (or /media/$USER/VANGUARD/… on Ubuntu, Debian, Mint).
   Computer that no longer starts: boot SystemRescue (key menu), then the same command as on Linux. Claude
   mounts the disk read-only there to diagnose.

   The first time, Claude gives a login address (this computer's browser does not open): open it on YOUR
   phone, never in this computer's browser (it would keep your account signed in after you leave), sign in,
   and paste the code back if asked.


2. FINISH

   Type /exit in Claude. The launcher logs out and erases from the computer Claude Code, the login, the
   conversation and Claude Code's logs of this session. "Logged out" is shown only if Anthropic confirmed
   that the login ended. If it shows "Logout NOT confirmed" (offline, or a version of Claude Code that
   does not tell), end the session on claude.ai (Settings › Account).
   Window closed with its X: on Windows, a watchdog still erases; if in doubt (or on Linux),
   run the launcher once more, then /exit: it first erases what was left.
   After a doubtful computer (possible virus), or if it shut down or crashed during the session: also end
   the session on claude.ai (Settings › Account), so the login is worthless anywhere else.
   Signed in in this computer's browser by mistake: sign out of claude.ai there before leaving.


3. WHAT IS PROTECTED

   - Nothing is installed: the program is copied to a temporary folder, run from there, then erased.
   - The login to your Claude account is never written to the key; it only lives in the session's temporary
     folder (your account's only; on Windows, refused on a drive without Windows permissions, FAT or
     network), erased at the end.
   - Before it runs, the program is checked: on Windows, its digital signature, checked by Windows, made by
     "Anthropic, PBC" (name, country and company number of the certificate), and its checksum; on Linux,
     Anthropic's signature on the checksum list, and the program's checksum.
   - Your Claude account's connectors (mail, online files, calendar) are not loaded, nor any MCP server.
     This computer's browser never opens.
   - Instructions left on the computer for Claude, in a folder above the temporary folder (CLAUDE.md,
     CLAUDE.local.md, AGENTS.md, .mcp.json, a .claude folder), or settings imposed on Claude Code by the
     computer (/etc/claude-code, C:\Program Files\ClaudeCode, registry policies): the launcher refuses to
     start, and says why. Only exception: the .claude folder of the home folder (Claude Code already used on
     this computer), where only instructions (CLAUDE.md, AGENTS.md, rules) cause a refusal.
   - Claude gets troubleshooting instructions (CLAUDE.md, in this folder): diagnose read-only, explain the
     cause before fixing, change nothing without consent, never turn off the antivirus, the firewall or
     updates, respect the relative's privacy.
   - No automatic update: the verified version is the one that runs. Vanguard updates the key on its
     owner's computer.

   What you still accept: Claude can be wrong. Read each command before saying yes.


4. LIMITS

   - 64-bit Windows and Linux (x86-64). On Windows ARM, the x86-64 version runs under emulation.
   - On Linux without gpg, Anthropic's signature cannot be checked: the launcher says so and asks.
   - On Windows, the checksum list is not checked by a signature (no gpg): only Anthropic's signature on the
     program is.
   - On Windows, the computer's certificate variables are removed, but Claude Code trusts, like the browser,
     the certificates installed in Windows: a computer that inspects connections (antivirus, company, or
     malware that added its own) can read them.
   - On Windows, any account can create a C:\.claude folder: the launcher refuses if it exists at the start,
     not if it appears during the session.
   - The launcher lives on the same key as the program: it sees a damaged copy, not a fully rewritten key.
     A key that left your hands goes through Vanguard (on your computer) again before use.
   - Malware already running under the same account can read the login during the session: nothing stops
     it. On a computer believed infected, boot SystemRescue instead (key menu), and end the session on
     claude.ai afterwards.
   - On Windows, Claude Code may ask for Git for Windows for some commands: install it only with the
     owner's consent, from git-scm.com or winget.
