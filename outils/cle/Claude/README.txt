TROUBLESHOOT WITH CLAUDE — Claude Code on the VANGUARD key
==========================================================
Français : LISEZMOI.txt

Claude Code, Anthropic's assistant, helps find the cause of a problem on a relative's computer (slowness,
crashes, viruses, network, startup). It reads the computer, explains and proposes; it asks before every
command and changes nothing without consent. It uses Vanguard, on the same key, for the diagnosis.

You need: a Claude account (Pro or Max plan, or Anthropic Console), Internet, and the consent of the
computer's owner: what Claude reads (logs, settings, file names) is sent to Anthropic.


1. START

   Windows (10 version 1809 or later): double-click "Depanner avec Claude.bat" at the root of the key.
   Linux: in a terminal,   bash /run/media/$USER/VANGUARD/Claude/depanner.sh
          (or /media/$USER/VANGUARD/… on Ubuntu, Debian, Mint).
   Computer that no longer starts: boot SystemRescue (key menu), then the same command as on Linux. Claude
   mounts the disk read-only there to diagnose.

   The first time, Claude gives a login address: open it (on this PC or on a phone), sign in, and paste the
   code back if asked.


2. FINISH

   Type /exit in Claude. The launcher logs out and erases Claude Code, the login and the conversation from
   the computer. Window closed with its X: on Windows, a watchdog still erases; if in doubt (or on Linux),
   run the launcher once more, then /exit: it first erases what was left.
   After a doubtful computer (possible virus): also end the session on claude.ai (Settings › Account), so
   the login is worthless anywhere else.


3. WHAT IS PROTECTED

   - Nothing is installed: the program is copied to a temporary folder, run from there, then erased.
   - The login to your Claude account is never written to the key; it only lives in the session's temporary
     folder (readable by your account only on Windows), erased at the end.
   - Before it runs, the program is checked: on Windows, its "Anthropic, PBC" digital signature, checked by
     Windows; on Linux, Anthropic's signature on the checksum list, and the program's checksum.
   - Claude gets troubleshooting instructions (CLAUDE.md, in this folder): diagnose read-only, explain the
     cause before fixing, change nothing without consent, never turn off the antivirus, the firewall or
     updates, respect the relative's privacy.
   - No automatic update: the verified version is the one that runs. Vanguard updates the key on its
     owner's computer.

   What you still accept: Claude can be wrong. Read each command before saying yes.


4. LIMITS

   - 64-bit Windows and Linux (x86-64). On Windows ARM, the x86-64 version runs under emulation.
   - On Linux without gpg, Anthropic's signature cannot be checked: the launcher says so and asks.
   - Malware already running under the same account can read the login during the session: nothing stops
     it. On a computer believed infected, boot SystemRescue instead (key menu), and end the session on
     claude.ai afterwards.
   - On Windows, Claude Code may ask for Git for Windows for some commands: install it only with the
     owner's consent, from git-scm.com or winget.
