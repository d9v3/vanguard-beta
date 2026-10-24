#!/usr/bin/env python3
"""Essai de « vanguard fuite-mot-de-passe » dans un pseudo-terminal : la saisie se fait sans écho, elle exige un vrai
terminal. Tape « password » (trouvé des millions de fois dans des fuites), puis Entrée seule pour terminer.
    python3 outils/test-commun/mot-de-passe-pty.py <programme vanguard>
"""
import os, pty, sys, time, select
exe = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.environ["VANGUARD_LANG"] = "fr"
    os.execv(exe, [exe, "fuite-mot-de-passe"])
out = b""
def lire(t):
    global out
    fin = time.time() + t
    while time.time() < fin:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                d = os.read(fd, 4096)
            except OSError:
                return
            if not d:
                return
            out += d
lire(2); os.write(fd, b"password\n"); lire(8); os.write(fd, b"\n"); lire(3)
try: os.waitpid(pid, 0)
except ChildProcessError: pass
print(out.decode("utf-8", "replace"))
