#!/usr/bin/env python3
"""Écrit tests/donnees/categorie-cf.txt : la catégorie Cf (format, invisible) d'Unicode, lue dans unicodedata.

Les essais `chaque_format_d_unicode_est_montre` (src/ui.rs) et `chaque_format_d_unicode_est_invisible_dans_un_nom`
(src/protection/telechargement.rs) lisent cette table : un caractère de format qu'une nouvelle version d'Unicode
ajoute, et que Vanguard ne connaît pas, les fait échouer au lieu de passer caché. Reprise de toile.

Lancer depuis la racine du dépôt :
    python3 outils/table-cf.py             # écrit la table avec l'Unicode de ce Python
    python3 outils/table-cf.py --verifier  # échoue si ce Python connaît un Cf absent de la table

La vérification accepte un Python plus ancien que la table (la CI n'a pas toujours le dernier) : chacun de ses Cf
doit y être. Un Python de la même version doit redonner la table à l'identique.
"""

import sys
import unicodedata
from pathlib import Path

TABLE = Path("tests/donnees/categorie-cf.txt")


def plages():
    """Les plages de la catégorie Cf, (début, fin) inclus."""
    resultat = []
    for u in range(0x110000):
        if unicodedata.category(chr(u)) == "Cf":
            if resultat and resultat[-1][1] == u - 1:
                resultat[-1][1] = u
            else:
                resultat.append([u, u])
    return [tuple(p) for p in resultat]


def texte(version, liste):
    lignes = [f"# Catégorie Cf d'Unicode {version}, écrite par outils/table-cf.py ; une plage par ligne."]
    lignes += [f"{a:04X}" if a == b else f"{a:04X}..{b:04X}" for a, b in liste]
    return "\n".join(lignes) + "\n"


def lire(chemin):
    """(version, ensemble des points de code) de la table du dépôt."""
    version, points = None, set()
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        if ligne.startswith("#"):
            mots = ligne.split()
            if "d'Unicode" in mots:
                version = mots[mots.index("d'Unicode") + 1].rstrip(",")
            continue
        debut, _, fin = ligne.partition("..")
        points.update(range(int(debut, 16), int(fin or debut, 16) + 1))
    return version, points


def main():
    version = unicodedata.unidata_version
    liste = plages()
    if "--verifier" not in sys.argv[1:]:
        TABLE.write_text(texte(version, liste), encoding="utf-8")
        print(f"{TABLE} : Unicode {version}, {len(liste)} plages")
        return
    if not TABLE.is_file():
        print(f"{TABLE} absente : python3 outils/table-cf.py")
        sys.exit(1)
    version_table, points = lire(TABLE)
    if version_table == version:
        if TABLE.read_text(encoding="utf-8") != texte(version, liste):
            print(f"{TABLE} ne correspond plus à Unicode {version} : python3 outils/table-cf.py")
            sys.exit(1)
        return
    manquants = sorted({u for a, b in liste for u in range(a, b + 1)} - points)
    if manquants:
        noms = ", ".join(f"U+{u:04X}" for u in manquants[:10])
        print(f"Unicode {version} (ce Python) a des Cf absents de la table (Unicode {version_table}) : {noms}")
        print("Refaire la table (python3 outils/table-cf.py), puis faire passer les essais de src/ui.rs et src/protection/telechargement.rs.")
        sys.exit(1)


if __name__ == "__main__":
    main()
