#!/usr/bin/env python3
"""Les nombres que les README annoncent, comparés à ceux comptés dans le code, en français et en anglais : un nombre
tapé à la main vieillit sans que personne le voie, et la page d'accueil du dépôt dirait alors autre chose que le code.

Nombres gardés : les règles du bilan (toutes, Linux, Windows), les modules qui refusent l'unsafe sans recours, les
règles YARA de ReversingLabs (le nombre exact ; « plus de N », jamais plus que le vrai), les comptes d'unsafe de
la section « Le code », et les cibles de fuzzing (les fichiers de fuzz/fuzz_targets/). Les règles, les modules et le
YARA viennent de outils/page-fonctions.py, le même calcul que la page des fonctions ; l'unsafe, du même calcul que
outils/verifier.sh (compte_unsafe), et outils/essais-chiffres-readme.sh vérifie que les deux disent pareil.

    python3 -I outils/chiffres-readme.py                    les deux README du dépôt
    python3 -I outils/chiffres-readme.py --lisez-moi FR EN  deux autres fichiers (essais), comptés contre ce code
    python3 -I outils/chiffres-readme.py --unsafe           les cinq comptes d'unsafe seulement (essais)

Code 0 : chaque nombre suit le code. 1 : un nombre a vieilli (nommé, avec le bon). 2 : une phrase attendue est
introuvable, ou un compte est impossible : rien n'est conclu, jamais un vert. Lancé par outils/verifier.sh (étape
« chiffres-readme »).
"""
import argparse
import importlib.util
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def page_fonctions():
    """outils/page-fonctions.py, chargé par son chemin (son nom a un tiret)."""
    spec = importlib.util.spec_from_file_location("page_fonctions", RACINE / "outils/page-fonctions.py")
    if spec is None or spec.loader is None:
        sys.exit(2)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unsafe() -> list[int]:
    """Les cinq comptes de compte_unsafe (outils/verifier.sh) : les lignes de src/ qui contiennent « unsafe », sans
    celles qui commencent par un commentaire, et chaque forme précédée d'autre chose qu'une lettre, un chiffre ou _."""
    lignes = [ligne for f in sorted((RACINE / "src").rglob("*.rs"))
              for ligne in f.read_text(encoding="utf-8").splitlines()
              if "unsafe" in ligne and not re.match(r"\s*//", ligne)]

    def forme(motif: str) -> int:
        return sum(len(re.findall(r"(?:^|[^_\w])" + motif, ligne)) for ligne in lignes)

    return [forme(r"unsafe \{"), forme("unsafe extern"), forme("unsafe fn"), forme("unsafe impl"),
            forme(r"#\[unsafe\(")]


def cibles_fuzz() -> int:
    """Les cibles du banc de fuzzing : un fichier .rs chacune dans fuzz/fuzz_targets/."""
    return len(list((RACINE / "fuzz/fuzz_targets").glob("*.rs")))


# Chaque phrase attendue, par langue : son motif (les espaces peuvent être des retours à la ligne du Markdown) et les
# nombres qu'elle doit porter, dans l'ordre de ses groupes. Chaque occurrence est vérifiée ; il en faut au moins une.
def phrases(r: dict[str, int], s: dict[str, int], u: list[int]) -> dict[str, list[tuple[str, str, list[int]]]]:
    regles = [r["REGLES"], r["REGLES_LINUX"], r["REGLES_WINDOWS"]]
    fuzz = [cibles_fuzz()]
    return {
        "fr": [
            ("règles du bilan", r"(\d+) règles à identifiant stable \(`[^`]+`\) : (\d+) sous Linux, (\d+) sous Windows",
             regles),
            ("modules sans unsafe", r"refusé sans recours \(`forbid`\) dans (\d+) modules", [s["FORBID"]]),
            ("comptes d'unsafe", r"(\d+) blocs `unsafe`, (\d+) blocs `unsafe extern`, (\d+) fonctions, (\d+) `impl` et"
             r" (\d+) attributs? `#\[unsafe\(…\)\]`", u),
            ("règles YARA", r"(?<!plus\sde\s)(?<!\d)(\d+) règles de ReversingLabs", [s["YARA"]]),
            ("cibles de fuzzing", r"(\d+) cibles de fuzzing", fuzz),
        ],
        "en": [
            ("règles du bilan", r"(\d+) rules with a stable identifier \(`[^`]+`\): (\d+) on Linux, (\d+) on Windows",
             regles),
            ("modules sans unsafe", r"refused with no way back \(`forbid`\) in (\d+) modules", [s["FORBID"]]),
            ("comptes d'unsafe", r"(\d+) `unsafe` blocks, (\d+) `unsafe extern` blocks, (\d+) functions, (\d+) `impl`"
             r" and (\d+) `#\[unsafe\(…\)\]` attributes?", u),
            ("règles YARA", r"(?<!over\s)(?<!\d)(\d+) ReversingLabs rules", [s["YARA"]]),
            ("cibles de fuzzing", r"(\d+) fuzzing targets", fuzz),
        ],
    }


# « plus de N règles » : N arrondi, jamais au-dessus du vrai nombre.
AU_MOINS = {"fr": r"plus de (\d+) règles", "en": r"over (\d+) (?:ReversingLabs )?rules"}


def juger(langue: str, nom_fichier: str, texte: str, attendues, yara: int) -> tuple[list[str], list[str]]:
    vieillis, introuvables = [], []
    for quoi, motif, bons in attendues:
        trouvees = list(re.finditer(motif.replace(" ", r"\s+"), texte))
        if not trouvees:
            introuvables.append(f"{nom_fichier} : phrase « {quoi} » introuvable (le texte a changé de forme ?)")
        for m in trouvees:
            ecrits = [int(g) for g in m.groups()]
            if ecrits != bons:
                ligne = texte.count("\n", 0, m.start()) + 1
                vieillis.append(f"{nom_fichier}:{ligne} : {quoi} : {ecrits} écrit, {bons} dans le code")
    for m in re.finditer(AU_MOINS[langue].replace(" ", r"\s+"), texte):
        if int(m.group(1)) > yara:
            ligne = texte.count("\n", 0, m.start()) + 1
            vieillis.append(f"{nom_fichier}:{ligne} : « plus de {m.group(1)} » règles, {yara} dans le code")
    return vieillis, introuvables


def main() -> None:
    a = argparse.ArgumentParser(description="Les nombres des README comparés au code.")
    a.add_argument("--lisez-moi", nargs=2, type=Path, metavar=("FR", "EN"),
                   default=(RACINE / "README.md", RACINE / "README.en.md"))
    a.add_argument("--unsafe", action="store_true")
    args = a.parse_args()
    u = unsafe()
    if args.unsafe:
        print(" ".join(map(str, u)))
        return
    if not any(u):
        print("✖ aucun unsafe compté dans src/ : rien n'est conclu")
        sys.exit(2)
    pf = page_fonctions()
    r, s = pf.regles(), pf.securite()
    attendues = phrases(r, s, u)
    vieillis, introuvables = [], []
    for langue, fichier in zip(("fr", "en"), args.lisez_moi):
        try:
            texte = fichier.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as e:
            introuvables.append(f"{fichier} illisible : {e}")
            continue
        v, i = juger(langue, fichier.name, texte, attendues[langue], s["YARA"])
        vieillis += v
        introuvables += i
    for ligne in vieillis + introuvables:
        print(f"✖ {ligne}")
    if introuvables:
        sys.exit(2)
    if vieillis:
        sys.exit(1)
    print(f"README : règles {r['REGLES']} ({r['REGLES_LINUX']} Linux, {r['REGLES_WINDOWS']} Windows), forbid "
          f"{s['FORBID']}, YARA {s['YARA']}, unsafe {' '.join(map(str, u))}, fuzz {cibles_fuzz()} : "
          "à jour dans les deux langues")


if __name__ == "__main__":
    main()
