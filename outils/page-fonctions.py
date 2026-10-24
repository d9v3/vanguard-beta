#!/usr/bin/env python3
"""Remplit la page des fonctions de Vanguard (outils/page-fonctions.html) pour la version à publier.

La page est refaite à chaque version par outils/deployer.sh (docs/index.html, servie par GitHub Pages) et publiée
sur claude.ai par la skill /livrer : ce script en remplit les trous, à partir du code et des vérifications, et écrit
la page prête. Rien n'est envoyé d'ici.
  - version et date : Cargo.toml et le jour ;
  - lignes de Rust : src/ et tests/, sans les commentaires ni les lignes vides ;
  - règles du bilan par système et fiches de l'audit du réseau : comptées dans le code (src/) ;
  - commandes en ligne : le programme les dit lui-même (« vanguard --help », en français), la liste comprise ;
  - commandes du guide : le programme les compte lui-même (« vanguard guide » sans terminal, hors ligne) ;
  - tests Linux et Wine : le résumé de la dernière vérification (outils/verifier.sh l'écrit dans
    ~/.cache/vanguard-dev/verifier-dernier.txt), ou --verifier SORTIE, ou les nombres donnés ;
  - vérifications sur le vrai Windows : la dernière passe réussie de la VM (historique.txt).

    python3 outils/page-fonctions.py [--complet] [--programme VANGUARD] [--sortie PAGE]
    python3 outils/page-fonctions.py --verifier SORTIE --tests-linux 693 --tests-wine 613 --version 0.82.0

--complet : un document HTML entier (doctype, head, body), pour GitHub Pages ; sans lui, le fragment que
claude.ai habille lui-même.
"""
import argparse
import datetime
import html
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
RESUME_VERIFICATION = Path.home() / ".cache/vanguard-dev/verifier-dernier.txt"
MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre",
        "décembre"]


def version() -> str:
    m = re.search(r'^version = "([^"]+)"', (RACINE / "Cargo.toml").read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit("✖ pas de version dans Cargo.toml")
    return m.group(1)


def milliers(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def lignes_de_rust() -> str:
    total = 0
    for dossier in ("src", "tests"):
        for f in (RACINE / dossier).rglob("*.rs"):
            for ligne in f.read_text(encoding="utf-8").splitlines():
                l = ligne.strip()
                if l and not l.startswith("//"):
                    total += 1
    # Arrondi à la centaine : « ≈ 83 500 », un ordre de grandeur, pas un compte qui bouge à chaque commit.
    return milliers(round(total, -2))


def regles() -> dict[str, int]:
    """Les règles du bilan déclarées dans le code, par système (Os::Linux, Windows, MacOs, Tous), et les fiches
    de l'audit du réseau (src/audit/fiches.rs) : comptées à la source, pas tapées à la main."""
    ids: dict[str, set[str]] = defaultdict(set)
    for f in (RACINE / "src").rglob("*.rs"):
        texte = f.read_text(encoding="utf-8")
        if "Os::" not in texte:
            continue
        for m in re.finditer(r'"([A-Z]{3}-[A-Z]{3}-\d{3})"\s*,\s*(?:systeme:\s*)?Os::(\w+)', texte):
            ids[m.group(2)].add(m.group(1))
        for m in re.finditer(r'id:\s*"([A-Z]{3}-[A-Z]{3}-\d{3})",\s*systeme:\s*Os::(\w+)', texte):
            ids[m.group(2)].add(m.group(1))
    linux, windows, macos, communes = (len(ids[s]) for s in ("Linux", "Windows", "MacOs", "Tous"))
    if not (linux and windows and macos and communes):
        sys.exit("✖ règles du bilan introuvables dans src/ (la déclaration a changé de forme ?)")
    fiches_rs = RACINE / "src/audit/fiches.rs"
    fiches = len(set(re.findall(r'"(COM-[A-Z]{3}-\d{3})"', fiches_rs.read_text(encoding="utf-8")))) \
        if fiches_rs.is_file() else 0
    return {
        "REGLES": linux + windows + macos + communes,
        "REGLES_COMMUNES": communes,
        "REGLES_LINUX_SEULES": linux, "REGLES_WINDOWS_SEULES": windows, "REGLES_MACOS_SEULES": macos,
        "REGLES_LINUX": linux + communes, "REGLES_WINDOWS": windows + communes, "REGLES_MACOS": macos + communes,
        "FICHES": fiches,
    }


def lancer(programme: Path, *arguments: str) -> str:
    """Le programme lancé dans un dossier personnel jetable, hors ligne, en français : rien de l'ordinateur n'y
    passe, et le texte revient sans ses couleurs."""
    with tempfile.TemporaryDirectory(prefix="page-fonctions-", dir=Path.home() / ".cache") as maison:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": maison, "XDG_DATA_HOME": f"{maison}/d",
               "XDG_CACHE_HOME": f"{maison}/c", "USER": "essai", "VANGUARD_HORS_LIGNE": "1", "VANGUARD_LANG": "fr"}
        r = subprocess.run([str(programme), *arguments], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=60, env=env, cwd=maison)
    return re.sub(r"\x1b\[[0-9;]*m", "", r.stdout)


def commandes_du_guide(programme: Path) -> str:
    """Le total affiché en tête du guide."""
    m = re.search(r"(\d+) commandes", lancer(programme, "guide"))
    if not m:
        sys.exit(f"✖ le guide n'a pas donné son nombre de commandes ({programme})")
    return milliers(int(m.group(1)))


def commandes_en_ligne(programme: Path) -> tuple[int, str]:
    """Les commandes de « vanguard help » (la liste de clap ; « --help » les range en rubriques) : leur nombre et la liste prête pour la page (nom, alias anglais,
    description), dans l'ordre du programme. Un description est coupée à la première phrase ou à 110 caractères."""
    aide = lancer(programme, "help")
    bloc = re.search(r"^Commands:\n(.*?)^Options:", aide, re.S | re.M)
    if not bloc:
        sys.exit(f"✖ « help » n'a pas donné sa liste de commandes ({programme})")
    entrees = []
    for ligne in bloc.group(1).splitlines():
        m = re.match(r"  ([a-z][a-z0-9-]*)\s+(.*)", ligne)
        if not m or m.group(1) == "help":
            continue
        nom, description = m.group(1), m.group(2).strip()
        alias = re.search(r"\[alias: ([^\]]+)\]", description)
        description = re.sub(r"\s*\[alias: [^\]]+\]", "", description)
        # La première phrase suffit sur la page ; le menu et « --help » gardent le reste.
        phrase = re.split(r"(?<=[.!?])\s", description, maxsplit=1)[0]
        if len(phrase) > 110:
            phrase = phrase[:108].rsplit(" ", 1)[0] + "…"
        entrees.append((nom, alias.group(1) if alias else "", phrase))
    if len(entrees) < 30:
        sys.exit(f"✖ « --help » ne donne que {len(entrees)} commandes : le texte a changé de forme ?")
    lignes = []
    for nom, alias, phrase in entrees:
        a = f" <i>{html.escape(alias)}</i>" if alias else ""
        lignes.append(f"        <div><dt>{html.escape(nom)}{a}</dt><dd>{html.escape(phrase)}</dd></div>")
    return len(entrees), "\n".join(lignes)


def tests(args) -> tuple[str, str]:
    linux, wine = args.tests_linux, args.tests_wine
    source = args.verifier or (RESUME_VERIFICATION if RESUME_VERIFICATION.is_file() else None)
    if source and not (linux and wine):
        texte = Path(source).read_text(encoding="utf-8")
        # « tests Linux (1544) », ou « tests Linux (1544, 12 sautés) » : les tests passés, les sautés non comptés.
        l = re.search(r"tests Linux \((\d+)[,)]", texte)
        w = re.search(r"tests Windows sous Wine \((\d+)[,)]", texte)
        linux = linux or (l and int(l.group(1)))
        wine = wine or (w and int(w.group(1)))
    if not linux or not wine:
        sys.exit("✖ nombres de tests inconnus : lance outils/verifier.sh (il écrit son résumé dans "
                 f"{RESUME_VERIFICATION}), ou donne --verifier SORTIE, ou --tests-linux et --tests-wine")
    return milliers(linux), milliers(wine)


def verifications_vm() -> str:
    historique = Path.home() / "Windows/VANGUARD-TEST/resultats/historique.txt"
    nombres = re.findall(r"OK, tout est passé \((\d+) vérifications", historique.read_text(encoding="utf-8",
                                                                                         errors="replace"))
    if not nombres:
        sys.exit("✖ aucune passe réussie de la VM dans historique.txt")
    return nombres[-1]


def alleger(page: str) -> str:
    """La page publiée sans ce qui ne sert qu'à la tenir : commentaires HTML et CSS, indentation et lignes vides. Les
    blocs <pre> gardent leurs espaces, qui y sont le texte même."""
    morceaux = re.split(r"(<pre\b.*?</pre>)", page, flags=re.S)
    for i in range(0, len(morceaux), 2):
        m = re.sub(r"<!--.*?-->", "", morceaux[i], flags=re.S)
        m = re.sub(r"/\*.*?\*/", "", m, flags=re.S)
        m = re.sub(r"\n[ \t]+", "\n", m)
        morceaux[i] = re.sub(r"\n{2,}", "\n", m)
    return "".join(morceaux)


def document_entier(fragment: str) -> str:
    """Le fragment (title, meta, style, puis le corps) habillé en document complet, comme claude.ai le fait pour
    l'artefact : nécessaire pour GitHub Pages, qui sert le fichier tel quel."""
    i = fragment.index('<div class="ouverture">')
    tete, corps = fragment[:i], fragment[i:]
    return ('<!doctype html>\n<html lang="fr">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"{tete}</head>\n<body>\n{corps}</body>\n</html>\n")


def main():
    a = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument("--verifier", help="sortie de outils/verifier.sh (nombres de tests) ; sinon son dernier résumé")
    a.add_argument("--tests-linux", type=int)
    a.add_argument("--tests-wine", type=int)
    a.add_argument("--programme", type=Path,
                   default=RACINE / "target/x86_64-unknown-linux-musl/release/vanguard")
    a.add_argument("--sortie", type=Path, default=Path.home() / ".cache/vanguard-dev/page-fonctions.html")
    a.add_argument("--version", help="la version à montrer, avant que Cargo.toml la porte (un aperçu)")
    a.add_argument("--complet", action="store_true", help="un document HTML entier (GitHub Pages)")
    args = a.parse_args()
    if not args.programme.is_file():
        sys.exit(f"✖ programme introuvable : {args.programme} (--programme)")
    # Chemin absolu : le programme est lancé depuis un dossier personnel jetable (lancer), où un chemin relatif
    # comme celui de deployer.sh ne mène nulle part (la page de GitHub Pages en est restée à la 0.82).
    args.programme = args.programme.resolve()
    v = args.version or version()
    courte = ".".join(v.split(".")[:2])
    jour = datetime.date.today()
    nombre_cli, liste_cli = commandes_en_ligne(args.programme)
    valeurs = {
        "VERSION": v,
        "VERSION_COURTE": courte,
        # Dans la boîte du terminal (76 colonnes), le numéro garde la place d'origine : la ligne garde sa largeur
        # avec l'accroche, plus longue de deux caractères que l'ancienne.
        "VERSION_COURTE_TERMINAL": courte.ljust(14),
        "DATE": f"{jour.day} {MOIS[jour.month - 1]} {jour.year}",
        "LIGNES": lignes_de_rust(),
        "COMMANDES": commandes_du_guide(args.programme),
        "COMMANDES_CLI": str(nombre_cli),
        "COMMANDES_LISTE": liste_cli,
        "VM": verifications_vm(),
    }
    valeurs.update({cle: str(n) for cle, n in regles().items()})
    valeurs["TESTS_LINUX"], valeurs["TESTS_WINE"] = tests(args)
    page = (RACINE / "outils/page-fonctions.html").read_text(encoding="utf-8")
    page = re.sub(r"<!--.*?-->\n", "", page, count=1, flags=re.S)
    for cle, valeur in valeurs.items():
        page = page.replace("{{" + cle + "}}", valeur)
    page = alleger(page)
    reste = re.findall(r"\{\{[A-Z_]+\}\}", page)
    if reste:
        sys.exit(f"✖ trous non remplis : {', '.join(sorted(set(reste)))}")
    if args.complet:
        page = document_entier(page)
    args.sortie.parent.mkdir(parents=True, exist_ok=True)
    args.sortie.write_text(page, encoding="utf-8")
    print(f"Page des fonctions prête : {args.sortie}")
    for cle in ("VERSION", "DATE", "LIGNES", "REGLES", "FICHES", "COMMANDES_CLI", "COMMANDES", "TESTS_LINUX",
                "TESTS_WINE", "VM"):
        print(f"  {cle.lower():<13} {valeurs[cle]}")


if __name__ == "__main__":
    main()
