#!/usr/bin/env python3
"""Remplit la page des fonctions de Vanguard (outils/page-fonctions.html) pour la version à publier.

La page est refaite à chaque version par outils/deployer.sh (docs/index.html, servie par GitHub Pages) et publiée
sur claude.ai par la skill /livrer : ce script en remplit les trous, à partir du code et des vérifications, et écrit
la page prête. Rien n'est envoyé d'ici.
  - version et date : Cargo.toml et le jour ;
  - lignes de Rust : src/ et tests/, sans les commentaires ni les lignes vides ;
  - règles du bilan par système et fiches de l'audit du réseau : comptées dans le code (src/) ;
  - sécurité de Vanguard lui-même : hôtes joints en HTTPS (src/http.rs), cibles de fuzzing (fuzz/Cargo.toml),
    preuves Kani (outils/preuves/src), modules qui refusent l'unsafe sans recours (src/), cas du corpus de détection
    (tests/corpus-detection) et règles YARA intégrées (assets/yara), comptés à la source ;
  - commandes en ligne : le programme les dit lui-même (« vanguard --help », en français), la liste comprise ;
  - commandes du guide : le programme les compte lui-même (« vanguard guide » sans terminal, hors ligne) ;
  - tests Linux et Wine : le résumé de la dernière vérification (outils/verifier.sh l'écrit dans
    ~/.cache/vanguard-dev/verifier-dernier.txt), ou --verifier SORTIE, ou les nombres donnés ;
  - vérifications sur le vrai Windows : la dernière passe réussie de la VM (son menu ou la file d'essais) ;
  - captures : celles du README (assets/captures, déjà masquées par outils/captures.py), en WebP sans perte et
    intégrées à la page (data:) : une seule page, sans fichier à côté, pour GitHub Pages comme pour claude.ai. Il y
    faut Pillow (python-pillow) ;
  - visite guidée de la fenêtre : les captures de outils/captures-fenetre.sh (données inventées), prises dans
    --captures (défaut ~/.cache/vanguard-dev/captures-fenetre) ; une capture manquante arrête le rendu.

    python3 -I outils/page-fonctions.py [--complet] [--programme VANGUARD] [--sortie PAGE] [--captures DOSSIER]
    python3 -I outils/page-fonctions.py --verifier SORTIE --tests-linux 693 --tests-wine 613 --version 0.82.0

--complet : un document HTML entier (doctype, head, body), pour GitHub Pages ; sans lui, le fragment que
claude.ai habille lui-même.
"""
import argparse
import base64
import datetime
import html
import io
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
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
    """Les règles du bilan déclarées dans le code, par système (Os::Linux, Windows, Tous), et les fiches
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
    linux, windows, communes = (len(ids[s]) for s in ("Linux", "Windows", "Tous"))
    if not (linux and windows and communes):
        sys.exit("✖ règles du bilan introuvables dans src/ (la déclaration a changé de forme ?)")
    fiches_rs = RACINE / "src/audit/fiches.rs"
    fiches = len(set(re.findall(r'"(COM-[A-Z]{3}-\d{3})"', fiches_rs.read_text(encoding="utf-8")))) \
        if fiches_rs.is_file() else 0
    return {
        "REGLES": linux + windows + communes,
        "REGLES_COMMUNES": communes,
        "REGLES_LINUX_SEULES": linux, "REGLES_WINDOWS_SEULES": windows,
        "REGLES_LINUX": linux + communes, "REGLES_WINDOWS": windows + communes,
        "FICHES": fiches,
    }


def securite() -> dict[str, int]:
    """Les nombres de la section « Sécurité de Vanguard lui-même », comptés à la source comme les règles : les hôtes
    de la liste fermée `HOTES` (src/http.rs), les cibles de fuzzing (fuzz/Cargo.toml), les preuves Kani
    (outils/preuves/src), les modules qui portent `#![forbid(unsafe_code)]` en tête de ligne (comme le compte de
    outils/verifier.sh), les cas du corpus de détection et les règles YARA de ReversingLabs."""
    http = (RACINE / "src/http.rs").read_text(encoding="utf-8")
    bloc = re.search(r"^(?:pub(?:\([a-z]+\))? )?const HOTES: &\[&str\] = &\[\n(.*?)^\];", http, re.S | re.M)
    hotes = len(re.findall(r'^\s*"[^"]+",', bloc.group(1), re.M)) if bloc else 0
    fuzz = len(re.findall(r"^\[\[bin\]\]", (RACINE / "fuzz/Cargo.toml").read_text(encoding="utf-8"), re.M))
    kani = sum(f.read_text(encoding="utf-8").count("#[kani::proof]")
               for f in (RACINE / "outils/preuves/src").rglob("*.rs"))
    forbid = sum(1 for f in (RACINE / "src").rglob("*.rs")
                 if re.search(r"^#!\[forbid\(unsafe_code\)\]$", f.read_text(encoding="utf-8"), re.M))
    corpus = sum(1 for d in (RACINE / "tests/corpus-detection").iterdir() if (d / "attendu.toml").is_file())
    yara = len(re.findall(r"^rule\s", (RACINE / "assets/yara/reversinglabs.yara").read_text(encoding="utf-8"), re.M))
    if not (hotes and fuzz and kani and forbid and corpus and yara):
        sys.exit("✖ nombres de sécurité introuvables (HOTES, fuzz/Cargo.toml, preuves Kani, forbid, corpus ou règles "
                 "YARA ont changé ?)")
    return {"HOTES": hotes, "FUZZ": fuzz, "KANI": kani, "FORBID": forbid, "CORPUS": corpus, "YARA": yara}


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
    # Deux historiques : les passes du menu de la VM, et celles de la file d'essais (vm-tester.sh), qui seule essaie
    # le programme d'une version avant sa page ; la plus récente des passes réussies l'emporte, d'où qu'elle vienne.
    racine = Path.home() / "Windows/VANGUARD-TEST"
    passes: list[tuple[str, str]] = []
    for fichier, motif in (
        ("resultats/historique.txt", r"^(\d{4}-\d\d-\d\d \d\d:\d\d) .*OK, tout est passé \((\d+) vérifications"),
        ("file-essais/historique.txt", r"^(\d{4}-\d\d-\d\d \d\d:\d\d) +\S+ +ok +test (\d+)/0/0/"),
    ):
        chemin = racine / fichier
        if chemin.is_file():
            passes += re.findall(motif, chemin.read_text(encoding="utf-8", errors="replace"), re.M)
    if not passes:
        sys.exit("✖ aucune passe réussie de la VM (resultats/ ni file-essais/historique.txt)")
    return max(passes)[1]


# Les captures de la page : nom dans assets/captures, et la partie gardée (gauche, haut, droite, bas), None pour toute.
# Celle du réseau s'arrête après le premier appareil « À REGARDER », sur une ligne vide (captures.py : 22 px de marge
# en haut, puis 20 px par ligne de terminal).
CAPTURES = {
    "BILAN": ("bilan.png", None),
    "RAPPORT": ("rapport.png", None),
    "RESEAU": ("reseau.png", (0, 0, 780, 22 + 36 * 20)),
}


# La visite guidée de la fenêtre (section « Prise en main ») : une capture par étape, rendue par
# outils/captures-fenetre.sh avec des données inventées (alice, Salon, adresses de documentation), hors du dépôt.
# Thème sombre seulement : les deux thèmes doubleraient le poids de la page (plus de 2 Mo, au lieu d'environ 1,3).
CAPTURES_FENETRE = Path.home() / ".cache/vanguard-dev/captures-fenetre"
VISITE = {
    "ACCUEIL": "accueil-fr-sombre-1280x800.png",
    "BILAN": "bilan-fr-sombre-1280x800.png",
    "APERCU": "gestes/apercu-lu-fr-sombre-1280x800.png",
    "FAIT": "gestes/fait-fr-sombre-1280x800.png",
    "REMETTRE": "gestes/remettre-fr-sombre-1280x800.png",
    "ALERTES": "alertes-fr-sombre-1280x800.png",
    "APPAREILS": "appareils-fr-sombre-1280x800.png",
    "ORDINATEUR": "rubrique-cet-ordinateur-fr-sombre-1280x800.png",
    "RESEAU": "rubrique-reseau-et-internet-fr-sombre-1280x800.png",
    "VIRUS": "rubrique-virus-et-logiciels-espions-fr-sombre-1280x800.png",
    "ARNAQUES": "rubrique-arnaques-et-vie-privee-fr-sombre-1280x800.png",
    "BLOQUER": "rubrique-bloquer-et-reagir-fr-sombre-1280x800.png",
    "OPTIMISER": "rubrique-optimiser-et-installer-fr-sombre-1280x800.png",
    "VANGUARD": "rubrique-vanguard-fr-sombre-1280x800.png",
    "GUIDE": "guide-fr-sombre-1280x800.png",
    "COMMANDE": "commande-connexions-sortantes-fr-sombre-1280x800.png",
    "CONSOLE": "console/suggestion-sombre.png",
    "RECHERCHE": "console/recherche-ssh-sombre.png",
}


def _webp(image, prefixe: str) -> dict[str, str]:
    """Une image en data: URI (WebP sans perte : le texte reste net, quatre fois plus léger que le PNG), avec sa
    largeur et sa hauteur pour que la page ne saute pas au chargement."""
    image = image.convert("RGB")
    tampon = io.BytesIO()
    image.save(tampon, "WEBP", lossless=True, method=6)
    return {prefixe: "data:image/webp;base64," + base64.b64encode(tampon.getvalue()).decode("ascii"),
            f"{prefixe}_L": str(image.width), f"{prefixe}_H": str(image.height)}


def captures(dossier_fenetre: Path = CAPTURES_FENETRE) -> dict[str, str]:
    """Les captures du README (CAPTURE_*) et celles de la visite guidée (VISITE_*), prises dans dossier_fenetre.
    Une capture de la visite qui manque arrête tout : jamais une page à trous."""
    try:
        from PIL import Image
    except ImportError:
        sys.exit("✖ Pillow manque pour intégrer les captures (python-pillow, ou pip install pillow)")
    manquantes = [nom for nom in VISITE.values() if not (dossier_fenetre / nom).is_file()]
    if manquantes:
        sys.exit(f"✖ {len(manquantes)} capture(s) de la fenêtre manquent dans {dossier_fenetre} "
                 f"({', '.join(manquantes[:3])}{' …' if len(manquantes) > 3 else ''}) : lancez "
                 "outils/captures-fenetre.sh (ou donnez le bon dossier par --captures)")
    valeurs = {}
    for cle, (nom, partie) in CAPTURES.items():
        with Image.open(RACINE / "assets/captures" / nom) as image:
            valeurs |= _webp(image.crop(partie) if partie else image, f"CAPTURE_{cle}")
    for cle, nom in VISITE.items():
        with Image.open(dossier_fenetre / nom) as image:
            valeurs |= _webp(image, f"VISITE_{cle}")
    return valeurs


# ── Jetons de design : les couleurs de la fenêtre de Vanguard, lues au rendu ──────────────────────────────────────
# La page reprend le préréglage « Vanguard » de la fenêtre (le premier de PREREGLAGES, fenetre/src/couleurs.rs) et
# le trait, l'ombre et le rayon des cartes (fenetre/src/dessin/mod.rs). Lus à chaque rendu : la page suit la fenêtre
# sans valeur recopiée à la main. Une forme inattendue arrête le rendu (pas de vieux repli silencieux).
NEUTRES = ("fond", "surface", "s2", "s3", "encre", "doux", "discret")
VIFS = ("accent", "grave", "moyen", "jaune", "bon")
AA = 4.5  # WCAG AA, texte courant


def _hex(rgb) -> str:
    return "#" + "".join(f"{c:02x}" for c in rgb)


def _rgb(x: str) -> tuple[int, int, int]:
    n = int(x, 16)
    return (n >> 16) & 255, (n >> 8) & 255, n & 255


def _luminance(rgb) -> float:
    def lin(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contraste(a, b) -> float:
    """Le contraste WCAG, la même formule que couleurs::contraste de la fenêtre."""
    x, y = _luminance(a), _luminance(b)
    return (max(x, y) + 0.05) / (min(x, y) + 0.05)


def lisible(couleur, fonds, encre):
    """La couleur telle quelle si elle tient 4,5:1 sur chaque fond ; sinon rapprochée de l'encre, pas à pas, juste
    assez pour y arriver. La fenêtre vise d'autres contrastes (gros texte, icônes) : la page, elle, écrit du texte
    courant dans ces couleurs."""
    for i in range(51):
        k = i / 50
        c = tuple(round(u + (v - u) * k) for u, v in zip(couleur, encre))
        if all(contraste(c, f) >= AA for f in fonds):
            return c
    return encre


def palettes(couleurs_rs: str) -> tuple[dict, dict]:
    """(sombre, clair) du préréglage « Vanguard » : le premier couple de PREREGLAGES."""
    bloc = re.search(r"const PREREGLAGES: \[\(Prereglage, Prereglage\); \d+\] = \[(.*?)^\];", couleurs_rs, re.S | re.M)
    if not bloc:
        sys.exit("✖ PREREGLAGES introuvable dans fenetre/src/couleurs.rs (la table a changé de forme ?)")
    jeux = re.findall(r"p\(\s*\[([^\]]*)\],\s*\[([^\]]*)\],?\s*\)", bloc.group(1))
    if len(jeux) < 2:
        sys.exit("✖ le préréglage « Vanguard » (sombre, clair) est illisible dans fenetre/src/couleurs.rs")
    resultat = []
    for neutres, vifs in jeux[:2]:
        n = re.findall(r"0x([0-9a-fA-F]{6})", neutres)
        v = re.findall(r"0x([0-9a-fA-F]{6})", vifs)
        if len(n) != len(NEUTRES) or len(v) != len(VIFS):
            sys.exit(f"✖ préréglage « Vanguard » : {len(n)} neutres et {len(v)} vives au lieu de "
                     f"{len(NEUTRES)} et {len(VIFS)} (fenetre/src/couleurs.rs)")
        resultat.append(dict(zip(NEUTRES + VIFS, (_rgb(x) for x in n + v))))
    return resultat[0], resultat[1]


def traits(dessin_rs: str) -> dict:
    """Le trait des cartes et leur ombre (sombre, clair : rgba prémultipliés dans palette_de) et le rayon des cartes."""
    rgba = re.findall(r"Color32::from_rgba_premultiplied\((\d+), (\d+), (\d+), (\d+)\)", dessin_rs)
    rayon = re.search(r"^pub const RAYON_CARTE: u8 = (\d+);", dessin_rs, re.M)
    if len(rgba) != 4 or not rayon:
        sys.exit("✖ trait, ombre ou RAYON_CARTE introuvables dans fenetre/src/dessin/mod.rs (forme changée ?)")

    def droit(r, g, b, a):
        r, g, b, a = (int(x) for x in (r, g, b, a))
        if not a:
            return "transparent"
        return f"rgba({min(255, round(r * 255 / a))}, {min(255, round(g * 255 / a))}, {min(255, round(b * 255 / a))}, {a / 255:.3f})"
    return {"trait_sombre": droit(*rgba[0]), "ombre_sombre": droit(*rgba[1]), "trait_clair": droit(*rgba[2]),
            "ombre_clair": droit(*rgba[3]), "rayon": int(rayon.group(1))}


def sur_vif(accent):
    """L'encre posée sur l'accent (couleurs::sur_vif) : noire ou blanche, celle qui contraste le plus."""
    return (0, 0, 0) if contraste(accent, (0, 0, 0)) >= contraste(accent, (255, 255, 255)) else (255, 255, 255)


def jetons(couleurs_rs: str, dessin_rs: str) -> dict[str, str]:
    """Les jetons de la page : le bloc CSS des deux thèmes (JETONS) et les fonds pour theme-color."""
    sombre, clair = palettes(couleurs_rs)
    t = traits(dessin_rs)

    def bloc(p, trait_, ombre, sombre_):
        fonds = (p["fond"], p["surface"], p["s2"])
        d = {
            "fond": _hex(p["fond"]), "surface": _hex(p["surface"]), "surface-2": _hex(p["s2"]),
            "surface-3": _hex(p["s3"]), "encre": _hex(p["encre"]),
            "doux": _hex(lisible(p["doux"], fonds, p["encre"])),
            "discret": _hex(lisible(p["discret"], fonds, p["encre"])),
            "trait": trait_, "trait-fort": _hex(p["s3"]),
            "accent": _hex(p["accent"]), "sur-accent": _hex(sur_vif(p["accent"])),
            "lien": _hex(lisible(p["accent"], fonds, p["encre"])),
            "bon": _hex(lisible(p["bon"], fonds, p["encre"])),
            "moyen": _hex(p["moyen"]), "grave": _hex(p["grave"]),
            "ombre": f"0 4px 18px {ombre}",
        }
        corps = "; ".join(f"--{k}: {v}" for k, v in d.items())
        return corps + ("; color-scheme: dark" if sombre_ else "")

    s = bloc(sombre, t["trait_sombre"], t["ombre_sombre"], True)
    c = bloc(clair, t["trait_clair"], t["ombre_clair"], False)
    css = (f":root {{ {c}; --rayon: {t['rayon']}px; }}\n"
           f"@media (prefers-color-scheme: dark) {{ :root:not([data-theme=\"light\"]) {{ {s}; }} }}\n"
           f":root[data-theme=\"dark\"] {{ {s}; }}")
    return {"JETONS": css, "FOND_CLAIR": _hex(clair["fond"]), "FOND_SOMBRE": _hex(sombre["fond"])}


# ── « À venir » : les cases non cochées du ticket public d9v3/vanguard-beta#1 ──────────────────────────────────────
# Le texte du ticket est une donnée : échappé avant toute mise en forme (gras, code, liens réduits à leur texte),
# jamais interprété ; passé par outils/confidentialite.py --texte avant d'entrer dans la page. Sans gh, sans Internet
# ou refusé, la section le dit au lieu d'échouer ou d'inventer.
TICKET = "d9v3/vanguard-beta"
TICKET_URL = f"https://github.com/{TICKET}/issues/1"
LONGUEUR_PISTE = 220


def lire_ticket(fichier: Path | None) -> tuple[str | None, str]:
    """(texte, raison) : le texte du ticket, ou None et pourquoi il n'a pas pu être lu."""
    if fichier:
        return fichier.read_text(encoding="utf-8"), ""
    if os.environ.get("VANGUARD_HORS_LIGNE"):
        return None, "hors ligne"
    try:
        r = subprocess.run(["gh", "issue", "view", "1", "-R", TICKET, "--json", "body", "-q", ".body"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=40)
    except FileNotFoundError:
        return None, "gh absent"
    except subprocess.TimeoutExpired:
        return None, "GitHub n'a pas répondu"
    if r.returncode != 0 or not r.stdout.strip():
        return None, "GitHub n'a pas donné le ticket"
    return r.stdout, ""


def _en_ligne(md: str) -> str:
    """Une ligne de Markdown du ticket en HTML sûr : échappée d'abord, puis gras, code et liens (le texte seul)."""
    t = html.escape(md, quote=True)
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    return t


def _court(md: str) -> str:
    """Une piste ramenée à LONGUEUR_PISTE signes, coupée à un mot, sans laisser un gras ou un code ouvert."""
    if len(md) <= LONGUEUR_PISTE:
        return md
    # À la fin d'une phrase si elle tombe assez loin ; sinon à un mot.
    fin = max(md.rfind(". ", 0, LONGUEUR_PISTE), md.rfind(" ; ", 0, LONGUEUR_PISTE))
    t = md[:fin + 1].rstrip() if fin >= 80 else md[:LONGUEUR_PISTE].rsplit(" ", 1)[0].rstrip(" ,;:(")
    if t.count("**") % 2:
        t += "**"
    if t.count("`") % 2:
        t += "`"
    return t + " …"


def pistes(texte: str) -> list[tuple[str, list[str]]]:
    """Les groupes (titre ###) de « ## À améliorer » et leurs cases non cochées, dans l'ordre du ticket."""
    m = re.search(r"^## À améliorer\s*$(.*?)(?=^## |\Z)", texte, re.S | re.M)
    if not m:
        return []
    groupes: list[tuple[str, list[str]]] = []
    for ligne in m.group(1).splitlines():
        if ligne.startswith("### "):
            groupes.append((ligne[4:].strip(), []))
        elif (case := re.match(r"\s*- \[ \] (.+)", ligne)) and groupes:
            groupes[-1][1].append(case.group(1).strip())
    return [(g, cases) for g, cases in groupes if cases]


def confidentiel(texte: str) -> bool:
    """Vrai si outils/confidentialite.py refuse ce texte (ou ne peut pas le lire) : rien n'entre dans la page."""
    try:
        r = subprocess.run([sys.executable, str(RACINE / "outils/confidentialite.py"), "--texte"], input=texte,
                           capture_output=True, text=True, timeout=120, cwd=RACINE)
    except (OSError, subprocess.TimeoutExpired):
        return True
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
    return r.returncode != 0


def a_venir(fichier: Path | None = None) -> str:
    """Le corps de la section « À venir » (HTML), ou la phrase qui dit pourquoi la liste n'est pas là."""
    lien = f'<a href="{TICKET_URL}">ticket public n° 1</a>'
    texte, raison = lire_ticket(fichier)
    groupes = pistes(texte) if texte else []
    if texte and not groupes:
        raison = "aucune case ouverte trouvée"
    if groupes and confidentiel("\n".join(f"{g}\n" + "\n".join(c) for g, c in groupes)):
        print("⚠ « À venir » : le texte du ticket a été refusé par outils/confidentialite.py, section laissée vide",
              file=sys.stderr)
        groupes, raison = [], "vérification de confidentialité refusée"
    if not groupes:
        return (f'<p class="note indisponible">La liste des pistes n\'est pas disponible dans cette page '
                f"({html.escape(raison)}). Elle se lit sur le {lien}. <span lang=\"en\">The list of upcoming work "
                f"is not available here; see public issue #1.</span></p>")
    total = sum(len(c) for _, c in groupes)
    morceaux = [f'<p class="note">{total} pistes encore ouvertes, tirées du {lien} « Fonctions et pistes '
                f"d'amélioration » au moment de cette page. Sans date ni promesse. <span lang=\"en\">{total} open "
                f"items from public issue #1, no date or promise.</span></p>", '<div class="pistes">']
    for titre, cases in groupes:
        ouvert = " open" if titre.lower().startswith("prochaine") else ""
        lignes = "\n".join(f"<li>{_en_ligne(_court(c))}</li>" for c in cases)
        morceaux.append(f'<details class="replie"{ouvert}><summary><span>{_en_ligne(titre)}</span>'
                        f'<span class="compte">{len(cases)}</span></summary>\n<ul class="liste">\n{lignes}\n</ul>'
                        "</details>")
    morceaux.append("</div>")
    return "\n".join(morceaux)


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


def remplir(gabarit: str, valeurs: dict[str, str]) -> str:
    """Le gabarit allégé, puis ses trous remplis en un seul passage : un texte venu d'ailleurs (le ticket) n'est ni
    allégé ni relu comme un trou, même s'il contient « {{VERSION}} » ou « /* … */ »."""
    page = alleger(re.sub(r"<!--.*?-->\n", "", gabarit, count=1, flags=re.S))
    reste = sorted(set(re.findall(r"\{\{([A-Z_]+)\}\}", page)) - valeurs.keys())
    if reste:
        sys.exit(f"✖ trous non remplis : {', '.join(reste)}")
    return re.sub(r"\{\{([A-Z_]+)\}\}", lambda m: valeurs[m.group(1)], page)


def document_entier(fragment: str) -> str:
    """Le fragment (title, meta, style, puis le corps) habillé en document complet, comme claude.ai le fait pour
    l'artefact : nécessaire pour GitHub Pages, qui sert le fichier tel quel."""
    i = fragment.index('<header class="barre-app"')
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
    a.add_argument("--captures", type=Path, default=CAPTURES_FENETRE,
                   help="dossier des captures de la fenêtre (outils/captures-fenetre.sh) ; défaut : %(default)s")
    a.add_argument("--ticket", type=Path, help="le texte du ticket n° 1 lu dans ce fichier (aperçu, essais) ; "
                   "sinon par gh, ou la section dit qu'il n'est pas disponible")
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
        "DATE": f"{jour.day} {MOIS[jour.month - 1]} {jour.year}",
        "LIGNES": lignes_de_rust(),
        "COMMANDES": commandes_du_guide(args.programme),
        "COMMANDES_CLI": str(nombre_cli),
        "COMMANDES_LISTE": liste_cli,
        "VM": verifications_vm(),
    }
    valeurs.update({cle: str(n) for cle, n in regles().items()})
    valeurs.update({cle: str(n) for cle, n in securite().items()})
    valeurs["TESTS_LINUX"], valeurs["TESTS_WINE"] = tests(args)
    valeurs.update(jetons((RACINE / "fenetre/src/couleurs.rs").read_text(encoding="utf-8"),
                          (RACINE / "fenetre/src/dessin/mod.rs").read_text(encoding="utf-8")))
    valeurs["A_VENIR"] = a_venir(args.ticket)
    images = captures(args.captures)
    page = remplir((RACINE / "outils/page-fonctions.html").read_text(encoding="utf-8"), valeurs | images)
    # Un « � », un invisible ou un caractère de contrôle écrit tel quel : l'outil Artifact refuse la page (0.94, U+FFFD
    # de « Textes piégés »), et un invisible dans une page publique trompe le lecteur. Ils s'écrivent en entité (&#xFFFD;).
    for numero, ligne in enumerate(page.splitlines(), 1):
        for car in ligne:
            if car == "\ufffd" or (unicodedata.category(car) in ("Cc", "Cf", "Co", "Cs") and car != "\t"):
                sys.exit(f"✖ caractère U+{ord(car):04X} écrit tel quel, ligne {numero} de la page (gabarit ou "
                         f"texte du ticket) : l'écrire en entité (&#x{ord(car):X};)")
    if args.complet:
        page = document_entier(page)
    args.sortie.parent.mkdir(parents=True, exist_ok=True)
    args.sortie.write_text(page, encoding="utf-8")
    print(f"Page des fonctions prête : {args.sortie}")
    for cle in ("VERSION", "DATE", "LIGNES", "REGLES", "FICHES", "HOTES", "FUZZ", "KANI", "FORBID", "CORPUS", "YARA",
                "COMMANDES_CLI", "COMMANDES", "TESTS_LINUX", "TESTS_WINE", "VM"):
        print(f"  {cle.lower():<13} {valeurs[cle]}")
    poids = sum(len(v) for c, v in images.items() if not c.endswith(("_L", "_H")))
    print(f"  {'captures':<13} {len(CAPTURES) + len(VISITE)}, {poids // 1024} Ko ; page {len(page.encode()) // 1024} Ko")


if __name__ == "__main__":
    main()
