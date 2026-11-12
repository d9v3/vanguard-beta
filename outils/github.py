#!/usr/bin/env python3
"""La page du dépôt sur GitHub tenue à jour toute seule : nom, description et version, lien, sujets, options.

Ce qui est voulu est écrit dans le dépôt, jamais seulement sur GitHub : le nom du programme et sa version
(Cargo.toml), et .github/depot.json (description en anglais, sans la version, que ce script ajoute au bout :
« … · v0.52.0 », celle de la dernière page publiée, qu'on télécharge ; lien de la page d'accueil ; sujets ; options). Lancé tout seul par outils/deployer.sh après chaque
envoi : seul ce qui diffère est changé, et dit. Rien ne part sans le garde-fou de confidentialité
(outils/confidentialite.py). Pas possible par gh : l'image de partage (Settings > Social preview, à la main).

Le nom du dépôt ne change pas tout seul : s'il diffère de celui du programme, le script le dit, et --renommer le
change (GitHub redirige les anciennes adresses).

Depuis la racine du dépôt :
    python3 -I outils/github.py              met la page du dépôt à jour
    python3 -I outils/github.py --voir       dit ce qui changerait, sans rien changer
    python3 -I outils/github.py --renommer   la met à jour et renomme le dépôt comme le programme
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

VOULU = Path(".github/depot.json")
# Limites de GitHub : 350 caractères de description ; 20 sujets, faits de minuscules, de chiffres et de tirets.
LONGUEUR = 350
SUJETS = 20
SUJET = re.compile(r"[a-z0-9][a-z0-9-]{0,49}")
# Option de depot.json : (champ lu par gh repo view, option de gh repo edit, mise en route, coupure).
OPTIONS = {
    "tickets": ("hasIssuesEnabled", "--enable-issues", "tickets activés", "tickets coupés"),
    "wiki": ("hasWikiEnabled", "--enable-wiki", "wiki activé", "wiki coupé"),
    "projets": ("hasProjectsEnabled", "--enable-projects", "projets activés", "projets coupés"),
    "discussions": ("hasDiscussionsEnabled", "--enable-discussions", "discussions activées", "discussions coupées"),
}


def lancer(*args, entree=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True, input=entree, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SystemExit(f"GitHub : {args[0]} n'a pas pu tourner ({e}).") from e
    if r.returncode:
        raise SystemExit(f"GitHub : « {' '.join(args[:3])} » a échoué : {(r.stderr or r.stdout).strip()}")
    return r.stdout


def paquet():
    """(nom, version) du programme, lus dans la section [package] de Cargo.toml."""
    section = Path("Cargo.toml").read_text(encoding="utf-8").split("[package]", 1)[1].split("\n[", 1)[0]
    return tuple(re.search(rf'^{cle}\s*=\s*"([^"]+)"', section, re.M).group(1) for cle in ("name", "version"))


def version_publiee(version):
    """La version de la dernière page publiée (Releases) : une 0.x.y n'en a pas toujours une (outils/deployer.sh), et
    la description montre ce qu'on télécharge. Sans page, ou sans réponse de GitHub : celle de Cargo.toml."""
    try:
        r = subprocess.run(["gh", "release", "view", "--json", "tagName", "-q", ".tagName"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return version
    etiquette = r.stdout.strip() if r.returncode == 0 else ""
    return etiquette[1:] if re.fullmatch(r"v\d+\.\d+\.\d+", etiquette) else version


def voulu(version):
    """Ce que la page doit montrer, vérifié : (description, lien, sujets, options)."""
    page = json.loads(VOULU.read_text(encoding="utf-8"))
    description = f"{page['description'].strip()} · v{version}"
    sujets = list(dict.fromkeys(page.get("sujets", [])))
    options = page.get("options", {})
    erreurs = []
    if len(description) > LONGUEUR:
        erreurs.append(f"description de {len(description)} caractères, version comprise ({LONGUEUR} au plus)")
    if len(sujets) > SUJETS:
        erreurs.append(f"{len(sujets)} sujets ({SUJETS} au plus)")
    erreurs += [f"sujet « {s} » (minuscules, chiffres et tirets)" for s in sujets if not SUJET.fullmatch(s)]
    erreurs += [f"option « {o} » inconnue" for o in options if o not in OPTIONS]
    if erreurs:
        raise SystemExit(f"GitHub : rien n'est changé, {VOULU} à corriger : " + " ; ".join(erreurs) + ".")
    # Le garde-fou relit tout ce qui partirait : une page de dépôt se lit sans être connecté, une fois public.
    texte = "\n".join([description, page.get("accueil", ""), *sujets])
    if subprocess.run([sys.executable, "-I", "outils/confidentialite.py", "--texte"], input=texte, text=True).returncode:
        raise SystemExit(f"GitHub : rien n'est changé (un détail personnel dans {VOULU}).")
    return description, page.get("accueil", ""), sujets, options


def main():
    args = sys.argv[1:]
    if args not in ([], ["--voir"], ["--renommer"]):
        raise SystemExit(__doc__)
    voir, renommer = args == ["--voir"], args == ["--renommer"]
    os.chdir(lancer("git", "rev-parse", "--show-toplevel").strip())
    nom, version = paquet()
    version = version_publiee(version)
    description, accueil, sujets, options = voulu(version)
    origine = lancer("git", "remote", "get-url", "origin").strip()
    m = re.search(r"github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", origine)
    if not m:
        raise SystemExit("GitHub : le dépôt d'origine (git remote origin) n'est pas sur GitHub.")
    proprietaire, depot = m.groups()
    champs = ",".join(["name", "description", "homepageUrl", "repositoryTopics", *(o[0] for o in OPTIONS.values())])
    actuel = json.loads(lancer("gh", "repo", "view", f"{proprietaire}/{depot}", "--json", champs))

    changements, edition = [], []
    renommage = actuel["name"] != nom
    if renommage and not renommer:
        print(f"GitHub : le dépôt s'appelle « {actuel['name']} », le programme « {nom} » : "
              "python3 -I outils/github.py --renommer pour le renommer.")
        renommage = False
    elif renommage:
        changements.append(f"nom ({actuel['name']} → {nom})")
    if actuel["description"] != description:
        ancienne = re.sub(r" · v\d+\.\d+\.\d+$", "", actuel["description"] or "")
        changements.append(f"version de la description (v{version})" if ancienne == description.rsplit(" · v", 1)[0]
                           else "description")
        edition += ["--description", description]
    if (actuel["homepageUrl"] or "") != accueil:
        changements.append("lien de la page d'accueil")
        edition += ["--homepage", accueil]
    presents = {s["name"] for s in actuel.get("repositoryTopics") or []}
    ajouts, retraits = [s for s in sujets if s not in presents], sorted(presents - set(sujets))
    if ajouts or retraits:
        changements.append("sujets (" + " ".join([f"+{s}" for s in ajouts] + [f"−{s}" for s in retraits]) + ")")
        edition += [a for s in ajouts for a in ("--add-topic", s)]
        edition += [a for s in retraits for a in ("--remove-topic", s)]
    for option, valeur in options.items():
        champ, drapeau, en_route, coupe = OPTIONS[option]
        if bool(actuel.get(champ)) != bool(valeur):
            changements.append(en_route if valeur else coupe)
            edition.append(f"{drapeau}={'true' if valeur else 'false'}")

    if not changements:
        print("GitHub : la page du dépôt est déjà à jour.")
        return
    if voir:
        print("GitHub : changerait " + ", ".join(changements) + ".")
        return
    if renommage:
        # Renommé comme le programme : GitHub redirige les anciennes adresses ; l'origine locale suit tout de suite.
        lancer("gh", "repo", "rename", nom, "--repo", f"{proprietaire}/{depot}", "--yes")
        depot = nom
        lancer("git", "remote", "set-url", "origin", re.sub(r"[\w.-]+?(\.git)?/?$", rf"{nom}\1", origine, count=1))
    if edition:
        lancer("gh", "repo", "edit", f"{proprietaire}/{depot}", *edition)
    print("GitHub : " + ", ".join(changements) + " mis à jour.")


if __name__ == "__main__":
    main()
