#!/usr/bin/env python3
"""Avis de licence des bibliothèques compilées dans Vanguard (Linux et Windows).

Les licences MIT, Apache-2.0, BSD et ISC des dépendances demandent de joindre leur texte à l'exécutable distribué :
ce script rassemble ces textes dans LICENCES-TIERCES.txt, copié sur la clé par deployer.sh.

Ne garde que ce qui finit dans le binaire : les dépendances normales (pas celles des tests ni des scripts de
compilation, comme winresource). Lancer depuis la racine du dépôt :
    python3 outils/licences-tierces.py
"""

import json
import re
import subprocess
from pathlib import Path

CIBLES = ["x86_64-unknown-linux-musl", "x86_64-pc-windows-gnu"]
SORTIE = Path("LICENCES-TIERCES.txt")
FICHIERS_LICENCE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE)", re.IGNORECASE)
# Textes types : ceux du dépôt d'abord (le paquet licenses d'Arch n'a ni MIT, ni BSD-3-Clause, ni LLVM-exception,
# propres à chaque projet), puis ceux du système.
TYPES = [Path("outils/licences-types"), Path("/usr/share/licenses/spdx")]
# Données intégrées au programme qui ne sont pas des bibliothèques Rust : (nom, licence, source, texte de la licence).
DONNEES = [
    (
        "Règles YARA de ReversingLabs / ReversingLabs YARA rules (assets/yara/reversinglabs.yara)",
        "MIT",
        "https://github.com/reversinglabs/reversinglabs-yara-rules",
        Path("assets/yara/LICENSE-reversinglabs.txt"),
    ),
]

# Listes téléchargées par Vanguard au moment de s'en servir, jamais intégrées ni redistribuées : une ligne chacune,
# pour la mention de leur source, sans texte de licence (nom, licence, source).
LISTES_TELECHARGEES = [
    (
        "Indicateurs de logiciels espions d'Échap / Échap stalkerware indicators (ioc.yaml)",
        "CC-BY-4.0",
        "https://github.com/AssoEchap/stalkerware-indicators",
    ),
    (
        "Dernières versions de logiciels d'endoflife.date / endoflife.date software versions",
        "MIT",
        "https://github.com/endoflife-date/endoflife.date",
    ),
    (
        "Formules de Homebrew / Homebrew formulae (formula.json : versions de 7-Zip et PuTTY / 7-Zip and PuTTY "
        "versions)",
        "BSD-2-Clause",
        "https://github.com/Homebrew/homebrew-core",
    ),
    (
        "Avis de sécurité de Mozilla / Mozilla security advisories (lus, non redistribués / read, not redistributed)",
        "MPL-2.0",
        "https://github.com/mozilla/foundation-security-advisories",
    ),
    (
        "Catalogue des failles exploitées de la CISA / CISA Known Exploited Vulnerabilities",
        "CC0-1.0",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ),
    (
        "Versions publiées par les éditeurs (Mozilla, Google, Microsoft, Adobe, Brave, Slack), des faits / Versions "
        "published by the publishers, facts",
        "sans licence / no licence",
        "leurs sites / their sites",
    ),
]


def paquets_embarques(cible):
    """Paquets atteignables depuis Vanguard par des dépendances normales, pour une cible donnée."""
    meta = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", cible]
        )
    )
    paquets = {p["id"]: p for p in meta["packages"]}
    noeuds = {n["id"]: n for n in meta["resolve"]["nodes"]}
    racine = meta["resolve"]["root"]
    vus, a_voir = set(), [racine]
    while a_voir:
        noeud = noeuds[a_voir.pop()]
        for dep in noeud["deps"]:
            normale = any(k["kind"] is None for k in dep["dep_kinds"])
            if normale and dep["pkg"] not in vus:
                vus.add(dep["pkg"])
                a_voir.append(dep["pkg"])
    return [paquets[i] for i in vus]


def textes_licence(paquet):
    dossier = Path(paquet["manifest_path"]).parent
    fichiers = sorted(f for f in dossier.iterdir() if f.is_file() and FICHIERS_LICENCE.match(f.name))
    if fichiers:
        return [(f.name, f.read_text(encoding="utf-8", errors="replace").strip()) for f in fichiers]
    # Paquet publié sans fichier de licence : texte type de chaque licence nommée dans son Cargo.toml.
    ids = re.findall(r"[A-Za-z0-9.\-]+", paquet.get("license") or "")
    textes = []
    for i in dict.fromkeys(ids):
        f = next((d / f"{i}.txt" for d in TYPES if (d / f"{i}.txt").is_file()), None)
        if f:
            textes.append((f"{i} (texte type)", f.read_text(encoding="utf-8").strip()))
    return textes


def main():
    embarques = {}
    for cible in CIBLES:
        for p in paquets_embarques(cible):
            embarques[(p["name"], p["version"])] = p

    blocs = [
        "Vanguard inclut les bibliothèques libres suivantes. Voici leurs avis de droit d'auteur et de licence.\n"
        "Vanguard includes the following open source libraries. Their copyright and license notices follow.\n"
        f"\n{len(embarques)} bibliothèques / libraries, et à la fin {len(DONNEES)} jeu(x) de données / then "
        f"{len(DONNEES)} data set(s)."
        "\n\nListes téléchargées à l'usage, non intégrées / Lists downloaded when used, not embedded :\n"
        + "\n".join(f"- {nom} — {licence} — {source}" for nom, licence, source in LISTES_TELECHARGEES)
    ]
    sans_texte = []
    for (nom, version), p in sorted(embarques.items()):
        textes = textes_licence(p)
        if not textes:
            sans_texte.append(f"{nom} {version}")
        entete = f"{nom} {version} — {p.get('license') or '?'}"
        if p.get("repository"):
            entete += f"\n{p['repository']}"
        corps = "\n\n".join(f"--- {fichier} ---\n\n{texte}" for fichier, texte in textes)
        blocs.append(f"{'=' * 80}\n{entete}\n{'=' * 80}\n\n{corps}")

    for nom, licence, source, fichier in DONNEES:
        texte = fichier.read_text(encoding="utf-8").strip()
        blocs.append(f"{'=' * 80}\n{nom} — {licence}\n{source}\n{'=' * 80}\n\n--- {fichier.name} ---\n\n{texte}")

    SORTIE.write_text("\n\n\n".join(blocs) + "\n", encoding="utf-8")
    print(f"{SORTIE} : {len(embarques)} bibliothèques")
    if sans_texte:
        print("Sans texte de licence trouvé :", ", ".join(sans_texte))


if __name__ == "__main__":
    main()
