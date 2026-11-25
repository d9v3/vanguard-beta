#!/usr/bin/env python3
"""Les dépendances en retard (LIBS-OUTDATED de CONFORMITE-ANSSI.md), dites à chaque vérification, et les versions
épinglées exprès, jugées.

Deux questions, deux réponses différentes :
  - une nouvelle version existe-t-elle ? Cargo le dit lui-même (`cargo update --dry-run --verbose`, aucun outil de
    plus) pour chaque Cargo.lock du dépôt. Ce n'est jamais un échec : la sortie d'une version ailleurs ne doit pas
    bloquer une livraison d'ici, et une version du jour n'est pas une version relue. Les bibliothèques demandées par
    nos Cargo.toml sont nommées, avec la date de parution ; les autres sont comptées, pour les versions que
    `cargo update` prendrait (Cargo ne dit pas leurs versions majeures). Une faille connue, elle, fait échouer (cargo
    audit, cargo deny) ; une version épinglée puis retirée de crates.io aussi se dit, sans échouer (comme deny.toml) ;
  - les épinglages (« =x.y.z ») sont-ils tous voulus ? outils/versions-gardees.toml les nomme avec leur raison ; un
    écart est un échec.
Une réponse de Cargo qui ne se lit pas en entier est un échec, jamais « rien en retard ».
Rien n'est écrit dans le dépôt : chaque Cargo.lock est comparé, avant et après.
    python3 -I outils/retards.py             les épinglages, puis les retards (Internet)
    python3 -I outils/retards.py --gardees   les épinglages seulement (sans Internet)
"""

import datetime
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
GARDEES = "outils/versions-gardees.toml"
# Une version piégée est souvent découverte et retirée dans ses premiers jours (même délai que .github/dependabot.yml).
DELAI = 7
# Une réponse de l'index de crates.io plus grosse n'est pas lue (les plus longues font quelques Mo).
PLAFOND = 16 * 1024 * 1024

NOM = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
VERSION = r"[0-9][0-9A-Za-z.+-]{0,63}"
SUITE = r"(?: \((?:latest|available): v(?P<libre>" + VERSION + r")[^()]*\)| \([^()]*\))?"
LIGNES = {
    "change": re.compile(rf"(?:Updating|Upgrading) (?P<nom>{NOM}) v(?P<avant>{VERSION}) -> v(?P<apres>{VERSION}){SUITE}"),
    "recul": re.compile(rf"Downgrading (?P<nom>{NOM}) v(?P<avant>{VERSION}) -> v(?P<apres>{VERSION}){SUITE}"),
    "reste": re.compile(rf"Unchanged (?P<nom>{NOM}) v(?P<avant>{VERSION}){SUITE}"),
    "ajout": re.compile(rf"Adding (?P<nom>{NOM}) v(?P<avant>{VERSION}){SUITE}"),
    "retrait": re.compile(rf"Removing (?P<nom>{NOM}) v(?P<avant>{VERSION}){SUITE}"),
}
COMPTE = re.compile(r"Locking (\d+) packages?\b.*")
# Ce que Cargo dit d'autre, sans rapport avec une version.
VERBES = re.compile(r"(?:Updating|Downgrading|Upgrading|Unchanged|Adding|Removing|Locking)\b")
INDEX = re.compile(r"Updating (?:crates\.io index|`[^`]*` index)")
PREUVE = "not updating lockfile due to dry run"


# Un « =x.y.z » dont la version a été retirée de crates.io depuis : cargo refuse alors tout l'essai à blanc, code 101.
RETIREE = re.compile(
    rf"error: failed to select a version for the requirement `(?P<nom>{NOM}) = \"=(?P<version>{VERSION})\"`"
    r"[^\n]*\n\s*version (?P=version) is yanked\n"
)


class Retiree(Exception):
    """Une version épinglée, retirée de crates.io : dite, sans bloquer, les retards de ce Cargo.toml non vérifiés."""


class Illisible(Exception):
    """Une donnée qui ne se lit pas en entier : un échec, jamais un « rien en retard »."""


def lire_cargo(sortie: str) -> list[dict]:
    """Les lignes de `cargo update --dry-run --verbose`. Chaque ligne qui commence par un de ses verbes doit se lire, et
    leur nombre être celui que Cargo annonce (« Locking N packages ») : une forme nouvelle se voit au lieu de se perdre.
    """
    lues, annonce, preuve = [], None, False
    for brute in sortie.splitlines():
        ligne = brute.strip()
        preuve = preuve or PREUVE in ligne
        if not VERBES.match(ligne) or INDEX.fullmatch(ligne):
            continue
        if compte := COMPTE.fullmatch(ligne):
            if annonce is not None:
                raise Illisible("deux annonces « Locking »")
            annonce = int(compte[1])
            continue
        for genre, motif in LIGNES.items():
            if m := motif.fullmatch(ligne):
                lues.append({"genre": genre, **m.groupdict()})
                break
        else:
            raise Illisible(f"ligne de cargo pas comprise : {ligne[:120]!r}")
    if not preuve:
        raise Illisible("cargo ne dit pas avoir fini son essai à blanc")
    changees = sum(x["genre"] in ("change", "recul", "ajout") for x in lues)
    if annonce is None or annonce != changees:
        raise Illisible(f"{changees} version(s) lue(s), {annonce} annoncée(s) par cargo")
    return lues


def directes(verrou: dict, paquet: str) -> dict[str, set[str]]:
    """Les bibliothèques demandées par le Cargo.toml lui-même et leurs versions retenues, lues dans Cargo.lock : il
    liste celles du paquet, avec le numéro quand plusieurs versions du même nom cohabitent."""
    versions: dict[str, set[str]] = {}
    for p in verrou["package"]:
        versions.setdefault(p["name"], set()).add(p["version"])
    racines = [p for p in verrou["package"] if p["name"] == paquet and "source" not in p]
    if len(racines) != 1:
        raise Illisible(f"{paquet} : {len(racines)} paquet(s) de ce nom dans Cargo.lock")
    demandees: dict[str, set[str]] = {}
    for d in racines[0].get("dependencies", []):
        nom, _, reste = d.partition(" ")
        numero = reste.split(" ")[0]
        retenues = {numero} if numero else versions.get(nom, set())
        if len(retenues) != 1 or not retenues <= versions.get(nom, set()):
            raise Illisible(f"{nom} : version retenue introuvable dans Cargo.lock")
        demandees.setdefault(nom, set()).update(retenues)
    return demandees


def epinglees(manifeste: dict) -> dict[str, set[str]]:
    """Les « =x.y.z » d'un Cargo.toml, toutes tables de dépendances comprises (dev, build, par cible)."""
    trouvees: dict[str, set[str]] = {}

    def tables(t: dict) -> None:
        for cle in ("dependencies", "dev-dependencies", "build-dependencies"):
            for nom, d in t.get(cle, {}).items():
                demande = d if isinstance(d, str) else d.get("version", "")
                vrai = nom if isinstance(d, str) else d.get("package", nom)
                for partie in demande.split(","):
                    if partie.strip().startswith("="):
                        trouvees.setdefault(vrai, set()).add(partie.strip()[1:].strip())

    tables(manifeste)
    tables(manifeste.get("workspace", {}))
    for cible in manifeste.get("target", {}).values():
        tables(cible)
    return trouvees


def manifestes() -> list[str]:
    """Chaque Cargo.toml qui a son Cargo.lock dans le dépôt : lus de Git, une crate de plus n'est pas oubliée."""
    sortie = subprocess.run(
        ["git", "ls-files", "-z", "--", "Cargo.lock", "*/Cargo.lock"], cwd=RACINE, capture_output=True, check=True
    ).stdout.decode()
    verrous = sorted(v for v in sortie.split("\0") if v)
    if "Cargo.lock" not in verrous:
        raise Illisible("Cargo.lock de Vanguard absent de git ls-files")
    return [v.removesuffix("lock") + "toml" for v in verrous]


def charger(chemin: str) -> dict:
    with open(RACINE / chemin, "rb") as f:
        return tomllib.load(f)


def ecarts_gardees(liste: list[dict], pins: dict[str, dict[str, set[str]]], verrous: dict[str, dict]) -> list[str]:
    """Ce qui ne va pas entre outils/versions-gardees.toml, les épinglages des Cargo.toml et les Cargo.lock."""
    ecarts, vues = [], set()
    for g in liste:
        manque = [c for c in ("manifeste", "nom", "version", "raison") if not str(g.get(c, "")).strip()]
        if manque or set(g) - {"manifeste", "nom", "version", "raison", "comme"}:
            ecarts.append(f"entrée mal écrite ({', '.join(manque) or 'champ inconnu'}) : {g.get('nom', '?')}")
            continue
        cle = (g["manifeste"], g["nom"], g["version"])
        if cle in vues:
            ecarts.append(f"{g['manifeste']} : {g['nom']} {g['version']} en double")
        vues.add(cle)
        if g["version"] not in pins.get(g["manifeste"], {}).get(g["nom"], set()):
            ecarts.append(f"{g['manifeste']} : {g['nom']} n'y est pas épinglée à {g['version']}")
        if "comme" in g:
            retenues = {p["version"] for p in verrous.get(g["comme"], {}).get("package", []) if p["name"] == g["nom"]}
            if g["version"] not in retenues:
                dit = ", ".join(sorted(retenues)) or "aucune"
                ecarts.append(f"{g['manifeste']} : {g['nom']} {g['version']}, mais {g['comme']} retient {dit}")
    for manifeste, noms in pins.items():
        for nom, versions in noms.items():
            for v in sorted(versions):
                if (manifeste, nom, v) not in vues:
                    ecarts.append(f"{manifeste} : {nom} épinglée à {v} sans raison dans {GARDEES}")
    return ecarts


def adresse_index(nom: str) -> str:
    n = nom.lower()
    dossier = {1: "1", 2: "2", 3: f"3/{n[0]}"}.get(len(n), f"{n[:2]}/{n[2:4]}")
    return f"https://index.crates.io/{dossier}/{n}"


def parue_le(index: str, version: str) -> datetime.date | None:
    """La date de parution d'une version, lue dans l'index de crates.io ; None s'il ne la donne pas."""
    for ligne in index.splitlines():
        try:
            e = json.loads(ligne)
            if e["vers"] == version:
                return datetime.date.fromisoformat(e["pubtime"][:10])
        except (ValueError, KeyError, TypeError):
            continue
    return None


def telecharger_index(nom: str) -> str:
    demande = urllib.request.Request(adresse_index(nom), headers={"User-Agent": "cargo"})
    with urllib.request.urlopen(demande, timeout=15) as r:
        octets = r.read(PLAFOND + 1)
    if len(octets) > PLAFOND:
        raise ValueError("réponse trop grosse")
    return octets.decode("utf-8", "replace")


def age_dit(nom: str, version: str, aujourdhui: datetime.date) -> str:
    try:
        jour = parue_le(telecharger_index(nom), version)
    except (OSError, ValueError, http.client.HTTPException, RecursionError):
        jour = None
    if jour is None:
        return "date de parution inconnue"
    jours = (aujourdhui - jour).days
    if jours < DELAI:
        return f"parue le {jour}, moins de {DELAI} jours : attendre"
    return f"parue le {jour}"


def ligne_semver(version: str) -> tuple[str, ...]:
    """Les numéros qui ne changent pas dans une mise à jour compatible : 1.x, 0.3.x, 0.0.4."""
    nombres = re.split(r"[.+-]", version)[:3]
    for i, n in enumerate(nombres):
        if n != "0":
            return tuple(nombres[: i + 1])
    return tuple(nombres)


def rang(version: str) -> tuple:
    """De quoi comparer deux versions ; une préversion passe avant sa version."""
    noyau, tiret, _ = version.partition("+")[0].partition("-")
    return [int(n) if n.isdigit() else 0 for n in noyau.split(".")], not tiret


def appariees(lues: list[dict]) -> list[dict]:
    """Les lignes, les « Removing » joints aux « Adding » du même nom : Cargo ne dit « a -> b » que si une seule version
    du nom bouge. La remplaçante est celle de la même ligne semver, sinon la plus haute ; sans elle, rien d'ajouté."""
    ajouts: dict[str, list[dict]] = {}
    for x in lues:
        if x["genre"] == "ajout":
            ajouts.setdefault(x["nom"], []).append(x)
    sorties = [x for x in lues if x["genre"] not in ("ajout", "retrait")]
    for x in lues:
        if x["genre"] != "retrait":
            continue
        memes = ajouts.get(x["nom"], [])
        proches = [a for a in memes if ligne_semver(a["avant"]) == ligne_semver(x["avant"])] or memes
        if not proches:
            sorties.append(x)
            continue
        pris = max(proches, key=lambda a: rang(a["avant"]))
        genre = "recul" if rang(pris["avant"]) < rang(x["avant"]) else "change"
        sorties.append({**x, "genre": genre, "apres": pris["avant"], "libre": pris["libre"]})
    return sorties


def retards(lues: list[dict], demandees: dict[str, set[str]], gardees: set[tuple[str, str]]) -> tuple[list[tuple], int]:
    """Les retards des bibliothèques demandées (nom, version, [(nouvelle, sorte)]), et le nombre des autres. Les deux
    nouvelles sont dites quand elles diffèrent : celle que `cargo update` prend, et celle qui demande le Cargo.toml."""
    nommes, autres = [], 0
    for x in appariees(lues):
        demandee = x["avant"] in demandees.get(x["nom"], set())
        if x["genre"] == "retrait":
            if demandee:
                raise Illisible(f"{x['nom']} {x['avant']} : retirée par cargo sans remplaçante dite")
            continue
        nouvelles = []
        # Un recul proposé (Downgrading) n'est pas un retard ; la version libre plus haute, si.
        if x["genre"] == "change":
            nouvelles.append((x["apres"], "cargo update suffit"))
        if x["libre"] and x["libre"] != x.get("apres"):
            nouvelles.append((x["libre"], "Cargo.toml à changer"))
        nouvelles = [(v, sorte) for v, sorte in nouvelles if v != x["avant"]]
        if not nouvelles:
            continue
        if not demandee:
            autres += 1
            continue
        if (x["nom"], x["avant"]) in gardees:
            nouvelles = [(v, "gardée exprès") for v, _ in nouvelles]
        nommes.append((x["nom"], x["avant"], nouvelles))
    return nommes, autres


def interroger(manifeste: str) -> list[dict]:
    verrou = RACINE / (manifeste.removesuffix("toml") + "lock")
    contenu = verrou.read_bytes()
    avant = hashlib.sha256(contenu).digest()
    # L'environnement l'emporte sur la config de cargo : hors ligne, il jugerait sur un index d'hier, code 0.
    env = {**os.environ, "CARGO_TERM_COLOR": "never", "CARGO_TERM_QUIET": "false", "CARGO_TERM_VERBOSE": "false"}
    env["CARGO_NET_OFFLINE"] = "false"
    try:
        r = subprocess.run(
            ["cargo", "update", "--dry-run", "--verbose", "--manifest-path", manifeste],
            cwd=RACINE, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
        )
    except subprocess.TimeoutExpired as e:
        raise Illisible("cargo n'a pas répondu en 5 minutes") from e
    finally:
        if hashlib.sha256(verrou.read_bytes()).digest() != avant:
            raise Illisible(f"{verrou.relative_to(RACINE)} a changé pendant l'essai à blanc")
    sortie = r.stdout.decode("utf-8", "replace")
    if r.returncode == 101 and (m := RETIREE.search(sortie)):
        raise Retiree(f"{m['nom']} {m['version']}, épinglée, est retirée de crates.io : ses retards non vérifiés")
    if r.returncode != 0:
        raise Illisible(f"cargo, code {r.returncode} : {sortie.strip()[-300:]!r}")
    # Un Cargo.lock sans bibliothèque de crates.io (extensions/sdk) n'a pas d'index à relire.
    if b'source = "registry+' in contenu and not any(INDEX.fullmatch(x.strip()) for x in sortie.splitlines()):
        raise Illisible("cargo n'a pas relu l'index de crates.io")
    return lire_cargo(sortie)


def main() -> int:
    if sys.argv[1:] not in ([], ["--gardees"]):
        print("usage : retards.py [--gardees]", file=sys.stderr)
        return 2
    try:
        noms = manifestes()
        liste = charger(GARDEES).get("gardee", [])
        pins = {m: epinglees(charger(m)) for m in noms}
        verrous = {v: charger(v) for v in (m.removesuffix("toml") + "lock" for m in noms)}
        if ecarts := ecarts_gardees(liste, pins, verrous):
            print("\n".join(f"✖ {e}" for e in ecarts))
            return 1
        print(f"✔ {sum(len(v) for p in pins.values() for v in p.values())} versions épinglées exprès, chacune avec sa raison")
        if sys.argv[1:]:
            return 0
        aujourdhui = datetime.datetime.now(datetime.timezone.utc).date()
        total, total_autres, non_vus = 0, 0, 0
        for m in noms:
            verrou = verrous[m.removesuffix("toml") + "lock"]
            demandees = directes(verrou, charger(m)["package"]["name"])
            gardees = {(g["nom"], g["version"]) for g in liste if g["manifeste"] == m}
            try:
                lues = interroger(m)
            except Retiree as e:
                non_vus += 1
                print(f"{m} :\n  {e}")
                continue
            nommes, autres = retards(lues, demandees, gardees)
            total, total_autres = total + len(nommes), total_autres + autres
            print(f"{m} : {len(nommes)} demandée(s) en retard sur {len(demandees)}, {autres} autre(s)")
            for nom, avant, nouvelles in nommes:
                dites = " ; ".join(f"{v} ({sorte}, {age_dit(nom, v, aujourdhui)})" for v, sorte in nouvelles)
                print(f"  {nom} {avant} -> {dites}")
        suite = f", {non_vus} Cargo.toml NON VÉRIFIÉ(S)" if non_vus else ""
        print(f"retards : {total} bibliothèque(s) demandée(s), {total_autres} autre(s){suite}")
        return 0
    except (Illisible, OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"✖ retards non vérifiés : {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
