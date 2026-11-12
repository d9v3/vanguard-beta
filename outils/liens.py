#!/usr/bin/env python3
"""Liens morts : aucun lien cassé ne part sur GitHub, ni dans la documentation, ni dans le programme, ni dans une
version.

Lancé tout seul : avant chaque envoi (outils/deployer.sh) et avant chaque page de version (outils/publier-version.sh) ;
la CI vérifie les liens internes à chaque envoi.

Ce qui est vérifié :
- les liens web de tous les fichiers suivis par git : documentation, code du programme (hors tests), scripts,
  licences. La page doit répondre, redirections suivies ;
- les liens relatifs des pages Markdown (README, CONTRIBUTING, SECURITY…) : le fichier existe dans le dépôt, et le
  titre visé par une ancre (« SECURITY.md#security ») existe dans la page ;
- les pages du dépôt sur GitHub (« ../../releases/latest/download/… ») : la dernière version a bien ce fichier, ou la
  version qui va être publiée (--version). Le dépôt est privé : elles se vérifient avec gh, pas en les ouvrant.
  Le bouton « Report a vulnerability » (security/advisories/new) : le signalement privé des failles est activé ;

Un lien mort (page introuvable, nom de domaine inconnu, fichier, titre ou téléchargement absent) arrête l'envoi. Un
lien douteux (refusé aux programmes, serveur lent ou en panne, certificat refusé) est montré sans rien arrêter : il
faut l'ouvrir soi-même dans un navigateur. Ne sont pas ouverts : les exemples (example.com, adresses privées, « x »),
les adresses construites à l'exécution, et les cas à part de outils/liens.txt (espaces de noms, points d'accès d'API).
Une page trouvée bonne n'est pas redemandée pendant un jour (~/.cache/vanguard-dev/liens.json).

Depuis la racine du dépôt :
    python3 -I outils/liens.py                      tous les liens du dépôt
    python3 -I outils/liens.py --hors-ligne         seulement les liens internes (sans Internet ni gh)
    python3 -I outils/liens.py --version FICHIER…   tous, les téléchargements du README comparés aux fichiers de la
                                                 version qui va être publiée
    python3 -I outils/liens.py --texte < FICHIER    les liens web d'un texte à publier (notes d'une version)
    --sans-cache, avec l'un d'eux                tout redemander
Sort en erreur (code 1) en disant quel lien est mort et où il paraît.
"""

import concurrent.futures
import http.client
import ipaddress
import json
import os
import posixpath
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REGLES = Path(__file__).with_name("liens.txt")
CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "vanguard-dev/liens.json"
# Une page trouvée bonne le reste un jour : les déploiements se suivent de près, inutile de tout redemander.
VALIDITE = 24 * 3600
DELAI = 15
# Pas plus de trois demandes à la fois au même site : GitHub en reçoit une soixantaine, pour les licences.
PAR_SITE = 3
# L'en-tête d'un navigateur : des sites refusent les programmes qui se nomment, sans que la page soit morte.
AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

# Cargo.lock nomme la source des paquets (« registry+https://… ») : pas des liens à ouvrir.
PAS_DES_LIENS = {"Cargo.lock", "fuzz/Cargo.lock"}
BINAIRES = (".png", ".ico", ".icns", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".gz", ".zip", ".exe", ".ttf", ".woff2")
URL = re.compile(r"https?://[^\s<>\"'`(){}\[\]|\\^]+")
PONCTUATION = ".,;:!?»”’'\""
# Cible d'un lien ou d'une image Markdown (« ](cible "titre") »), d'une définition (« [nom]: cible »), d'un attribut.
CIBLE_MD = re.compile(r"\]\(\s*<?([^()\s<>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
DEFINITION_MD = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)")
ATTRIBUT = re.compile(r"""\b(?:href|src)\s*=\s*["']([^"']+)["']""")
SCHEMA = re.compile(r"[a-z][a-z0-9+.-]*:", re.I)
# Noms réservés aux exemples et aux réseaux locaux (RFC 2606, 6761, 8375) : rien à ouvrir.
NOMS_EXEMPLES = (".example", ".invalid", ".test", ".localhost", ".local", ".lan", ".home.arpa", ".internal")
DOMAINES_EXEMPLES = ("example.com", "example.net", "example.org")
# Réponses qui passent d'elles-mêmes : un second essai, quelques secondes plus tard.
PASSAGERS = {429, 500, 502, 503, 504}
NOM_INCONNU = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}


@dataclass
class Lien:
    """Un lien web et les endroits où il paraît."""

    lieux: list = field(default_factory=list)
    # Complété à l'exécution (« …/check-email/{} ») : seul le serveur peut être vérifié.
    modele: bool = False


def git(*args):
    r = subprocess.run(["git", "-c", "core.quotePath=false", *args], capture_output=True, text=True, errors="replace")
    if r.returncode:
        raise SystemExit(f"liens : git {' '.join(args)} a échoué : {r.stderr.strip()}")
    return r.stdout


# --- Où sont les liens -----------------------------------------------------------------------------------------------


def sans_tests(texte):
    """Le code Rust sans son module de tests : les adresses y sont inventées (« https://x.example/a »)."""
    m = re.search(r"^#\[cfg\(test\)\]\s*\nmod \w+", texte, re.M)
    return texte[: m.start()] if m else texte


def developper(texte):
    """Un script avec ses variables à valeur fixe remplacées : « https://github.com/$DEPOT » devient une adresse."""
    valeurs = dict(re.findall(r"^\s*(?:export\s+|readonly\s+|local\s+)?([A-Za-z_]\w*)=[\"']?([^\"'\s$`;|&<>()]+)[\"']?"
                              r"\s*(?:#.*)?$", texte, re.M))
    return re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: valeurs.get(m.group(1), m.group(0)), texte)


def liens_web(texte, fichier, liens):
    """Ajoute à liens les adresses web d'un texte, avec leur fichier et leur ligne."""
    for numero, ligne in enumerate(texte.splitlines(), 1):
        for m in URL.finditer(ligne):
            adresse = m.group(0).rstrip(PONCTUATION)
            if "$" in adresse:
                continue  # construite à l'exécution, d'une variable inconnue ici
            lien = liens.setdefault(adresse, Lien())
            lien.lieux.append(f"{fichier}:{numero}")
            lien.modele |= ligne[m.end() : m.end() + 1] == "{"


def liens_md(texte):
    """(ligne, cible) des liens d'une page Markdown, hors blocs de code et code en ligne."""
    dans_code = False
    for numero, ligne in enumerate(texte.splitlines(), 1):
        if re.match(r"\s*(```|~~~)", ligne):
            dans_code = not dans_code
        elif not dans_code:
            definitions = DEFINITION_MD.findall(ligne)
            ligne = re.sub(r"`[^`]*`", "", ligne)
            for cible in CIBLE_MD.findall(ligne) + ATTRIBUT.findall(ligne) + definitions:
                yield numero, cible


def lire_depot(suivis, web, internes):
    """Les liens web de tous les fichiers suivis par git, et les liens relatifs des pages Markdown."""
    for fichier in sorted(suivis):
        # Les tests du programme (tests/) inventent leurs adresses, comme les modules de tests du code et les graines du
        # fuzzing (fuzz/graines/), des réponses de box et des plists d'exemple ; les copies réduites de fichiers réels
        # (assets/essais/) en portent des milliers, qui sont des données, pas des liens du projet.
        if (
            fichier in PAS_DES_LIENS
            or fichier.startswith(("tests/", "fuzz/graines/", "assets/essais/"))
            or fichier.lower().endswith(BINAIRES)
        ):
            continue
        try:
            brut = Path(fichier).read_bytes()
        except OSError:
            continue  # supprimé, pas encore commité
        if b"\0" in brut[:8192]:
            continue
        texte = brut.decode("utf-8", errors="replace")
        if fichier.endswith(".rs"):
            texte = sans_tests(texte)
        elif fichier.endswith(".sh"):
            texte = developper(texte)
        liens_web(texte, fichier, web)
        if fichier.endswith(".md"):
            internes += [(f"{fichier}:{n}", fichier, c) for n, c in liens_md(texte) if not SCHEMA.match(c)]


# --- Liens internes --------------------------------------------------------------------------------------------------


def ancres(texte):
    """Les ancres des titres d'une page Markdown, faites comme GitHub : minuscules, ponctuation retirée, espaces en
    tirets, « -1 », « -2 »… aux titres répétés ; plus celles écrites à la main (<a id="…">)."""
    vues, resultat, dans_code = {}, set(), False
    for ligne in texte.splitlines():
        if re.match(r"\s*(```|~~~)", ligne):
            dans_code = not dans_code
            continue
        m = None if dans_code else re.match(r"\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$", ligne)
        if not m:
            continue
        titre = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", m.group(1)).replace("`", "").replace("*", "")
        base = re.sub(r"[^\w\- ]", "", titre.strip().lower()).replace(" ", "-")
        n = vues.get(base, 0)
        vues[base] = n + 1
        resultat.add(f"{base}-{n}" if n else base)
    return resultat | set(re.findall(r"""<a\s+(?:name|id)\s*=\s*["']([^"']+)["']""", texte))


def resoudre(fichier, cible):
    """Ce que vise le lien relatif d'une page : (« fichier », chemin dans le dépôt, ancre), (« github », page du dépôt,
    None) pour « ../../releases/… », vu depuis …/blob/<branche>/<page> comme GitHub l'affiche, ou (« dehors », …)."""
    chemin, _, ancre = cible.partition("#")
    chemin = urllib.parse.unquote(chemin.partition("?")[0])
    ancre = urllib.parse.unquote(ancre)
    if not chemin:
        return "fichier", fichier, ancre
    # GitHub lit « /chemin » depuis la racine du dépôt.
    base = "" if chemin.startswith("/") else posixpath.dirname(fichier)
    joint = posixpath.normpath(posixpath.join(base, chemin.lstrip("/")))
    parties = joint.split("/")
    montee = next((i for i, p in enumerate(parties) if p != ".."), len(parties))
    if montee == 0:
        return "fichier", joint, ancre
    if montee == 2:
        return "github", "/".join(parties[2:]), None
    return "dehors", joint, None


def existe(chemin, suivis):
    return chemin == "." or chemin in suivis or any(s.startswith(chemin + "/") for s in suivis)


class GhMuet(Exception):
    """gh n'a pas pu répondre : pas installé, pas connecté, pas d'Internet."""


class GitHub:
    """Le dépôt sur GitHub, vu par gh : privé, ses pages ne s'ouvrent pas sans être connecté."""

    def __init__(self, suivis, fichiers_version):
        adresse = subprocess.run(["git", "remote", "get-url", "origin"], capture_output=True, text=True).stdout
        m = re.search(r"github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?/?$", adresse.strip())
        self.nom = m.group(1) if m else None
        self.suivis = suivis
        self.fichiers_version = fichiers_version
        # Les fichiers que outils/publier-version.sh publie : un lien vers l'un d'eux qui manque encore à la dernière
        # version y sera à la prochaine, il n'est pas mort (sinon il bloquerait l'envoi qui doit la précéder).
        script = Path("outils/publier-version.sh")
        self.publies = set(re.findall(r"\$DOSSIER/([\w.-]+)", script.read_text())) if script.exists() else set()
        self._derniere = False
        self._reponses = {}

    def demander(self, *args):
        """La réponse de gh (JSON), None si ce qu'on demande n'existe pas. Chaque question ne part qu'une fois, son
        échec compris : sans Internet, douze liens vers la dernière version attendaient chacun jusqu'à 60 s."""
        if args not in self._reponses:
            try:
                self._reponses[args] = self._demander(args)
            except GhMuet as e:
                self._reponses[args] = e
        reponse = self._reponses[args]
        if isinstance(reponse, GhMuet):
            raise reponse
        return reponse

    @staticmethod
    def _demander(args):
        try:
            r = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise GhMuet(str(e)) from e
        if r.returncode == 0:
            return json.loads(r.stdout or "null")
        if re.search(r"not found|404", r.stderr, re.I):
            return None
        raise GhMuet((r.stderr.strip().splitlines() or [f"code {r.returncode}"])[-1])

    def depot(self):
        """Le dépôt vu par gh (nom et page d'accueil, une seule question pour les deux), None s'il n'existe pas."""
        return self.demander("repo", "view", self.nom, "--json", "name,homepageUrl")

    def derniere(self):
        """Les noms des fichiers de la dernière version, None s'il n'y en a pas."""
        if self._derniere is False:
            version = self.demander("release", "view", "--repo", self.nom, "--json", "assets")
            self._derniere = None if version is None else {f["name"] for f in version["assets"]}
        return self._derniere

    def page(self, page):
        """(état, précision) d'une page du dépôt sur GitHub."""
        if not self.nom:
            return "douteux", "dépôt GitHub inconnu (git remote origin)"
        parties = page.strip("/").split("/")
        try:
            if parties[:2] == ["releases", "latest"] and len(parties) in (2, 4) and parties[2:3] in ([], ["download"]):
                if self.fichiers_version is not None:
                    noms = set(self.fichiers_version)
                elif (noms := self.derniere()) is None:
                    return "douteux", "aucune version publiée pour l'instant"
                if len(parties) == 2 or parties[3] in noms:
                    return "ok", ""
                if self.fichiers_version is None and parties[3] in self.publies:
                    return "douteux", "pas encore dans la dernière version : sera dans la prochaine"
                return "mort", f"pas de fichier « {parties[3]} » dans la " + (
                    "version publiée maintenant" if self.fichiers_version is not None else "dernière version")
            if parties[:2] == ["releases", "tag"] and len(parties) == 3:
                trouve = self.demander("release", "view", parties[2], "--repo", self.nom, "--json", "tagName")
                return ("ok", "") if trouve else ("mort", f"pas de version {parties[2]}")
            if parties[0] in ("blob", "tree", "raw") and len(parties) >= 3:
                chemin = "/".join(parties[2:])
                return ("ok", "") if existe(chemin, self.suivis) else ("mort", "absent du dépôt (ou pas suivi par git)")
            # Le bouton « Report a vulnerability » de SECURITY.md : la page n'existe que si le signalement privé des
            # failles est activé (Settings › Security), sinon le seul chemin donné pour signaler mène nulle part.
            if parties == ["security", "advisories", "new"]:
                etat = self.demander("api", f"repos/{self.nom}/private-vulnerability-reporting")
                if etat is None:
                    return "mort", "dépôt introuvable"
                return ("ok", "") if etat.get("enabled") else (
                    "mort", "signalement privé des failles coupé (Settings › Security)")
            if parties[0] in ("", "releases", "issues", "pulls", "actions", "tags", "commits", "branches", "security"):
                return ("ok", "") if self.depot() else ("mort", "dépôt introuvable")
        except GhMuet as e:
            return "douteux", f"gh n'a pas pu répondre ({e})"
        return "douteux", "page du dépôt que cet outil ne sait pas vérifier"

    def du_depot(self, adresse):
        """La page du dépôt que vise une adresse web (« https://github.com/<dépôt>/releases »), sinon None."""
        if not self.nom:
            return None
        m = re.match(rf"https?://(?:www\.)?github\.com/{re.escape(self.nom)}(?:\.git)?(?=[/?#]|$)/?([^?#]*)", adresse,
                     re.I)
        return m.group(1) if m else None

    def accueil(self):
        """L'adresse de la page d'accueil du dépôt (lien affiché à côté de la description), ou None."""
        try:
            depot = self.depot() if self.nom else None
        except GhMuet:
            return None
        return (depot or {}).get("homepageUrl") or None


# --- Liens web -------------------------------------------------------------------------------------------------------


def regles():
    """Les cas à part de outils/liens.txt : (sorte, début du lien, lien à ouvrir à la place)."""
    liste = []
    for ligne in REGLES.read_text(encoding="utf-8").splitlines():
        mots = re.split(r"(?:^|\s)#", ligne, maxsplit=1)[0].split()
        if not mots:
            continue
        if mots[0] in ("ignorer", "serveur", "protege") and len(mots) == 2:
            liste.append((mots[0], mots[1], None))
        elif mots[0] == "essai" and len(mots) == 3:
            liste.append(("essai", mots[1], mots[2]))
        else:
            raise SystemExit(f"liens : ligne incomprise dans outils/{REGLES.name} : {ligne}")
    return liste


def regle_pour(adresse, liste):
    """La règle au début le plus long qui commence l'adresse."""
    return max((r for r in liste if adresse.startswith(r[1])), key=lambda r: len(r[1]), default=None)


def exemple(adresse):
    """Une adresse d'exemple ou du réseau local, qui n'est pas à ouvrir : « https://x.example/a », 192.168.1.20…"""
    try:
        hote = (urllib.parse.urlsplit(adresse).hostname or "").rstrip(".")
    except ValueError:
        return True
    try:
        return not ipaddress.ip_address(hote).is_global
    except ValueError:
        pass
    return ("." not in hote or "*" in hote or hote.endswith(NOMS_EXEMPLES) or hote in DOMAINES_EXEMPLES
            or hote.endswith(tuple("." + d for d in DOMAINES_EXEMPLES)))


def en_ascii(adresse):
    """L'adresse telle qu'elle part sur le réseau, sans son ancre : nom en IDNA, accents du chemin encodés."""
    p = urllib.parse.urlsplit(adresse)
    hote = p.netloc if p.netloc.isascii() else p.netloc.encode("idna").decode()
    sur = "/%:@!$&'()*+,;=~?[]"
    return urllib.parse.urlunsplit((p.scheme, hote, urllib.parse.quote(p.path, safe=sur),
                                    urllib.parse.quote(p.query, safe=sur), ""))


def demander(adresse, methode):
    """(code HTTP, erreur) d'une demande, sans lire la page."""
    requete = urllib.request.Request(adresse, method=methode,
                                     headers={"User-Agent": AGENT, "Accept": "*/*", "Accept-Language": "fr,en;q=0.8"})
    try:
        with urllib.request.urlopen(requete, timeout=DELAI) as reponse:
            return reponse.status, None
    except urllib.error.HTTPError as e:
        e.close()
        return e.code, None
    except urllib.error.URLError as e:
        return None, e.reason
    except (OSError, http.client.HTTPException, ValueError) as e:
        return None, e


def juger(code, erreur, serveur_seul, protege):
    """(état, précision) d'une réponse : ok, mort, douteux, ou « inconnu » si le DNS ne connaît pas le nom."""
    if code is not None:
        if 200 <= code < 300 or serveur_seul or protege and code in (401, 403, 429, 999):
            return "ok", ""
        if code in (404, 410):
            return "mort", f"page introuvable ({code})"
        if code in (401, 403, 999):
            return "douteux", f"refusé aux programmes ({code}) : à ouvrir dans un navigateur"
        if code == 429:
            return "douteux", "trop de demandes (429)"
        return "douteux", f"serveur en panne ({code})" if code >= 500 else f"réponse {code}"
    if isinstance(erreur, socket.gaierror) and erreur.errno in NOM_INCONNU:
        return "inconnu", "nom de domaine inconnu"
    if isinstance(erreur, TimeoutError) or "timed out" in str(erreur):
        return "douteux", f"pas de réponse en {DELAI} s"
    if isinstance(erreur, ssl.SSLCertVerificationError):
        return "douteux", f"certificat refusé ({erreur.verify_message})"
    if isinstance(erreur, ConnectionRefusedError):
        return "douteux", "connexion refusée"
    return "douteux", f"injoignable ({erreur})"


def nom_public(hote):
    """Le nom existe-t-il pour un DNS public ? Celui de l'ordinateur peut filtrer (listes de blocage) : un nom qu'il dit
    inconnu n'est mort que si 1.1.1.1 le dit aussi. None : pas pu demander."""
    adresse = "https://1.1.1.1/dns-query?" + urllib.parse.urlencode({"name": hote, "type": "A"})
    try:
        with urllib.request.urlopen(urllib.request.Request(adresse, headers={"Accept": "application/dns-json"}),
                                    timeout=DELAI) as reponse:
            statut = json.load(reponse).get("Status")
    except (OSError, ValueError):
        return None
    return None if statut not in (0, 3) else statut == 0


def internet():
    try:
        socket.getaddrinfo("github.com", 443)
        return True
    except OSError:
        return False


class Verification:
    """Les demandes aux sites, quelques-unes à la fois, et ce qui a été trouvé bon depuis moins d'un jour."""

    def __init__(self, cache):
        self.cache = cache
        self.verrou = threading.Lock()
        self.sites = {}

    def site(self, hote):
        with self.verrou:
            return self.sites.setdefault(hote, threading.Semaphore(PAR_SITE))

    def ouvrir(self, adresse, serveur_seul, protege):
        """(état, précision) d'une page : ok, mort ou douteux."""
        cle = ("serveur " if serveur_seul else "") + adresse
        with self.verrou:
            if cle in self.cache:
                return "ok", ""
        hote = urllib.parse.urlsplit(adresse).hostname or ""
        with self.site(hote):
            for essai in (1, 2):
                code, erreur = demander(adresse, "HEAD")
                if not isinstance(erreur, socket.gaierror) and (code is None or code >= 300 and not serveur_seul):
                    # Bien des serveurs répondent mal à HEAD : seule la vraie demande compte.
                    code, erreur = demander(adresse, "GET")
                etat, precision = juger(code, erreur, serveur_seul, protege)
                passager = code in PASSAGERS or code is None and not isinstance(erreur, (ssl.SSLError, socket.gaierror))
                if etat != "douteux" or essai == 2 or not passager:
                    break
                time.sleep(3)
        if etat == "inconnu":
            public = nom_public(hote)
            etat, precision = ("mort", precision) if public is False else (
                "douteux", "nom inconnu du DNS de cet ordinateur (filtré ?)")
        if etat == "ok":
            with self.verrou:
                self.cache[cle] = time.time()
        return etat, precision


def lire_cache():
    try:
        donnees = json.loads(CACHE.read_text())
    except (OSError, ValueError):
        return {}
    maintenant = time.time()
    return {c: t for c, t in donnees.items() if isinstance(t, (int, float)) and 0 <= maintenant - t < VALIDITE}


def ecrire_cache(cache):
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        provisoire = CACHE.with_suffix(".tmp")
        provisoire.write_text(json.dumps(cache, indent=0, sort_keys=True))
        provisoire.replace(CACHE)
    except OSError:
        pass  # sans cache, tout sera redemandé la prochaine fois


# --- Ensemble --------------------------------------------------------------------------------------------------------


def rapport(resultats, verifies, a_part, sans_internet):
    """Montre les liens morts et douteux ; 1 s'il y a un lien mort."""
    morts = {k: v for k, v in resultats.items() if k[1] == "mort"}
    douteux = {k: v for k, v in resultats.items() if k[1] == "douteux"}
    print(f"Liens : {verifies} vérifié(s)" + (f", {a_part} exemple(s) ou cas à part non ouverts" if a_part else "")
          + (f", {len(morts)} mort(s)" if morts else ", aucun mort") + ".", flush=True)
    if sans_internet:
        print(f"Pas d'Internet : {sans_internet} lien(s) web non vérifié(s).", file=sys.stderr)
    for titre, groupe in (("douteux, à ouvrir soi-même (rien n'est arrêté)", douteux), ("mort(s)", morts)):
        if groupe:
            print(f"{len(groupe)} lien(s) {titre} :", file=sys.stderr)
        for (lien, _, precision), lieux in sorted(groupe.items()):
            lieux = sorted(set(lieux))
            ou = ", ".join(lieux[:3]) + (f" et {len(lieux) - 3} autre(s)" if len(lieux) > 3 else "")
            print(f"  {lien}\n      {precision} — {ou}", file=sys.stderr)
    if morts:
        print("Corrige-les, ou décris un cas à part dans outils/liens.txt.", file=sys.stderr)
    return 1 if morts else 0


def main():
    args = sys.argv[1:]
    sans_cache = "--sans-cache" in args
    args = [a for a in args if a != "--sans-cache"]
    mode = args[0] if args else ""
    if mode not in ("", "--hors-ligne", "--version", "--texte") or (len(args) > 1) != (mode == "--version"):
        raise SystemExit(__doc__)
    if mode == "--texte":
        texte = sys.stdin.read()
    os.chdir(git("rev-parse", "--show-toplevel").strip())
    suivis = set(git("ls-files", "-z").split("\0")) - {""}
    github = GitHub(suivis, args[1:] if mode == "--version" else None)
    web, internes, resultats = {}, [], {}
    verifies = a_part = sans_internet = 0

    def noter(lien, etat, precision, lieux):
        nonlocal verifies
        verifies += 1
        if etat != "ok":
            resultats.setdefault((lien, etat, precision), []).extend(lieux)

    if mode == "--texte":
        liens_web(texte, "texte", web)
    else:
        lire_depot(suivis, web, internes)

    pages = {}
    for lieu, fichier, cible in internes:
        sorte, valeur, ancre = resoudre(fichier, cible)
        if sorte == "github":
            if mode == "--hors-ligne":
                a_part += 1
                continue
            etat, precision = github.page(valeur)
        elif sorte == "dehors":
            etat, precision = "mort", "sort du dépôt"
        elif not existe(valeur, suivis):
            etat, precision = "mort", "absent du dépôt (ou pas suivi par git)"
        elif ancre and valeur.endswith(".md"):
            if valeur not in pages:
                pages[valeur] = ancres(Path(valeur).read_text(encoding="utf-8", errors="replace"))
            trouve = ancre in pages[valeur]
            etat, precision = ("ok", "") if trouve else ("mort", f"pas de titre « #{ancre} » dans {valeur}")
        else:
            etat, precision = "ok", ""
        noter(cible, etat, precision, [lieu])

    if mode != "--hors-ligne":
        if mode != "--texte" and (accueil := github.accueil()):
            web.setdefault(accueil, Lien()).lieux.append("page d'accueil du dépôt sur GitHub")
        liste = regles()
        en_ligne = internet()
        a_ouvrir = {}
        for adresse, lien in web.items():
            regle = regle_pour(adresse, liste)
            if exemple(adresse) or regle and regle[0] == "ignorer":
                a_part += 1
            elif (page := github.du_depot(adresse)) is not None:
                noter(adresse, *github.page(page), lien.lieux)
            elif not en_ligne:
                sans_internet += 1
            else:
                cible = regle[2] if regle and regle[0] == "essai" else adresse
                sorte = regle[0] if regle else None
                serveur_seul = sorte == "serveur" or lien.modele and sorte != "essai"
                cle = (en_ascii(cible), serveur_seul, sorte == "protege")
                a_ouvrir.setdefault(cle, []).append(adresse)
        verification = Verification({} if sans_cache else lire_cache())
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futurs = {pool.submit(verification.ouvrir, *cle): cle for cle in a_ouvrir}
            for futur in concurrent.futures.as_completed(futurs):
                etat, precision = futur.result()
                for adresse in a_ouvrir[futurs[futur]]:
                    noter(adresse, etat, precision, web[adresse].lieux)
        ecrire_cache(verification.cache)

    sys.exit(rapport(resultats, verifies, a_part, sans_internet))


if __name__ == "__main__":
    main()
