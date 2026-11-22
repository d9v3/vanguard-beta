#!/usr/bin/env python3
"""Contrôle des sources du catalogue des logiciels, avant chaque publication (conception-interface, ligne C5).

Une source peut se dégrader en quelques mois (Bitwarden : extra/bitwarden marqué périmé, licence Flathub devenue non
libre). Pour chaque source de outils/catalogue-sources.json (le catalogue compilé, sérialisé par l'essai Rust
logiciels::tests::catalogue_exporte_a_jour, jamais lu dans le source par motifs) :
  - Arch : le paquet est dans core, extra ou multilib, et n'y est pas marqué périmé (flag_date) ;
  - Flathub : l'application existe, n'est pas en fin de vie, est vérifiée par son éditeur, et sa licence dit ce que dit
    le catalogue (libre ou non, mêmes identifiants SPDX ; FLATHUB_PAS_LIBRE : non libre) ;
  - winget : l'identifiant est dans l'index que télécharge winget lui-même (source2.msix du CDN de Microsoft, bâti
    depuis le dépôt microsoft/winget-pkgs ; sans l'API de GitHub, limitée à 60 requêtes par heure sans jeton) ;
  - Debian : le paquet binaire est dans stable, section main (API madison de ftp-master) ;
  - Fedora : le paquet est dans la dernière version publiée (mdapi) ;
  - openSUSE : non couvert (aucune API publique simple en JSON sans compte), dit et compté. Aucun cask au catalogue.

Codes de sortie : 0 tout vérifié et sain (les dégradations admises sont montrées) ; 1 au moins une dégradation non
admise ; 2 rien de dégradé trouvé, mais au moins une source non vérifiée (réseau, délai, réponse illisible, limite),
ou l'outil n'a pas pu juger. Un code 1 dit toujours « Sources : N dégradation(s) », un code 0 « Sources : N
vérifiée(s), saines » : livrer-branche.sh exige ce témoin (une trace de Python sort aussi en 1).

Une dégradation connue n'est admise que par outils/controle-sources-admis.json (versionné : source, identifiant,
constat, raison, date, jusqu_au) ; passé jusqu_au, elle redevient une dégradation.

Ce qui vient d'Internet est une donnée : HTTPS seulement, certificat vérifié, hôtes en liste fermée, aucune
redirection suivie, délai par requête, taille plafonnée, JSON strict (clés en double, NaN refusés), types vérifiés ;
tout texte distant affiché est assaini (contrôles, bidi, invisibles retirés). Rien n'est écrit : tout reste en
mémoire (l'index de winget compris, ouvert par sqlite3 en mémoire, en mode défensif). Aucun shell.
Essais hors ligne : outils/essais-controle-sources.py (faux serveur HTTPS local), lancé par verifier.sh.
  python3 -I outils/controle-sources.py [--catalogue F] [--admis F]
"""

import datetime
import http.client
import io
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import time
import unicodedata
import urllib.parse
import zipfile

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOGUE = os.path.join(RACINE, "outils", "catalogue-sources.json")
ADMIS = os.path.join(RACINE, "outils", "controle-sources-admis.json")

# Hôtes permis, chacun avec les débuts de chemin qu'on y demande : rien d'autre ne part.
HOTES = {
    "archlinux.org": ("/packages/search/json/",),
    "flathub.org": ("/api/v2/appstream/",),
    "cdn.winget.microsoft.com": ("/cache/source2.msix",),
    "api.ftp-master.debian.org": ("/madison",),
    "mdapi.fedoraproject.org": ("/branches", "/f"),
}
DELAI = 20  # secondes par opération réseau (connexion, lecture d'un morceau)
DELAI_TOTAL = 60  # secondes par requête, du début à la fin de la lecture (un serveur qui goutte un octet à la fois)
PLAFOND_JSON = 2 * 1024 * 1024
PLAFOND_MSIX = 16 * 1024 * 1024
PLAFOND_INDEX = 64 * 1024 * 1024
PAUSE = 0.2  # entre deux requêtes : un passage par publication, sans rafale
INDEX_WINGET_AGE_MAX = 14  # jours : un index plus vieux ne prouve plus qu'un identifiant existe encore
DEPOTS_ARCH = ("core", "extra", "multilib")
AGENT = "vanguard-controle-sources/1"

# Identifiants permis (les mêmes que l'essai catalogue_complet_et_sur, plus stricts) : chaque morceau entre points
# commence par une lettre ou un chiffre, jamais vide (ni « .. », ni « -x » pris pour une option), 128 au plus.
MORCEAU = r"[A-Za-z0-9][A-Za-z0-9+_-]*"
MOTIFS = {
    "paquet": re.compile(rf"{MORCEAU}(\.{MORCEAU})*"),
    "flatpak": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9][A-Za-z0-9_-]*){2,}"),
    "winget": re.compile(rf"{MORCEAU}(\.{MORCEAU})+"),
}
SOURCES = ("arch", "debian", "fedora", "opensuse", "flathub", "winget")
CONSTATS = {
    "absent": "absent de la source",
    "perime": "marqué périmé",
    "fin-de-vie": "en fin de vie",
    "licence": "licence différente du catalogue",
    "hors-main": "hors de la section main",
}
# Dits (ligne « ℹ »), jamais une dégradation : ils ne changent pas le code de sortie, ni ne s'admettent. Un éditeur
# qui n'a pas vérifié son application sur Flathub n'est pas une source qui s'est dégradée (beaucoup ne l'ont jamais
# fait), mais vaut d'être su avant de la proposer.
INFOS = {
    "editeur-non-verifie": "pas vérifié par son éditeur",
}


class NonVerifie(Exception):
    """Une source qu'on n'a pas pu juger : jamais comptée saine."""


def propre(texte, longueur=160):
    """Un texte venu d'ailleurs, sans rien qui agisse sur le terminal : contrôles (ESC compris), bidi, invisibles,
    séparateurs de ligne et caractères non attribués deviennent « ? » ; coupé à `longueur`."""
    if not isinstance(texte, str):
        texte = repr(texte)
    sortie = []
    for c in texte[: longueur + 1]:
        cat = unicodedata.category(c)
        sortie.append("?" if cat[0] == "C" or cat in ("Zl", "Zp") else c)
    t = "".join(sortie)
    return t if len(t) <= longueur else t[:longueur] + "…"


def json_strict(octets):
    """JSON en UTF-8 strict, sans NaN ni Infinity, sans clé en double ; trop profond : refusé."""

    def paires(liste):
        vues = {}
        for cle, valeur in liste:
            if cle in vues:
                raise NonVerifie(f"JSON piégé : clé « {propre(cle, 40)} » en double")
            vues[cle] = valeur
        return vues

    def constante(nom):
        raise NonVerifie(f"JSON piégé : {nom}")

    try:
        texte = octets.decode("utf-8")
        return json.loads(texte, object_pairs_hook=paires, parse_constant=constante)
    except NonVerifie:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise NonVerifie(f"réponse illisible ({type(e).__name__})") from None


class Client:
    """HTTPS vers les seuls hôtes permis. `ctx` et `relier` ne changent que dans les essais (autorité et faux
    serveur locaux) : le nom vérifié dans le certificat reste toujours celui de l'hôte permis."""

    def __init__(self, ctx=None, relier=None, pause=PAUSE, delai=DELAI, delai_total=DELAI_TOTAL):
        self.ctx = ctx or ssl.create_default_context()
        self.ctx.check_hostname = True
        self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.relier = relier or (lambda hote: (hote, 443))
        self.pause = pause
        self.delai = delai
        self.delai_total = delai_total
        self.injoignables = {}
        self.requetes = 0

    def obtenir(self, hote, chemin, plafond=PLAFOND_JSON, types=("application/json",), absents=(404,)):
        """Le corps d'une réponse 200 (ou None pour un code de `absents`) ; tout le reste lève NonVerifie."""
        if hote not in HOTES or not any(chemin.startswith(p) for p in HOTES[hote]):
            raise NonVerifie(f"requête hors de la liste fermée : {propre(hote)}{propre(chemin)}")
        if hote in self.injoignables:
            raise NonVerifie(self.injoignables[hote])
        if self.requetes:
            time.sleep(self.pause)
        self.requetes += 1
        debut = time.monotonic()
        ctx, (adresse, port), delai = self.ctx, self.relier(hote), self.delai

        class Connexion(http.client.HTTPSConnection):
            def connect(self):
                brute = socket.create_connection((adresse, port), timeout=delai)
                # Le nom vérifié est l'hôte permis, quelle que soit l'adresse jointe.
                self.sock = ctx.wrap_socket(brute, server_hostname=hote)

        connexion = Connexion(hote, 443, timeout=delai, context=ctx)
        try:
            try:
                connexion.request(
                    "GET",
                    chemin,
                    headers={"User-Agent": AGENT, "Accept": ", ".join(types), "Accept-Encoding": "identity"},
                )
                reponse = connexion.getresponse()
            except ssl.SSLCertVerificationError as e:
                raise NonVerifie(f"{hote} : certificat refusé ({propre(e.verify_message, 80)})") from None
            except (OSError, http.client.HTTPException) as e:
                raison = f"{hote} injoignable ({type(e).__name__} : {propre(str(e), 80)})"
                if not isinstance(e, http.client.HTTPException):
                    self.injoignables[hote] = raison
                raise NonVerifie(raison) from None
            if reponse.status in absents:
                return None
            if 300 <= reponse.status < 400:
                ailleurs = urllib.parse.urlsplit(reponse.getheader("Location") or "").hostname or "?"
                raise NonVerifie(f"{hote} : redirection (vers {propre(ailleurs, 60)}) jamais suivie")
            if reponse.status == 429 or (reponse.status == 403 and reponse.getheader("Retry-After")):
                raise NonVerifie(f"{hote} : limite de requêtes atteinte (code {reponse.status}), réessayer plus tard")
            if reponse.status != 200:
                raise NonVerifie(f"{hote} : réponse {reponse.status}")
            codage = (reponse.getheader("Content-Encoding") or "identity").strip().lower()
            if codage != "identity":
                raise NonVerifie(f"{hote} : réponse compressée ({propre(codage, 30)}) refusée")
            genre = (reponse.getheader("Content-Type") or "").split(";")[0].strip().lower()
            if genre not in types:
                raise NonVerifie(f"{hote} : type de réponse inattendu ({propre(genre, 60)})")
            annonce = reponse.getheader("Content-Length")
            if annonce is not None and (not annonce.isdigit() or int(annonce) > plafond):
                raise NonVerifie(f"{hote} : réponse trop grande ou mal annoncée ({propre(annonce, 30)} octets)")
            morceaux, total = [], 0
            while True:
                if time.monotonic() - debut > self.delai_total:
                    raise NonVerifie(f"{hote} : délai dépassé ({self.delai_total} s)")
                try:
                    morceau = reponse.read1(65536)
                except (OSError, http.client.HTTPException) as e:
                    raise NonVerifie(f"{hote} : lecture interrompue ({type(e).__name__})") from None
                if not morceau:
                    break
                total += len(morceau)
                if total > plafond:
                    raise NonVerifie(f"{hote} : réponse de plus de {plafond} octets refusée")
                morceaux.append(morceau)
            return b"".join(morceaux)
        finally:
            connexion.close()

    def json(self, hote, chemin, **options):
        corps = self.obtenir(hote, chemin, **options)
        return None if corps is None else json_strict(corps)


def quoter(identifiant):
    return urllib.parse.quote(identifiant, safe="")


# ── Chaque source : une liste de constats (vide : saine), ou NonVerifie ──


def arch(client, nom):
    reponse = client.json("archlinux.org", f"/packages/search/json/?name={quoter(nom)}")
    if not isinstance(reponse, dict) or not isinstance(reponse.get("results"), list):
        raise NonVerifie("archlinux.org : réponse sans liste de résultats")
    trouves = []
    for r in reponse["results"]:
        if not isinstance(r, dict):
            raise NonVerifie("archlinux.org : résultat illisible")
        if r.get("pkgname") == nom and r.get("repo") in DEPOTS_ARCH:
            trouves.append(r)
    if not trouves:
        return [("absent", "ni dans core, ni extra, ni multilib")]
    constats = []
    for r in trouves:
        drapeau = r.get("flag_date")
        if drapeau is not None:
            if not isinstance(drapeau, str):
                raise NonVerifie("archlinux.org : flag_date illisible")
            constats.append(("perime", f"{r['repo']}/{nom} {propre(r.get('pkgver'), 40)} depuis le {propre(drapeau, 10)}"))
    return constats


def normaliser_licences(expression):
    """Les identifiants SPDX d'une expression, sans -only, -or-later ni + (une même licence, plus ou moins large) ;
    les exceptions (après WITH) laissées de côté."""
    morceaux = re.split(r"[\s()]+", expression)
    ids, apres_with = set(), False
    for m in morceaux:
        if not m:
            continue
        if m.upper() in ("AND", "OR"):
            continue
        if m.upper() == "WITH":
            apres_with = True
            continue
        if apres_with:
            apres_with = False
            continue
        for fin in ("-only", "-or-later", "+"):
            if m.endswith(fin):
                m = m[: -len(fin)]
                break
        ids.add(m.upper())
    return ids


def flathub(client, appli, licence, pas_libre):
    reponse = client.json("flathub.org", f"/api/v2/appstream/{quoter(appli)}")
    if reponse is None:
        return [("absent", "Flathub répond 404")]
    if not isinstance(reponse, dict) or reponse.get("id") != appli:
        raise NonVerifie("flathub.org : réponse d'une autre application, ou illisible")
    constats = []
    eol = reponse.get("is_eol")
    if not isinstance(eol, bool):
        raise NonVerifie("flathub.org : is_eol illisible")
    if eol:
        constats.append(("fin-de-vie", "is_eol"))
    meta = reponse.get("metadata")
    verifie = meta.get("flathub::verification::verified") if isinstance(meta, dict) else None
    if verifie not in (True, False, None):
        raise NonVerifie("flathub.org : état de vérification illisible")
    if verifie is not True:
        constats.append(("editeur-non-verifie", "l'éditeur n'a pas vérifié l'application sur Flathub"))
    libre = reponse.get("is_free_license")
    projet = reponse.get("project_license")
    if not isinstance(libre, bool) or not isinstance(projet, str):
        raise NonVerifie("flathub.org : licence illisible")
    attendu_libre = licence is not None and not pas_libre
    dit = f"Flathub : {propre(projet, 80)} ({'libre' if libre else 'non libre'})"
    if libre != attendu_libre:
        attendu = "libre" if attendu_libre else "non libre"
        constats.append(("licence", f"le catalogue la dit {attendu} ; {dit}"))
    elif attendu_libre:
        manquants = normaliser_licences(licence) - normaliser_licences(projet)
        if manquants:
            constats.append(("licence", f"catalogue {licence} ; {dit}"))
    return constats


def lire_index_winget(client, aujourd_hui):
    """Les identifiants de l'index de winget (source2.msix), en minuscules → identifiant exact ; tout en mémoire."""
    corps = client.obtenir(
        "cdn.winget.microsoft.com",
        "/cache/source2.msix",
        plafond=PLAFOND_MSIX,
        types=("application/octet-stream", "application/vnd.ms-appx", "application/msix"),
        absents=(),
    )
    try:
        archive = zipfile.ZipFile(io.BytesIO(corps))
        info = archive.getinfo("Public/index.db")
        if info.file_size > PLAFOND_INDEX:
            raise NonVerifie("index de winget trop grand")
        with archive.open(info) as f:
            # Lu jusqu'au plafond + 1, quoi que dise l'en-tête de l'archive (une bombe peut mentir sur sa taille).
            donnees = f.read(PLAFOND_INDEX + 1)
        if len(donnees) > PLAFOND_INDEX:
            raise NonVerifie("index de winget trop grand")
    except NonVerifie:
        raise
    except (zipfile.BadZipFile, KeyError, OSError, EOFError, ValueError, NotImplementedError) as e:
        raise NonVerifie(f"index de winget illisible ({type(e).__name__})") from None
    base = sqlite3.connect(":memory:")
    try:
        # Base venue d'ailleurs : mode défensif, ni déclencheur ni vue, schéma non fiable, lecture seule, temps borné.
        base.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        base.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)
        base.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_TRIGGER, False)
        base.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_VIEW, False)
        fin = time.monotonic() + 30
        base.set_progress_handler(lambda: 1 if time.monotonic() > fin else 0, 10000)
        base.deserialize(donnees)
        base.execute("PRAGMA query_only = 1")
        if base.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise NonVerifie("index de winget abîmé (quick_check)")
        genre = base.execute("SELECT type FROM sqlite_master WHERE name = 'packages'").fetchall()
        if genre != [("table",)]:
            raise NonVerifie("index de winget sans table packages")
        colonnes = {r[1] for r in base.execute("PRAGMA table_info(packages)")}
        if not {"id"} <= colonnes:
            raise NonVerifie("index de winget sans colonne id")
        meta = dict(base.execute("SELECT name, value FROM metadata WHERE name = 'lastwritetime'").fetchall())
        ecrit = meta.get("lastwritetime")
        if not isinstance(ecrit, str) or not ecrit.isdigit() or len(ecrit) > 12:
            raise NonVerifie("index de winget sans date lisible")
        date = datetime.datetime.fromtimestamp(int(ecrit), datetime.UTC).date()
        age = (aujourd_hui - date).days
        if age > INDEX_WINGET_AGE_MAX or age < -2:
            raise NonVerifie(f"index de winget daté du {date} : trop vieux (ou dans le futur) pour conclure")
        ids = {}
        for (ident,) in base.execute("SELECT id FROM packages"):
            if isinstance(ident, str):
                ids.setdefault(ident.lower(), ident)
        if not ids:
            raise NonVerifie("index de winget vide")
        return ids, date
    except sqlite3.Error as e:
        raise NonVerifie(f"index de winget illisible ({type(e).__name__})") from None
    finally:
        base.close()


def winget(index, ident):
    exact = index.get(ident.lower())
    if exact is None:
        return [("absent", "pas dans l'index de winget")]
    return []


def debian(client, nom):
    reponse = client.json("api.ftp-master.debian.org", f"/madison?package={quoter(nom)}&f=json&s=stable")
    if not isinstance(reponse, list):
        raise NonVerifie("api.ftp-master.debian.org : réponse illisible")
    sections = set()
    for bloc in reponse:
        if not isinstance(bloc, dict):
            raise NonVerifie("api.ftp-master.debian.org : réponse illisible")
        suites = bloc.get(nom, {})
        if not isinstance(suites, dict):
            raise NonVerifie("api.ftp-master.debian.org : réponse illisible")
        for versions in suites.values():
            if not isinstance(versions, dict):
                raise NonVerifie("api.ftp-master.debian.org : réponse illisible")
            for v in versions.values():
                if not isinstance(v, dict) or not isinstance(v.get("architectures"), list):
                    raise NonVerifie("api.ftp-master.debian.org : réponse illisible")
                # Un paquet binaire : construit pour amd64 ou pour toutes (pas seulement « source »).
                if any(a in ("amd64", "all") for a in v["architectures"]):
                    sections.add(v.get("component"))
    if not sections:
        return [("absent", "pas de paquet binaire dans stable")]
    if "main" not in sections:
        return [("hors-main", "stable, section " + ", ".join(propre(s, 20) for s in sections))]
    return []


def branche_fedora(client):
    reponse = client.json("mdapi.fedoraproject.org", "/branches")
    if not isinstance(reponse, list):
        raise NonVerifie("mdapi.fedoraproject.org : liste des versions illisible")
    nums = [int(b[1:]) for b in reponse if isinstance(b, str) and re.fullmatch(r"f[0-9]{2,3}", b)]
    if not nums:
        raise NonVerifie("mdapi.fedoraproject.org : aucune version publiée dans la liste")
    return f"f{max(nums)}"


def fedora(client, branche, nom):
    # mdapi répond 400 (pas 404) pour un nom qu'il n'a pas : compté absent, une dégradation qui arrête la publication
    # (jamais une source saine), à revoir à la main si mdapi change.
    reponse = client.json("mdapi.fedoraproject.org", f"/{branche}/pkg/{quoter(nom)}", absents=(404, 400))
    if reponse is None:
        return [("absent", f"pas dans Fedora {branche[1:]}")]
    if not isinstance(reponse, dict) or not isinstance(reponse.get("version"), str):
        raise NonVerifie("mdapi.fedoraproject.org : réponse illisible")
    return []


# ── Catalogue et liste des admis ──


def lire_catalogue(chemin):
    with open(chemin, "rb") as f:
        cat = json_strict(f.read())
    if not isinstance(cat, dict) or cat.get("format") != 1 or not isinstance(cat.get("logiciels"), list):
        raise NonVerifie(f"{chemin} : format inattendu")
    pas_libre = cat.get("flathub_pas_libre")
    if not isinstance(pas_libre, list) or not all(isinstance(x, str) for x in pas_libre):
        raise NonVerifie(f"{chemin} : flathub_pas_libre illisible")
    return cat["logiciels"], set(pas_libre)


def valide(genre, ident):
    return isinstance(ident, str) and len(ident) <= 128 and MOTIFS[genre].fullmatch(ident) is not None


def taches(logiciels):
    """(source, identifiant, logiciel) à vérifier, et les identifiants refusés (jamais envoyés)."""
    a_faire, refuses = [], []
    for l in logiciels:
        if not isinstance(l, dict) or not isinstance(l.get("nom"), str):
            refuses.append(("?", "?", "entrée du catalogue illisible"))
            continue
        paquets = l.get("paquets")
        if not isinstance(paquets, dict) or set(paquets) != {"arch", "debian", "fedora", "opensuse"}:
            refuses.append(("?", propre(l["nom"], 40), "paquets illisibles"))
            continue
        for source in ("arch", "debian", "fedora", "opensuse"):
            liste = paquets[source]
            if not isinstance(liste, list):
                refuses.append((source, propre(l["nom"], 40), "liste illisible"))
                continue
            for p in liste:
                if valide("paquet", p):
                    a_faire.append((source, p, l))
                else:
                    refuses.append((source, propre(p, 40), "identifiant hors de l'alphabet permis"))
        for source, genre in (("flathub", "flatpak"), ("winget", "winget")):
            ident = l.get("flatpak" if source == "flathub" else "winget")
            if ident is None:
                continue
            if valide(genre, ident):
                a_faire.append((source, ident, l))
            else:
                refuses.append((source, propre(ident, 40), "identifiant hors de l'alphabet permis"))
    return a_faire, refuses


def lire_admis(chemin, aujourd_hui):
    """Les dégradations admises encore valables : {(source, identifiant, constat): (raison, date, jusqu_au)}, et
    celles échues (redevenues des dégradations, dites)."""
    with open(chemin, "rb") as f:
        donnees = json_strict(f.read())
    if not isinstance(donnees, dict) or donnees.get("format") != 1 or not isinstance(donnees.get("admis"), list):
        raise NonVerifie(f"{chemin} : format inattendu")
    admis, echus = {}, []
    for a in donnees["admis"]:
        champs = ("source", "identifiant", "constat", "raison", "date", "jusqu_au")
        if not isinstance(a, dict) or set(a) != set(champs) or not all(isinstance(a[c], str) for c in champs):
            raise NonVerifie(f"{chemin} : entrée illisible (champs attendus : {', '.join(champs)})")
        if a["source"] not in SOURCES or a["constat"] not in CONSTATS or len(a["raison"].strip()) < 10:
            raise NonVerifie(f"{chemin} : entrée {propre(a['identifiant'], 40)} : source, constat ou raison refusé")
        try:
            date = datetime.date.fromisoformat(a["date"])
            jusqu = datetime.date.fromisoformat(a["jusqu_au"])
        except ValueError:
            raise NonVerifie(f"{chemin} : date illisible pour {propre(a['identifiant'], 40)}") from None
        if jusqu < date or (jusqu - date).days > 366:
            raise NonVerifie(f"{chemin} : {propre(a['identifiant'], 40)} admis plus d'un an, ou jusqu_au avant date")
        cle = (a["source"], a["identifiant"], a["constat"])
        if cle in admis:
            raise NonVerifie(f"{chemin} : {propre(a['identifiant'], 40)} admis deux fois")
        if jusqu < aujourd_hui:
            echus.append((cle, a["jusqu_au"]))
        else:
            admis[cle] = (a["raison"], a["date"], a["jusqu_au"])
    return admis, echus


# ── Le passage ──


def controler(client, logiciels, pas_libre, admis, echus, aujourd_hui, hors_ligne=False):
    """Écrit le compte rendu sur la sortie et rend le code de sortie."""
    a_faire, refuses = taches(logiciels)
    degradations, admises, non_verifies, sains, non_couverts, infos = [], [], [], 0, 0, []
    for source, ident, raison in refuses:
        non_verifies.append((source, ident, raison))
    index, branche, erreur_index, erreur_branche = None, None, None, None
    for source, ident, logiciel in a_faire:
        if source == "opensuse":
            non_couverts += 1
            continue
        if hors_ligne:
            non_verifies.append((source, ident, "hors ligne demandé (VANGUARD_HORS_LIGNE=1)"))
            continue
        try:
            if source == "arch":
                constats = arch(client, ident)
            elif source == "debian":
                constats = debian(client, ident)
            elif source == "fedora":
                if branche is None and erreur_branche is None:
                    try:
                        branche = branche_fedora(client)
                    except NonVerifie as e:
                        erreur_branche = str(e)
                if erreur_branche:
                    raise NonVerifie(erreur_branche)
                constats = fedora(client, branche, ident)
            elif source == "flathub":
                constats = flathub(client, ident, logiciel.get("licence"), ident in pas_libre)
            else:
                if index is None and erreur_index is None:
                    try:
                        index = lire_index_winget(client, aujourd_hui)
                    except NonVerifie as e:
                        erreur_index = str(e)
                if erreur_index:
                    raise NonVerifie(erreur_index)
                constats = winget(index[0], ident)
        except NonVerifie as e:
            non_verifies.append((source, ident, str(e)))
            continue
        for constat, detail in constats:
            if constat in INFOS:
                infos.append((constat, detail, source, ident, logiciel["nom"]))
        constats = [c for c in constats if c[0] not in INFOS]
        if not constats:
            sains += 1
        for constat, detail in constats:
            cle = (source, ident, constat)
            if cle in admis:
                admises.append((cle, detail, admis[cle]))
            else:
                degradations.append((cle, detail, logiciel["nom"]))
    for cle, jusqu in echus:
        # Une admission échue qui ne correspond plus à rien n'est pas une dégradation : seulement dite.
        if any(d[0] == cle for d in degradations):
            print(f"  ! admission échue le {jusqu} : {cle[0]} {cle[1]} ({cle[2]})")

    for (source, ident, constat), detail, nom in degradations:
        print(f"  ✖ {propre(nom, 40)} · {source} {ident} : {CONSTATS[constat]} ({propre(detail, 200)})")
    for (source, ident, constat), detail, (raison, date, jusqu) in admises:
        print(f"  ≈ {source} {ident} : {CONSTATS[constat]}, admis le {date} jusqu'au {jusqu} ({propre(raison, 120)})")
    for source, ident, raison in non_verifies:
        print(f"  ? {source} {ident} : non vérifié ({propre(raison, 200)})")
    for constat, detail, source, ident, nom in infos:
        print(f"  ℹ {propre(nom, 40)} · {source} {ident} : {INFOS[constat]} ({propre(detail, 200)}) : dit, sans effet")
    if index is not None:
        print(f"  · index de winget du {index[1]} ({len(index[0])} identifiants)")
    if branche is not None:
        print(f"  · Fedora : {branche}, Debian : stable, Arch : {', '.join(DEPOTS_ARCH)}")
    print(f"  · non couverts : {non_couverts} paquet(s) openSUSE (aucune API publique simple) ; aucun cask au catalogue")
    if degradations:
        print(
            f"Sources : {len(degradations)} dégradation(s), {len(non_verifies)} non vérifiée(s), {sains} saine(s), "
            f"{len(admises)} admise(s)."
        )
        return 1
    if non_verifies:
        print(f"Sources : {len(non_verifies)} non vérifiée(s), {sains} saine(s), {len(admises)} admise(s) : rien conclu.")
        return 2
    if sains + len(admises) == 0:
        print("Sources : aucune source vérifiée : rien conclu.")
        return 2
    print(f"Sources : {sains + len(admises)} vérifiée(s), saines ({len(admises)} admise(s)).")
    return 0


def principal(argv, client=None, aujourd_hui=None):
    catalogue, admis_chemin = CATALOGUE, ADMIS
    args = list(argv)
    while args:
        option = args.pop(0)
        if option in ("--catalogue", "--admis") and args:
            valeur = args.pop(0)
            if option == "--catalogue":
                catalogue = valeur
            else:
                admis_chemin = valeur
        else:
            print(f"usage : controle-sources.py [--catalogue F] [--admis F] (option refusée : {propre(option, 40)})")
            return 2
    aujourd_hui = aujourd_hui or datetime.datetime.now(datetime.UTC).date()
    try:
        logiciels, pas_libre = lire_catalogue(catalogue)
        admis, echus = lire_admis(admis_chemin, aujourd_hui)
    except (OSError, NonVerifie) as e:
        print(f"Sources : rien conclu, lecture impossible ({propre(str(e), 200)}).")
        return 2
    hors_ligne = os.environ.get("VANGUARD_HORS_LIGNE") == "1"
    return controler(client or Client(), logiciels, pas_libre, admis, echus, aujourd_hui, hors_ligne)


if __name__ == "__main__":
    try:
        code = principal(sys.argv[1:])
    except Exception as e:  # noqa: BLE001 : une panne est dite « rien conclu », jamais prise pour un constat
        print(f"Sources : rien conclu, panne de l'outil ({type(e).__name__} : {propre(str(e), 160)}).")
        code = 2
    sys.exit(code)
