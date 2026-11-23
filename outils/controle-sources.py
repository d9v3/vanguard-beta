#!/usr/bin/env python3
"""Contrôle des sources du catalogue des logiciels, avant chaque publication (conception-interface, ligne C5).

Une source peut se dégrader en quelques mois (Bitwarden : extra/bitwarden marqué périmé, licence Flathub devenue non
libre). Pour chaque source du catalogue compilé (`--catalogue` : à la publication, celui qu'imprime le programme Linux
qui part, `vanguard deploiement catalogue-sources` ; sans option, outils/catalogue-sources.json, sa copie tenue à
jour par l'essai Rust logiciels::tests::catalogue_exporte_a_jour ; jamais lu dans le source par motifs) :
  - Arch : le paquet est dans core, extra ou multilib, et n'y est pas marqué périmé (flag_date, clé exigée) ;
  - Flathub : l'application existe, n'est pas en fin de vie, est vérifiée par son éditeur, et sa licence dit ce que dit
    le catalogue (libre ou non, exactement les mêmes identifiants SPDX ; FLATHUB_PAS_LIBRE : non libre) ;
  - winget : l'identifiant, casse comprise (le programme installe avec --exact), est dans l'index que télécharge winget lui-même (source2.msix du CDN de Microsoft, bâti
    depuis le dépôt microsoft/winget-pkgs ; sans l'API de GitHub, limitée à 60 requêtes par heure sans jeton) ;
  - Debian : le paquet binaire est dans stable, section main (API madison de ftp-master ; toute autre suite dans la
    réponse : non vérifié) ;
  - Fedora : le paquet est dans la dernière version publiée, la plus haute « current » de Bodhi (jamais rawhide ni une
    version en préparation, que mdapi liste aussi), cherché dans mdapi (le nom rendu doit être celui demandé) ;
  - openSUSE : non couvert (aucune API publique simple en JSON sans compte), dit et compté. Aucun cask au catalogue ;
  - Ubuntu et ses dérivées : non couvertes, dit (le programme y prend les noms de Debian, firefox-esr devenu firefox).

Codes de sortie : 0 tout vérifié et sain (les dégradations admises sont montrées) ; 1 au moins une dégradation non
admise ; 2 rien de dégradé trouvé, mais au moins une source non vérifiée (réseau, délai, réponse illisible, limite),
ou l'outil n'a pas pu juger. Un code 1 dit toujours « Sources : N dégradation(s) », un code 0 « Sources : N
vérifiée(s), saines » : outils/publier-version.sh exige ce témoin (une trace de Python sort aussi en 1). Il tourne
avant la page de la version, après l'envoi du code sur master par deployer.sh : une source dégradée retarde la page,
pas le code. Une panne sur une seule source (réponse piégée qui fait lever n'importe quoi) rend cette source non
vérifiée, jamais tout le passage : les dégradations déjà trouvées ailleurs restent dites, et le code 1 tient.

Une dégradation connue n'est admise que par outils/controle-sources-admis.json (versionné, format 2 : source,
identifiant, constat, detail, raison, date, jusqu_au). L'admission vaut pour la valeur exacte constatée (detail) :
si le constat du jour dit autre chose (autre licence, autre date du drapeau), c'est une dégradation. Passé jusqu_au,
elle redevient une dégradation ; une admission qui ne sert plus à rien est dite (« admission inutile »).

Ce qui vient d'Internet est une donnée : HTTPS seulement, certificat vérifié contre le magasin du système (le chemin
compilé dans OpenSSL, jamais SSL_CERT_FILE ni SSL_CERT_DIR ; OPENSSL_CONF, OPENSSL_MODULES, OPENSSL_ENGINES posées :
rien conclu), hôtes en liste fermée, aucune redirection suivie, délai par opération, pour toute la requête (résolution
du nom et connexion comprises) et pour tout le passage, taille plafonnée, longueur annoncée tenue, JSON strict (clés en double, NaN refusés), types vérifiés ;
tout texte distant affiché est assaini (contrôles, bidi, invisibles retirés). Rien n'est écrit : tout reste en
mémoire (l'index de winget compris, ouvert par sqlite3 en mémoire, en mode défensif, valeurs plafonnées, schéma
exigé colonne par colonne avant toute lecture : ni vue, ni table virtuelle, ni colonne calculée). Aucun shell.
Essais hors ligne : outils/essais-controle-sources.py (faux serveur HTTPS local), lancé par verifier.sh.
  python3 -I outils/controle-sources.py [--catalogue F] [--admis F]
"""

import datetime
import hashlib
import http.client
import io
import json
import lzma
import os
import re
import socket
import sqlite3
import ssl
import sys
import threading
import time
import unicodedata
import urllib.parse
import zipfile
import zlib

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
    "bodhi.fedoraproject.org": ("/releases/",),
}
DELAI = 20  # secondes par opération réseau (connexion, lecture d'un morceau)
DELAI_TOTAL = 60  # secondes par requête, de la résolution du nom à la fin de la lecture (un serveur qui goutte)
# Secondes pour tout le passage : une centaine de requêtes qui répondent chacune juste sous DELAI_TOTAL tiendraient
# sinon la publication plus d'une heure (campagne C5, n° 2 et 9). Au-delà, chaque source restante est non vérifiée.
DELAI_PASSAGE = 600
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
    "casse": "identifiant d'une autre casse dans l'index (winget --exact ne le trouve pas)",
}
# Dits (ligne « ℹ »), jamais une dégradation : ils ne changent pas le code de sortie, ni ne s'admettent. Un éditeur
# qui n'a pas vérifié son application sur Flathub n'est pas une source qui s'est dégradée (beaucoup ne l'ont jamais
# fait), mais vaut d'être su avant de la proposer.
INFOS = {
    "editeur-non-verifie": "pas vérifié par son éditeur",
}


class NonVerifie(Exception):
    """Une source qu'on n'a pas pu juger : jamais comptée saine."""


# Caractères qui s'affichent vides, ou comme une lettre de remplissage, sans être des contrôles (catégorie Lo) : ils
# servaient à pousser un faux « Sources : … saines » en début de ligne visuelle (campagne C5, n° 10).
REMPLISSAGE = {"\u115f", "\u1160", "\u3164", "\uffa0", "\u2800"}
# Classes bidi qui changent le sens de ce qui suit, même portées par un caractère d'une autre catégorie.
BIDI_ACTIFS = {"R", "AL", "RLE", "RLO", "LRE", "LRO", "PDF", "RLI", "LRI", "FSI", "PDI"}


def propre(texte, longueur=160):
    """Un texte venu d'ailleurs, sans rien qui agisse sur le terminal : contrôles (ESC compris), invisibles (Cf),
    marques qui se combinent (Mn, Me), espaces autres que l'espace simple, séparateurs de ligne, caractères de
    remplissage, lettres de droite à gauche et caractères non attribués deviennent « ? » ; coupé à `longueur`."""
    if not isinstance(texte, str):
        texte = repr(texte)
    sortie = []
    for c in texte[: longueur + 1]:
        cat = unicodedata.category(c)
        mauvais = (
            cat[0] == "C"
            or cat in ("Zl", "Zp", "Mn", "Me")
            or (cat == "Zs" and c != " ")
            or c in REMPLISSAGE
            or unicodedata.bidirectional(c) in BIDI_ACTIFS
        )
        sortie.append("?" if mauvais else c)
    t = "".join(sortie)
    return t if len(t) <= longueur else t[:longueur] + "…"


def exact(texte, longueur):
    """`propre(texte, longueur)`, suivi de l'empreinte de la valeur entière quand l'affichage la change ou la coupe :
    une admission (liée au détail) vaut alors pour toute la valeur, pas pour ses `longueur` premiers caractères
    (campagne C5, n° 8 et 14)."""
    vu = propre(texte, longueur)
    if vu == texte:
        return vu
    brut = texte if isinstance(texte, str) else repr(texte)
    return f"{vu} [sha256:{hashlib.sha256(brut.encode('utf-8', 'surrogatepass')).hexdigest()[:16]}]"


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


# Variables lues par OpenSSL au chargement de Python, avant qu'on puisse rien y faire : un fichier de configuration
# ou un module (fournisseur, moteur) qu'elles désignent peut changer ce que « certificat vérifié » veut dire.
ENV_OPENSSL = ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES")


def contexte_tls():
    """Le contexte TLS du vrai passage. Pourquoi pas ssl.create_default_context() : il charge le magasin par
    set_default_verify_paths, qui suit SSL_CERT_FILE et SSL_CERT_DIR même sous python3 -I ; une variable posée par
    un profil suffisait à faire accepter une autorité de complaisance. Ici, le magasin est le chemin compilé dans
    OpenSSL (openssl_cafile, openssl_capath : ceux du système), donné explicitement : l'environnement n'y peut rien,
    que le script soit lancé par publier-version.sh ou à la main. Sans magasin lisible : rien vérifié."""
    chemins = ssl.get_default_verify_paths()
    fichier = chemins.openssl_cafile if chemins.openssl_cafile and os.path.isfile(chemins.openssl_cafile) else None
    dossier = chemins.openssl_capath if chemins.openssl_capath and os.path.isdir(chemins.openssl_capath) else None
    if fichier is None and dossier is None:
        raise NonVerifie("aucun magasin de certificats du système lisible")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_verify_locations(cafile=fichier, capath=dossier)
    except (OSError, ssl.SSLError) as e:
        raise NonVerifie(f"magasin de certificats du système illisible ({type(e).__name__})") from None
    return ctx


class Client:
    """HTTPS vers les seuls hôtes permis. `ctx` et `relier` ne changent que dans les essais (autorité et faux
    serveur locaux) : le nom vérifié dans le certificat reste toujours celui de l'hôte permis."""

    def __init__(
        self, ctx=None, relier=None, pause=PAUSE, delai=DELAI, delai_total=DELAI_TOTAL, delai_passage=DELAI_PASSAGE
    ):
        # Une panne du magasin est gardée pour chaque requête (non vérifiée), pas levée ici : le compte rendu sort.
        self.ctx, self.erreur_ctx = ctx, None
        if self.ctx is None:
            try:
                self.ctx = contexte_tls()
            except NonVerifie as e:
                self.erreur_ctx = str(e)
        if self.ctx is not None:
            self.ctx.check_hostname = True
            self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.relier = relier or (lambda hote: (hote, 443))
        self.pause = pause
        self.delai = delai
        self.delai_total = delai_total
        self.delai_passage = delai_passage
        self.fin_passage = time.monotonic() + delai_passage
        self.injoignables = {}
        self.requetes = 0

    def obtenir(self, hote, chemin, plafond=PLAFOND_JSON, types=("application/json",), absents=(404,)):
        """Le corps d'une réponse 200 (ou None pour un code de `absents`) ; tout le reste lève NonVerifie."""
        if hote not in HOTES or not any(chemin.startswith(p) for p in HOTES[hote]):
            raise NonVerifie(f"requête hors de la liste fermée : {propre(hote)}{propre(chemin)}")
        if self.erreur_ctx:
            raise NonVerifie(self.erreur_ctx)
        if hote in self.injoignables:
            raise NonVerifie(self.injoignables[hote])
        passage = f"délai du passage dépassé ({self.delai_passage} s pour toutes les sources)"
        if time.monotonic() + self.pause >= self.fin_passage:
            raise NonVerifie(passage)
        if self.requetes:
            time.sleep(self.pause)
        self.requetes += 1
        ctx, (adresse, port), delai = self.ctx, self.relier(hote), self.delai
        prises, echu = [], threading.Event()
        # L'échéance de la requête est aussi bornée par celle du passage : la dernière requête n'en déborde pas.
        duree = min(self.delai_total, self.fin_passage - time.monotonic())
        fin_requete = time.monotonic() + duree
        coupe_passage = duree < self.delai_total

        def echue():
            return echu.is_set() or time.monotonic() >= fin_requete

        def reste():
            return max(0.01, min(delai, fin_requete - time.monotonic()))

        class Connexion(http.client.HTTPSConnection):
            def connect(self):
                # Pourquoi pas socket.create_connection : sa résolution du nom n'a aucun délai, et il essaie chaque
                # adresse pendant `delai` entier ; un hôte à N adresses muettes tenait N × 20 s, hors de l'échéance
                # de la requête (campagne C5, n° 1). Ici, la résolution tourne dans un fil borné, et chaque
                # tentative n'a que le temps qui reste à la requête.
                trouve = []

                def resoudre():
                    try:
                        trouve.append(socket.getaddrinfo(adresse, port, type=socket.SOCK_STREAM))
                    except OSError as e:
                        trouve.append(e)

                fil = threading.Thread(target=resoudre, daemon=True)
                fil.start()
                fil.join(reste())
                if not trouve:
                    raise TimeoutError("résolution du nom trop lente")
                if isinstance(trouve[0], OSError):
                    raise trouve[0]
                derniere = OSError("aucune adresse")
                for famille, genre, proto, _, ou in trouve[0]:
                    if echue():
                        raise TimeoutError("échéance de la requête atteinte pendant la connexion")
                    brute = socket.socket(famille, genre, proto)
                    prises.append(brute)  # avant connect : la coupure la voit dès qu'elle existe
                    try:
                        brute.settimeout(reste())
                        brute.connect(ou)
                    except OSError as e:
                        derniere = e
                        brute.close()
                        continue
                    # Le nom vérifié est l'hôte permis, quelle que soit l'adresse jointe. Une coupure sans
                    # close_notify est une erreur, pas une fin de corps.
                    self.sock = ctx.wrap_socket(brute, server_hostname=hote, suppress_ragged_eofs=False)
                    prises.append(self.sock)
                    self.sock.settimeout(delai)
                    return
                raise derniere

        def couper():
            # L'échéance de toute la requête : le délai par opération ne borne pas un serveur qui goutte ses en-têtes
            # ou son corps un octet à la fois. On ferme la prise sous la lecture en cours (la méthode de socket.socket,
            # pas celle de SSLSocket qui oublierait l'état TLS), la lecture bloquée rend la main aussitôt.
            echu.set()
            for prise in list(prises):
                try:
                    socket.socket.shutdown(prise, socket.SHUT_RDWR)
                except OSError:
                    pass

        def depasse():
            if coupe_passage:
                return NonVerifie(passage)
            raison = f"{hote} : délai dépassé ({self.delai_total} s pour toute la requête)"
            self.injoignables[hote] = raison
            return NonVerifie(raison)

        minuterie = threading.Timer(duree, couper)
        minuterie.daemon = True
        connexion = Connexion(hote, 443, timeout=delai, context=ctx)
        minuterie.start()
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
                if echue():
                    raise depasse() from None
                raison = f"{hote} injoignable ({type(e).__name__} : {propre(str(e), 80)})"
                if not isinstance(e, http.client.HTTPException):
                    self.injoignables[hote] = raison
                raise NonVerifie(raison) from None
            if echue():
                raise depasse()
            if reponse.status in absents:
                return None
            if 300 <= reponse.status < 400:
                try:
                    ailleurs = urllib.parse.urlsplit(reponse.getheader("Location") or "").hostname or "?"
                except ValueError:  # « http://[x » : une adresse qui ne se découpe pas
                    ailleurs = "?"
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
            # Des chiffres ASCII seulement : str.isdigit() dit vrai pour « ² », que int() refuse.
            if annonce is not None and (not re.fullmatch(r"[0-9]{1,12}", annonce) or int(annonce) > plafond):
                raise NonVerifie(f"{hote} : réponse trop grande ou mal annoncée ({propre(annonce, 30)} octets)")
            morceaux, total = [], 0
            while True:
                try:
                    morceau = reponse.read1(65536)
                except (OSError, http.client.HTTPException) as e:
                    if echue():
                        raise depasse() from None
                    raise NonVerifie(f"{hote} : lecture interrompue ({type(e).__name__})") from None
                if echue():
                    raise depasse()
                if not morceau:
                    break
                total += len(morceau)
                if total > plafond:
                    raise NonVerifie(f"{hote} : réponse de plus de {plafond} octets refusée")
                morceaux.append(morceau)
            # read1 ne lève pas IncompleteRead : un corps coupé avant la longueur annoncée finit comme un vrai.
            if annonce is not None and total != int(annonce):
                raise NonVerifie(f"{hote} : réponse incomplète ({total} octets sur {annonce} annoncés)")
            return b"".join(morceaux)
        finally:
            minuterie.cancel()
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
        # La clé est exigée : une réponse qui l'omet ne dit pas « pas périmé » (null le dit), elle ne dit rien.
        if "flag_date" not in r:
            raise NonVerifie("archlinux.org : flag_date absent de la réponse")
        drapeau = r["flag_date"]
        if drapeau is not None:
            if not isinstance(drapeau, str):
                raise NonVerifie("archlinux.org : flag_date illisible")
            # Valeurs entières liées (empreinte si l'affichage les coupe) : une admission vaut pour ce drapeau-là.
            constats.append(("perime", f"{r['repo']}/{nom} {exact(r.get('pkgver'), 40)} depuis le {exact(drapeau, 40)}"))
    return constats


def normaliser_licences(expression):
    """Les identifiants SPDX d'une expression, sans -only, -or-later ni + (une même licence, plus ou moins large) ;
    les exceptions (après WITH) laissées de côté. Un morceau hors de l'alphabet SPDX : rien conclu (jamais deviné)."""
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
        if not m:
            continue  # un « + » isolé : rien à comparer
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,80}", m):
            raise NonVerifie(f"licence illisible ({propre(m, 40)})")
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
    dit = f"Flathub : {exact(projet, 80)} ({'libre' if libre else 'non libre'})"
    if libre != attendu_libre:
        attendu = "libre" if attendu_libre else "non libre"
        constats.append(("licence", f"le catalogue la dit {attendu} ; {dit}"))
    elif attendu_libre and normaliser_licences(licence) != normaliser_licences(projet):
        # Les mêmes identifiants, dans les deux sens : une licence ajoutée par Flathub (« MIT AND LicenseRef-x »)
        # change ce qu'on installe autant qu'une licence retirée (campagne C5, n° 7 et 13).
        constats.append(("licence", f"catalogue {licence} ; {dit}"))
    return constats


# Le schéma exigé des deux tables lues, colonne par colonne : (nom, type déclaré), dans l'ordre. Comparé à ce que
# rend pragma_table_xinfo (le schéma analysé par SQLite), jamais au texte CREATE, qu'un commentaire déguise (n° 5).
SCHEMA_METADATA = [("name", "TEXT"), ("value", "TEXT")]
LONGUEUR_SQLITE = 1_000_000
DELAI_SQLITE = 30


def verifier_schema_winget(base):
    """Refuse toute base qui ferait évaluer du code en la lisant : chaque objet de main doit être une table
    ordinaire ou un index (ni vue, ni table virtuelle, ni ombre de table virtuelle), aucune colonne cachée ni
    calculée nulle part, et les deux tables lues ont le schéma attendu. Tout ici lit le schéma analysé par SQLite
    (pragma_table_list, pragma_table_xinfo), sans rien évaluer de la base."""
    tables = base.execute("SELECT name, type FROM pragma_table_list WHERE schema = 'main'").fetchmany(1001)
    if len(tables) > 1000:
        raise NonVerifie("index de winget avec trop de tables")
    for nom, genre in tables:
        if genre in ("virtual", "shadow"):
            # Une table virtuelle (fts5, rtree, un module chargé) ou l'une de ses tables d'ombre : son module ferait
            # le travail de la lecture. Repérée par SQLite lui-même, quel que soit le texte de sa déclaration.
            raise NonVerifie(f"index de winget avec une table virtuelle ({propre(nom, 40)}) refusé")
        if genre != "table":
            raise NonVerifie(f"index de winget avec un objet de type {propre(genre, 20)} ({propre(nom, 40)}) refusé")
    noms = {nom for nom, _ in tables}
    for table in ("packages", "metadata"):
        if table not in noms:
            raise NonVerifie(f"index de winget sans table {table}")
    colonnes = {}
    for nom in sorted(noms):
        lignes = base.execute(
            "SELECT name, upper(type), hidden FROM pragma_table_xinfo(?) ORDER BY cid", (nom,)
        ).fetchmany(1001)
        if len(lignes) > 1000:
            raise NonVerifie("index de winget avec une table trop large")
        # hidden : 1 colonne cachée (table virtuelle), 2 calculée VIRTUAL, 3 calculée STORED.
        if any(h != 0 for _, _, h in lignes):
            raise NonVerifie(f"index de winget avec une colonne cachée ou calculée ({propre(nom, 40)}) refusé")
        colonnes[nom] = [(c, t) for c, t, _ in lignes]
    if colonnes["metadata"] != SCHEMA_METADATA:
        raise NonVerifie("index de winget : table metadata au schéma inattendu")
    if ("id", "TEXT") not in colonnes["packages"]:
        raise NonVerifie("index de winget sans colonne id (TEXT)")



def lire_index_winget(client, aujourd_hui):
    """Les identifiants de l'index de winget (source2.msix), en minuscules → identifiants exacts ; tout en mémoire."""
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
    except (
        zipfile.BadZipFile,
        KeyError,
        OSError,
        EOFError,
        ValueError,
        NotImplementedError,
        zlib.error,  # flux deflate abîmé
        RuntimeError,  # entrée marquée chiffrée (« password required »)
        lzma.LZMAError,
    ) as e:
        raise NonVerifie(f"index de winget illisible ({type(e).__name__})") from None
    base = sqlite3.connect(":memory:")
    try:
        # Base venue d'ailleurs : mode défensif, ni déclencheur ni vue, schéma non fiable, lecture seule, temps borné.
        base.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        base.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)
        base.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_TRIGGER, False)
        base.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_VIEW, False)
        # Aucune valeur (texte, blob, ni le SQL d'une requête) de plus d'un million d'octets : une colonne calculée
        # qui fabrique un texte géant échoue « too big » au lieu de remplir la mémoire (campagne C5, n° 3). Posé
        # avant deserialize, pour que rien de la base ne soit lu sans lui.
        base.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, LONGUEUR_SQLITE)
        base.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 100_000)
        # La borne de temps est relue en Python toutes les 100 instructions de la machine de SQLite : une expression
        # lente (randomblob, printf géant) ne la dépasse que d'une poignée d'instructions (n° 4).
        fin = time.monotonic() + DELAI_SQLITE
        base.set_progress_handler(lambda: 1 if time.monotonic() > fin else 0, 100)
        base.deserialize(donnees)
        base.execute("PRAGMA query_only = 1")
        # quick_check évaluerait les CHECK (du code de la base) : ils sont ignorés, l'intégrité des pages reste lue.
        base.execute("PRAGMA ignore_check_constraints = 1")
        verifier_schema_winget(base)
        # Après le refus du schéma : quick_check n'a plus devant lui que deux tables ordinaires, sans colonne
        # calculée ni table virtuelle (rien de la base n'est évalué en lisant ses pages).
        verdict = base.execute("PRAGMA quick_check").fetchmany(2)
        if verdict != [("ok",)]:
            raise NonVerifie("index de winget abîmé (quick_check)")
        # Une seule ligne lastwritetime, de type texte et courte : jamais tout ramené en mémoire (fetchall).
        lignes = base.execute(
            "SELECT typeof(value), length(value), value FROM metadata WHERE name = 'lastwritetime' LIMIT 2"
        ).fetchmany(2)
        if len(lignes) != 1 or lignes[0][0] != "text" or lignes[0][1] > 11:
            raise NonVerifie("index de winget sans date lisible")
        ecrit = lignes[0][2]
        # Chiffres ASCII seulement (isdigit() accepte « ² ») ; 11 au plus, et fromtimestamp gardé : une année hors
        # de portée de datetime lève ValueError, OverflowError ou OSError.
        if not isinstance(ecrit, str) or not re.fullmatch(r"[0-9]{1,11}", ecrit):
            raise NonVerifie("index de winget sans date lisible")
        try:
            date = datetime.datetime.fromtimestamp(int(ecrit), datetime.UTC).date()
        except (ValueError, OverflowError, OSError):
            raise NonVerifie("index de winget sans date lisible") from None
        age = (aujourd_hui - date).days
        if age > INDEX_WINGET_AGE_MAX or age < -2:
            raise NonVerifie(f"index de winget daté du {date} : trop vieux (ou dans le futur) pour conclure")
        ids = {}
        for genre, longueur, ident in base.execute("SELECT typeof(id), length(id), id FROM packages"):
            # Un identifiant vraiment texte et de longueur permise ; le reste est laissé de côté sans être gardé.
            if genre == "text" and longueur <= 128 and isinstance(ident, str):
                ids.setdefault(ident.lower(), set()).add(ident)
        if not ids:
            raise NonVerifie("index de winget vide")
        return ids, date
    except (sqlite3.Error, UnicodeDecodeError) as e:
        # UnicodeDecodeError : un texte qui n'est pas de l'UTF-8 valide, que sqlite3 ne décode qu'en le lisant.
        raise NonVerifie(f"index de winget illisible ({type(e).__name__})") from None
    finally:
        base.close()


def winget(index, ident):
    """Vanguard installe par `winget install --id <id> --exact` (src/machine/windows/mod.rs) : --exact compare aussi
    la casse, selon la documentation de winget. Un identifiant qui n'existe dans l'index que dans une autre casse ne
    s'installerait donc pas : c'est un constat, pas une source saine (campagne C5, n° 6 et 12)."""
    vus = index.get(ident.lower())
    if not vus:
        return [("absent", "pas dans l'index de winget")]
    if ident not in vus:
        return [("casse", "l'index dit " + ", ".join(exact(v, 128) for v in sorted(vus)))]
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
        for suite, versions in suites.items():
            # Le filtre s=stable est fait par le serveur : on le revérifie. Une autre suite (unstable, testing)
            # ne dit rien de stable, et ne doit pas être comptée comme si.
            if suite != "stable":
                raise NonVerifie(f"api.ftp-master.debian.org : suite inattendue ({propre(suite, 30)})")
            if not isinstance(versions, dict):
                raise NonVerifie("api.ftp-master.debian.org : réponse illisible")
            for v in versions.values():
                if not isinstance(v, dict) or not isinstance(v.get("architectures"), list):
                    raise NonVerifie("api.ftp-master.debian.org : réponse illisible")
                if not isinstance(v.get("component"), str):
                    raise NonVerifie("api.ftp-master.debian.org : section illisible")
                # Un paquet binaire : construit pour amd64 ou pour toutes (pas seulement « source »).
                if any(a in ("amd64", "all") for a in v["architectures"]):
                    sections.add(v["component"])
    if not sections:
        return [("absent", "pas de paquet binaire dans stable")]
    if "main" not in sections:
        return [("hors-main", "stable, section " + ", ".join(exact(s, 20) for s in sorted(sections)))]
    return []


def branche_fedora(client):
    """La dernière version publiée de Fedora. Pourquoi Bodhi et pas le plus grand fNN de mdapi : mdapi liste toute
    branche de koji, la version en préparation comprise (f46 quand f45 est la dernière publiée) ; seul Bodhi dit
    l'état (current : publiée ; pending, frozen : pas encore). La branche retenue doit aussi être dans mdapi."""
    reponse = client.json("bodhi.fedoraproject.org", "/releases/?state=current&rows_per_page=100")
    if not isinstance(reponse, dict) or not isinstance(reponse.get("releases"), list) or reponse.get("pages") != 1:
        raise NonVerifie("bodhi.fedoraproject.org : liste des versions illisible (ou sur plusieurs pages)")
    nums = []
    for r in reponse["releases"]:
        if not isinstance(r, dict):
            raise NonVerifie("bodhi.fedoraproject.org : version illisible")
        if r.get("id_prefix") != "FEDORA":
            continue  # EPEL, conteneurs, flatpaks : pas la distribution
        nom, etat, branche = r.get("name"), r.get("state"), r.get("branch")
        if not isinstance(nom, str) or not re.fullmatch(r"F[0-9]{2,3}", nom) or branche != f"f{nom[1:]}":
            raise NonVerifie(f"bodhi.fedoraproject.org : version illisible ({propre(nom, 20)})")
        if etat != "current":
            # Demandé state=current au serveur : une autre réponse est revérifiée, jamais prise pour publiée.
            raise NonVerifie(f"bodhi.fedoraproject.org : {propre(nom, 20)} en état {propre(etat, 20)} dans les publiées")
        nums.append(int(nom[1:]))
    if not nums:
        raise NonVerifie("bodhi.fedoraproject.org : aucune version publiée dans la liste")
    branche = f"f{max(nums)}"
    branches = client.json("mdapi.fedoraproject.org", "/branches")
    if not isinstance(branches, list):
        raise NonVerifie("mdapi.fedoraproject.org : liste des versions illisible")
    if branche not in branches:
        raise NonVerifie(f"mdapi.fedoraproject.org : {branche} (dernière publiée selon Bodhi) absente de mdapi")
    return branche


def fedora(client, branche, nom):
    # mdapi répond 400 (pas 404) pour un nom qu'il n'a pas : compté absent, une dégradation qui arrête la publication
    # (jamais une source saine), à revoir à la main si mdapi change.
    reponse = client.json("mdapi.fedoraproject.org", f"/{branche}/pkg/{quoter(nom)}", absents=(404, 400))
    if reponse is None:
        return [("absent", f"pas dans Fedora {branche[1:]}")]
    if not isinstance(reponse, dict) or not isinstance(reponse.get("version"), str):
        raise NonVerifie("mdapi.fedoraproject.org : réponse illisible")
    # Le nom rendu (basename : le paquet binaire, vérifié sur mdapi) doit être celui demandé, comme l'id de Flathub.
    if reponse.get("basename") != nom:
        raise NonVerifie(f"mdapi.fedoraproject.org : réponse pour un autre paquet ({propre(reponse.get('basename'), 40)})")
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


CLES_LOGICIEL = {"nom", "licence", "paquets", "flatpak", "winget"}


def taches(logiciels):
    """(source, identifiant, logiciel) à vérifier, et les identifiants refusés (jamais envoyés). Les clés de chaque
    entrée sont exigées toutes : une clé renommée (« winget_id ») ne doit pas passer pour « pas de source »."""
    a_faire, refuses = [], []
    for l in logiciels:
        if not isinstance(l, dict) or not isinstance(l.get("nom"), str) or set(l) != CLES_LOGICIEL:
            nom = l.get("nom") if isinstance(l, dict) else "?"
            refuses.append(("?", propre(nom, 40), f"entrée du catalogue illisible (clés attendues : {', '.join(sorted(CLES_LOGICIEL))})"))
            continue
        paquets = l.get("paquets")
        if not isinstance(paquets, dict) or set(paquets) != {"arch", "debian", "fedora", "opensuse"}:
            refuses.append(("?", propre(l["nom"], 40), "paquets illisibles"))
            continue
        avant = len(a_faire)
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
            ident = l[genre]
            if ident is None:
                continue
            if valide(genre, ident):
                a_faire.append((source, ident, l))
            else:
                refuses.append((source, propre(ident, 40), "identifiant hors de l'alphabet permis"))
        # openSUSE n'est pas couvert : un logiciel qui n'a que lui (ou rien) n'a rien de vérifiable, et le dire.
        if not any(t[0] != "opensuse" for t in a_faire[avant:]):
            refuses.append(("?", propre(l["nom"], 40), "aucune source vérifiable pour ce logiciel"))
    return a_faire, refuses


CHAMPS_ADMIS = ("source", "identifiant", "constat", "detail", "raison", "date", "jusqu_au")


def lire_admis(chemin, aujourd_hui):
    """Les dégradations admises encore valables : {(source, identifiant, constat): (detail, raison, date,
    jusqu_au)}, et celles échues : [(clé, jusqu_au)]."""
    with open(chemin, "rb") as f:
        donnees = json_strict(f.read())
    if not isinstance(donnees, dict) or donnees.get("format") != 2 or not isinstance(donnees.get("admis"), list):
        raise NonVerifie(f"{chemin} : format inattendu (format 2 attendu)")
    admis, echus, vus = {}, [], set()
    for a in donnees["admis"]:
        champs = CHAMPS_ADMIS
        if not isinstance(a, dict) or set(a) != set(champs) or not all(isinstance(a[c], str) for c in champs):
            raise NonVerifie(f"{chemin} : entrée illisible (champs attendus : {', '.join(champs)})")
        # openSUSE n'est jamais jugé : une admission pour lui n'admettrait rien, elle tromperait seulement le lecteur.
        if a["source"] not in SOURCES or a["source"] == "opensuse" or a["constat"] not in CONSTATS or len(a["raison"].strip()) < 10:
            raise NonVerifie(f"{chemin} : entrée {propre(a['identifiant'], 40)} : source, constat ou raison refusé")
        if not a["detail"].strip():
            raise NonVerifie(f"{chemin} : {propre(a['identifiant'], 40)} sans detail (la valeur exacte admise)")
        try:
            date = datetime.date.fromisoformat(a["date"])
            jusqu = datetime.date.fromisoformat(a["jusqu_au"])
        except ValueError:
            raise NonVerifie(f"{chemin} : date illisible pour {propre(a['identifiant'], 40)}") from None
        if date > aujourd_hui:
            raise NonVerifie(f"{chemin} : {propre(a['identifiant'], 40)} admis à une date future ({a['date']})")
        if jusqu < date or (jusqu - date).days > 366:
            raise NonVerifie(f"{chemin} : {propre(a['identifiant'], 40)} admis plus d'un an, ou jusqu_au avant date")
        cle = (a["source"], a["identifiant"], a["constat"])
        if cle in vus:
            raise NonVerifie(f"{chemin} : {propre(a['identifiant'], 40)} admis deux fois")
        vus.add(cle)
        if jusqu < aujourd_hui:
            echus.append((cle, a["jusqu_au"]))
        else:
            admis[cle] = (a["detail"], a["raison"], a["date"], a["jusqu_au"])
    return admis, echus


# ── Le passage ──


def juger(client, source, ident, logiciel, pas_libre, aujourd_hui, etat):
    """Les constats d'une source. `etat` garde la branche de Fedora et l'index de winget (ou leur panne), lus une
    fois pour tout le passage."""
    if source == "arch":
        return arch(client, ident)
    if source == "debian":
        return debian(client, ident)
    if source == "flathub":
        return flathub(client, ident, logiciel["licence"], ident in pas_libre)
    if source == "fedora":
        cle, lire = "branche", lambda: branche_fedora(client)
    else:
        cle, lire = "index", lambda: lire_index_winget(client, aujourd_hui)
    if cle not in etat:
        try:
            etat[cle] = (lire(), None)
        except NonVerifie as e:
            etat[cle] = (None, str(e))
        except Exception as e:  # noqa: BLE001 : la panne est gardée, pour ne pas la relancer à chaque paquet
            etat[cle] = (None, f"panne : {type(e).__name__}")
    valeur, erreur = etat[cle]
    if erreur:
        raise NonVerifie(erreur)
    return fedora(client, valeur, ident) if source == "fedora" else winget(valeur[0], ident)


def controler(client, logiciels, pas_libre, admis, echus, aujourd_hui, hors_ligne=False):
    """Écrit le compte rendu sur la sortie et rend le code de sortie."""
    a_faire, refuses = taches(logiciels)
    degradations, admises, non_verifies, sains, non_couverts, infos = [], [], [], 0, 0, []
    for source, ident, raison in refuses:
        non_verifies.append((source, ident, raison))
    etat, servies, jugees = {}, set(), set()
    # Une admission (valable ou échue) pour une source que le catalogue n'a pas (plus) : dite, et rien conclu tant
    # qu'elle reste (campagne C5, n° 15) ; elle dirait sinon en silence qu'une dégradation est connue et admise.
    connues = {(source, ident) for source, ident, _ in a_faire}
    for cle in sorted(set(admis) | {c for c, _ in echus}):
        if cle[:2] not in connues:
            non_verifies.append((cle[0], cle[1], f"admission ({cle[2]}) pour une source absente du catalogue : à retirer"))
    for source, ident, logiciel in a_faire:
        if source == "opensuse":
            non_couverts += 1
            continue
        if hors_ligne:
            non_verifies.append((source, ident, "hors ligne demandé (VANGUARD_HORS_LIGNE=1)"))
            continue
        try:
            constats = juger(client, source, ident, logiciel, pas_libre, aujourd_hui, etat)
        except NonVerifie as e:
            non_verifies.append((source, ident, str(e)))
            continue
        except Exception as e:  # noqa: BLE001 : le filet par source (la frontière « donnée distante → non vérifié »)
            # Une réponse piégée qui fait lever n'importe quoi (TypeError, ValueError…) rend cette source non
            # vérifiée, pas tout le passage : les dégradations déjà trouvées restent dites, le code 1 tient.
            non_verifies.append((source, ident, f"panne : {type(e).__name__}"))
            continue
        jugees.add((source, ident))
        for constat, detail in constats:
            if constat in INFOS:
                infos.append((constat, detail, source, ident, logiciel["nom"]))
        constats = [c for c in constats if c[0] not in INFOS]
        if not constats:
            sains += 1
        for constat, detail in constats:
            cle = (source, ident, constat)
            if cle not in admis:
                degradations.append((cle, detail, logiciel["nom"]))
                continue
            servies.add(cle)
            admis_detail, raison, date, jusqu = admis[cle]
            if detail == admis_detail:
                admises.append((cle, detail, admis[cle]))
            else:
                # L'admission vaut pour ce qui a été vu ce jour-là, pas pour tout changement du même genre.
                degradations.append(
                    (cle, f"admis le {date} pour « {propre(admis_detail, 100)} », constaté : « {detail} »", logiciel["nom"])
                )
    # Ce qui est dit d'abord : les infos et les non vérifiées, puis les admissions, et les dégradations en dernier,
    # juste avant le résumé, pour qu'elles restent à l'écran (la sortie n'est jamais coupée, mais on lit le bas).
    for constat, detail, source, ident, nom in infos:
        print(f"  ℹ {propre(nom, 40)} · {source} {ident} : {INFOS[constat]} ({propre(detail, 200)}) : dit, sans effet")
    for cle in sorted(admis):
        if cle not in servies and cle[:2] in jugees:
            print(f"  ℹ admission inutile, à retirer : {cle[0]} {propre(cle[1], 60)} ({cle[2]}) : constat disparu")
    for cle, jusqu in echus:
        if not any(d[0] == cle for d in degradations):
            print(f"  ℹ admission échue le {jusqu}, à retirer : {cle[0]} {propre(cle[1], 60)} ({cle[2]})")
    for source, ident, raison in non_verifies:
        print(f"  ? {source} {ident} : non vérifié ({propre(raison, 200)})")
    for (source, ident, constat), detail, (_, raison, date, jusqu) in admises:
        print(
            f"  ≈ {source} {ident} : {CONSTATS[constat]}, admis le {date} jusqu'au {jusqu} "
            f"({propre(detail, 120)} ; {propre(raison, 120)})"
        )
    for cle, jusqu in echus:
        if any(d[0] == cle for d in degradations):
            print(f"  ! admission échue le {jusqu} : {cle[0]} {propre(cle[1], 60)} ({cle[2]})")
    for (source, ident, constat), detail, nom in degradations:
        print(f"  ✖ {propre(nom, 40)} · {source} {ident} : {CONSTATS[constat]} ({propre(detail, 260)})")
    index = etat.get("index", (None, None))[0]
    branche = etat.get("branche", (None, None))[0]
    print(f"  · catalogue : {len(logiciels)} logiciel(s) lu(s), {len(a_faire)} source(s)")
    if index is not None:
        print(f"  · index de winget du {index[1]} ({len(index[0])} identifiants)")
    if branche is not None:
        print(f"  · Fedora : {branche} (Bodhi), Debian : stable, Arch : {', '.join(DEPOTS_ARCH)}")
    print(f"  · non couverts : {non_couverts} paquet(s) openSUSE (aucune API publique simple) ; aucun cask au catalogue")
    # Le programme installe aussi par apt sur Ubuntu et ses dérivées, avec les noms de Debian (firefox-esr y devient
    # firefox) : rien n'est vérifié dans les dépôts d'Ubuntu, et c'est dit (campagne C5, n° 16).
    print("  · non couverts : Ubuntu et ses dérivées (noms de Debian supposés, jamais vérifiés dans les dépôts d'Ubuntu)")
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
    posees = [v for v in ENV_OPENSSL if os.environ.get(v) is not None]
    if posees and client is None:
        print(f"Sources : rien conclu, {', '.join(posees)} posée(s) : OpenSSL les a lues avant nous (à retirer).")
        return 2
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
