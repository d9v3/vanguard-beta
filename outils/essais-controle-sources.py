#!/usr/bin/env python3
"""Essais hors ligne de outils/controle-sources.py : un faux serveur HTTPS sur la boucle locale, signé par une autorité
jetable (openssl), répond à la place d'Arch, Flathub, winget, Debian et Fedora. Rien ne sort de l'ordinateur ; les
réponses et le catalogue sont inventés. Le nom vérifié dans le certificat reste celui de l'hôte permis : seuls
l'autorité et l'adresse jointe changent.
  1. Tout sain : code 0 et son témoin ; chaque source interrogée, au bon chemin ; Fedora : la dernière publiée selon
     Bodhi (f45), jamais la plus haute de mdapi (f46, en préparation).
  2. Périmé (Arch), licence changée (Flathub, FLATHUB_PAS_LIBRE devenue libre aussi), fin de vie, éditeur non
     vérifié, absent de chaque source, hors de main (Debian) : code 1 et le témoin « N dégradation(s) ».
  3. Admis (liste versionnée, format 2) : code 0 et dit pour la valeur exacte admise ; autre valeur, autre
     identifiant, autre source : une dégradation ; échu : de nouveau une dégradation ; inutile : dit ; date future,
     liste mal faite : rien conclu.
  4. Délai, réponse géante (annoncée ou non), compressée, mauvais type, JSON piégé (clé en double, NaN, trop
     profond, UTF-8 faux), réponse d'une autre application, redirection hors liste (jamais suivie), certificat d'une
     autre autorité, certificat sans le nom de l'hôte : non vérifié, code 2, jamais sain.
  5. Séquences d'échappement, bidi et invisibles dans un champ distant : rien de tout ça à l'écran.
  6. Identifiant hostile dans le catalogue : jamais envoyé, code 2.
  7. Index de winget : trop vieux, daté du futur, vide, abîmé, sans table, piégé (vue, table virtuelle, date hors de
     portée), flux abîmé, entrée chiffrée, bombe : code 2 ; réglages défensifs de sqlite posés (observés).
  8. VANGUARD_HORS_LIGNE=1 : aucune requête, code 2, en moins d'une seconde.
  9. Frontière « donnée distante → non vérifié » : une panne sur une source (n'importe quelle exception, en-têtes
     tordus, corps tronqué, coupure, en-têtes au goutte-à-goutte) la rend non vérifiée, et la dégradation trouvée
     ailleurs reste dite (code 1, ligne ✖).
 10. Champ absent : flag_date d'Arch, suite de Debian, nom du paquet Fedora, clé du catalogue, logiciel sans
     source, Bodhi incohérent : non vérifié, jamais sain.
 11. Magasin de certificats : SSL_CERT_FILE et SSL_CERT_DIR sans effet ; OPENSSL_CONF posée : rien conclu.
 12. Campagne C5 : adresses muettes et résolution lente bornées, échéance du passage, index de winget lu sans rien
     évaluer (colonne calculée, table virtuelle déguisée, CHECK, valeur géante, borne de temps, bornes de date),
     casse de winget, licences dans les deux sens, valeur longue liée par empreinte, caractères de remplissage,
     admissions (hors catalogue, openSUSE, champ par champ), lecteurs de chaque source, vrai outil hors ligne.
Sans openssl ou sans fts5 : « sauté » (code 77), jamais vert.
Lancé par outils/verifier.sh (étape controle-sources).
  python3 -I outils/essais-controle-sources.py
"""

import contextlib
import datetime
import importlib.util
import io
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import struct
import threading
import time
import traceback
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Sans openssl (l'autorité jetable) ou sans fts5 (les tables virtuelles piégées), ces essais ne prouvent rien : dit
# « sauté » (77, compté par verifier.sh), jamais vert.
if shutil.which("openssl") is None:
    print("(sauté : openssl absent, pas d'autorité jetable pour le faux serveur)")
    sys.exit(77)
try:
    sqlite3.connect(":memory:").execute("CREATE VIRTUAL TABLE essai USING fts5(x)")
except sqlite3.Error:
    print("(sauté : SQLite sans fts5, les index piégés ne se fabriquent pas)")
    sys.exit(77)

ICI = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("controle_sources", os.path.join(ICI, "controle-sources.py"))
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

AUJOURD_HUI = datetime.date(2026, 11, 22)
ECHECS = 0


def ok(texte):
    print(f"  ✔ {texte}")


def ko(texte):
    global ECHECS
    ECHECS += 1
    print(f"  ✖ {texte}")


def verifier(condition, texte, sortie=""):
    if condition:
        ok(texte)
    else:
        ko(f"{texte}\n{sortie[-1500:]}")


# ── Autorité et certificats jetables ──

TRAVAIL = tempfile.mkdtemp(prefix="essais-controle-sources.")
HOTES = sorted(cs.HOTES)


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=TRAVAIL)


def certificat(nom, hotes):
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout",
            f"{nom}.key", "-out", f"{nom}.csr", "-subj", f"/CN={hotes[0]}")
    with open(os.path.join(TRAVAIL, f"{nom}.ext"), "w") as f:
        f.write("subjectAltName=" + ",".join(f"DNS:{h}" for h in hotes) + "\n")
        f.write("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", f"{nom}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days",
            "2", "-out", f"{nom}.pem", "-extfile", f"{nom}.ext")


openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key",
        "-out", "ca.pem", "-days", "2", "-subj", "/CN=Autorite des essais", "-addext",
        "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
certificat("serveur", HOTES + ["evil.example"])
# Un second serveur au certificat valide (même autorité) qui n'a pas le nom de Fedora.
certificat("sans-fedora", [h for h in HOTES if h != "mdapi.fedoraproject.org"])

# ── Le faux serveur ──

REQUETES = []
SCENARIO = {}


def reponse_json(objet, statut=200, **en_tetes):
    corps = objet if isinstance(objet, bytes) else json.dumps(objet).encode()
    return {"statut": statut, "corps": corps, "type": "application/json", **en_tetes}


class Gestion(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        hote = self.headers.get("Host", "")
        REQUETES.append((hote, self.path))
        r = SCENARIO.get("tout")
        if r is None:
            r = repondre(hote, self.path)
        if r.get("attente"):
            time.sleep(r["attente"])
        try:
            self.send_response(r["statut"])
            self.send_header("Content-Type", r.get("type", "application/json"))
            for cle, valeur in r.get("en_tetes", {}).items():
                self.send_header(cle, valeur)
            if r.get("goutte"):
                # Sans longueur annoncée : un octet à la fois, sans fin.
                self.send_header("Connection", "close")
                self.end_headers()
                fin = time.monotonic() + 10
                while time.monotonic() < fin:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.3)
                return
            if r.get("goutte_en_tetes"):
                # Les en-têtes eux-mêmes, un octet à la fois : le délai par opération n'y voit jamais de silence.
                self.flush_headers()  # la ligne d'état et les premiers en-têtes, sans la ligne vide de fin
                self.wfile.write(b"X-Lent: ")
                fin = time.monotonic() + 10
                while time.monotonic() < fin:
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    time.sleep(0.3)
                self.wfile.write(b"\r\nContent-Length: 2\r\n\r\n{}")
                self.wfile.flush()
                self.close_connection = True
                return
            if r.get("coupe"):
                # Sans longueur annoncée, fermé sans close_notify (SSLSocket.shutdown n'en envoie pas) : une coupure.
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(r["corps"])
                self.wfile.flush()
                return
            if r.get("tronque"):
                # Moins d'octets que la longueur annoncée, puis une fin TLS propre (close_notify) : sans le contrôle
                # de la longueur, le corps coupé passerait pour entier.
                self.send_header("Content-Length", str(len(r["corps"]) + 50))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(r["corps"])
                self.wfile.flush()
                self.connection.unwrap()
                return
            if r.get("flot"):
                self.send_header("Connection", "close")
                self.end_headers()
                for _ in range(r["flot"]):
                    self.wfile.write(b" " * 65536)
                return
            self.send_header("Content-Length", r.get("longueur", str(len(r["corps"]))))
            self.end_headers()
            self.wfile.write(r["corps"])
        except (OSError, ssl.SSLError):
            pass


class Serveur(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # un client qui coupe (délai, refus) est le cas essayé, pas une panne du faux serveur


def serveur(nom):
    s = Serveur(("127.0.0.1", 0), Gestion)
    s.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(TRAVAIL, f"{nom}.pem"), os.path.join(TRAVAIL, f"{nom}.key"))
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


SERVEUR = serveur("serveur")
SANS_FEDORA = serveur("sans-fedora")
PORT, PORT_SANS_FEDORA = SERVEUR.server_address[1], SANS_FEDORA.server_address[1]

# ── Réponses saines, modifiables par cas ──


def index_winget(ids=("Mozilla.Firefox", "GIMP.GIMP.3"), date=AUJOURD_HUI, piege=None, ecrit=None):
    base = sqlite3.connect(":memory:")
    base.execute("CREATE TABLE metadata (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
    if ecrit is None:
        ecrit = str(int(datetime.datetime(date.year, date.month, date.day, tzinfo=datetime.UTC).timestamp()))
    base.execute("INSERT INTO metadata VALUES ('lastwritetime', ?)", (ecrit,))
    if piege == "vue":
        base.execute("CREATE TABLE vraie (id TEXT)")
        base.execute("CREATE VIEW packages AS SELECT id FROM vraie")
    elif piege == "virtuelle":
        base.execute("CREATE VIRTUAL TABLE packages USING fts5(id)")
        base.executemany("INSERT INTO packages (id) VALUES (?)", [(i,) for i in ids])
    elif piege == "virtuelle-ailleurs":
        base.execute("CREATE TABLE packages (rowid INTEGER PRIMARY KEY, id TEXT NOT NULL, latest_version TEXT)")
        base.executemany("INSERT INTO packages (id, latest_version) VALUES (?, '1.0')", [(i,) for i in ids])
        base.execute("CREATE VIRTUAL TABLE autre USING fts5(x)")
    elif piege != "sans-table":
        base.execute("CREATE TABLE packages (rowid INTEGER PRIMARY KEY, id TEXT NOT NULL, latest_version TEXT)")
        base.executemany("INSERT INTO packages (id, latest_version) VALUES (?, '1.0')", [(i,) for i in ids])
    if piege == "declencheur":
        base.execute("CREATE TABLE journal (x TEXT)")
        base.execute("CREATE TRIGGER t AFTER INSERT ON packages BEGIN INSERT INTO journal VALUES ('x'); END")
    base.commit()
    donnees = base.serialize()
    if piege == "abime":
        # Le premier bloc libre d'une page d'une autre table mis hors de la page : packages et metadata se lisent
        # encore très bien, seul quick_check voit la base abîmée (sans lui, elle serait crue).
        base.execute("CREATE TABLE autre (x TEXT)")
        base.executemany("INSERT INTO autre VALUES (?)", [("y" * 50,) for _ in range(10)])
        base.commit()
        donnees = bytearray(base.serialize())
        taille = struct.unpack(">H", donnees[16:18])[0]
        racine = base.execute("SELECT rootpage FROM sqlite_master WHERE name = 'autre'").fetchone()[0]
        donnees[(racine - 1) * taille + 1:(racine - 1) * taille + 3] = b"\xff\xf0"
        donnees = bytes(donnees)
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Public/index.db", donnees)
        z.writestr("AppxManifest.xml", "<Package/>")
    octets = bytearray(tampon.getvalue())
    if piege in ("deflate", "chiffre"):
        local = octets.index(b"PK\x03\x04")
        nom, extra = struct.unpack("<HH", octets[local + 26:local + 30])
        central = octets.index(b"PK\x01\x02")
        if piege == "deflate":
            # Les premiers octets du flux deflate remplacés par un type de bloc réservé : zlib.error à la lecture.
            octets[local + 30 + nom + extra:local + 30 + nom + extra + 8] = b"\xff" * 8
        else:
            # Le bit « chiffré » posé dans le répertoire central : zipfile lève RuntimeError (mot de passe requis).
            octets[central + 8] |= 1
            octets[local + 6] |= 1
    return bytes(octets)


SAIN = {
    ("archlinux.org", "/packages/search/json/?name=keepassxc"): reponse_json(
        {"results": [{"pkgname": "keepassxc", "repo": "extra", "pkgver": "2.8.0", "flag_date": None},
                     {"pkgname": "keepassxc", "repo": "extra-testing", "pkgver": "2.9.0", "flag_date": "2026-11-01"}]}),
    ("flathub.org", "/api/v2/appstream/org.keepassxc.KeePassXC"): reponse_json(
        {"id": "org.keepassxc.KeePassXC", "is_eol": False, "is_free_license": True,
         "project_license": "GPL-3.0-or-later AND (LGPL-2.1-only WITH Qt-exception-1.0)",
         "metadata": {"flathub::verification::verified": True}}),
    ("flathub.org", "/api/v2/appstream/com.exemple.Commercial"): reponse_json(
        {"id": "com.exemple.Commercial", "is_eol": False, "is_free_license": False,
         "project_license": "LicenseRef-proprietary", "metadata": {"flathub::verification::verified": True}}),
    ("api.ftp-master.debian.org", "/madison?package=keepassxc&f=json&s=stable"): reponse_json(
        [{"keepassxc": {"stable": {"2.7.10-1": {"component": "main", "architectures": ["source", "amd64"]}}}}]),
    # f46 est dans mdapi (branchée dans koji) mais pas publiée : Bodhi la dit « pending », hors de state=current.
    ("mdapi.fedoraproject.org", "/branches"): reponse_json(["epel9", "f44", "f45", "f46", "rawhide", "src_f45"]),
    ("bodhi.fedoraproject.org", "/releases/?state=current&rows_per_page=100"): reponse_json(
        {"page": 1, "pages": 1, "rows_per_page": 100, "total": 4, "releases": [
            {"name": "EPEL-9", "branch": "epel9", "state": "current", "id_prefix": "FEDORA-EPEL"},
            {"name": "F44", "branch": "f44", "state": "current", "id_prefix": "FEDORA"},
            {"name": "F45", "branch": "f45", "state": "current", "id_prefix": "FEDORA"},
            {"name": "F45F", "branch": "f45", "state": "current", "id_prefix": "FEDORA-FLATPAK"}]}),
    ("mdapi.fedoraproject.org", "/f45/pkg/keepassxc"): reponse_json(
        {"version": "2.8.0", "release": "1.fc45", "basename": "keepassxc"}),
    ("cdn.winget.microsoft.com", "/cache/source2.msix"): {"statut": 200, "corps": index_winget(),
                                                          "type": "application/octet-stream"},
}
REPONSES = {}


def repondre(hote, chemin):
    r = REPONSES.get((hote, chemin))
    if r is None:
        return {"statut": 404, "corps": b"{}", "type": "application/json"}
    return r


def catalogue(**changes):
    logiciels = [
        {"nom": "KeePassXC", "licence": "GPL-3.0 AND LGPL-2.1", "paquets": {"arch": ["keepassxc"], "debian": ["keepassxc"],
                                                            "fedora": ["keepassxc"], "opensuse": ["keepassxc"]},
         "flatpak": "org.keepassxc.KeePassXC", "winget": "Mozilla.Firefox"},
        {"nom": "Commercial", "licence": "GPL-3.0", "paquets": {"arch": [], "debian": [], "fedora": [], "opensuse": []},
         "flatpak": "com.exemple.Commercial", "winget": "GIMP.GIMP.3"},
    ]
    for cle, valeur in changes.items():
        logiciels[0][cle] = valeur
    return {"format": 1, "flathub_pas_libre": ["com.exemple.Commercial"], "logiciels": logiciels}


def ecrire(nom, objet):
    chemin = os.path.join(TRAVAIL, nom)
    with open(chemin, "w", encoding="utf-8") as f:
        f.write(objet if isinstance(objet, str) else json.dumps(objet))
    return chemin


def client(autorite="ca.pem", port=None, delai=2, delai_total=4):
    ctx = ssl.create_default_context(cafile=os.path.join(TRAVAIL, autorite)) if autorite else None
    return cs.Client(ctx=ctx, relier=lambda h: ("127.0.0.1", port or PORT), pause=0, delai=delai,
                     delai_total=delai_total)


def passer(cat=None, admis=None, c=None, reponses=None, env=None):
    """Un passage complet : (code, sortie)."""
    REQUETES.clear()
    REPONSES.clear()
    REPONSES.update(SAIN)
    REPONSES.update(reponses or {})
    chemin_cat = ecrire("catalogue.json", cat if cat is not None else catalogue())
    chemin_admis = ecrire("admis.json", admis if admis is not None else {"format": 2, "admis": []})
    tampon = io.StringIO()
    ancien = os.environ.get("VANGUARD_HORS_LIGNE")
    if env is not None:
        os.environ["VANGUARD_HORS_LIGNE"] = env
    try:
        with contextlib.redirect_stdout(tampon):
            try:
                code = cs.principal(["--catalogue", chemin_cat, "--admis", chemin_admis], client=c or client(),
                                    aujourd_hui=AUJOURD_HUI)
            except Exception:  # noqa: BLE001 : une exception sortie du passage est un échec de l'essai, dit
                code = "exception"
                print(traceback.format_exc())
    finally:
        if ancien is None:
            os.environ.pop("VANGUARD_HORS_LIGNE", None)
        else:
            os.environ["VANGUARD_HORS_LIGNE"] = ancien
    return code, tampon.getvalue()


def avec(hote, chemin, **r):
    return {(hote, chemin): r}


ARCH = ("archlinux.org", "/packages/search/json/?name=keepassxc")
FLAT = ("flathub.org", "/api/v2/appstream/org.keepassxc.KeePassXC")
FLAT_COM = ("flathub.org", "/api/v2/appstream/com.exemple.Commercial")
DEB = ("api.ftp-master.debian.org", "/madison?package=keepassxc&f=json&s=stable")
FED = ("mdapi.fedoraproject.org", "/f45/pkg/keepassxc")
MSIX = ("cdn.winget.microsoft.com", "/cache/source2.msix")
BODHI = ("bodhi.fedoraproject.org", "/releases/?state=current&rows_per_page=100")
BRANCHES = ("mdapi.fedoraproject.org", "/branches")
PERIME = reponse_json({"results": [{"pkgname": "keepassxc", "repo": "extra", "pkgver": "2.7",
                                    "flag_date": "2026-06-22T20:03:01Z"}]})
DETAIL_PERIME = "extra/keepassxc 2.7 depuis le 2026-06-22T20:03:01Z"


def msix(corps):
    return {MSIX: {"statut": 200, "corps": corps, "type": "application/octet-stream"}}


def bodhi(*releases):
    return {BODHI: reponse_json({"page": 1, "pages": 1, "rows_per_page": 100, "total": len(releases),
                                 "releases": list(releases)})}


def avec_perime(code, sortie):
    """La dégradation d'Arch trouvée à côté a survécu à la panne d'une autre source."""
    return code == 1 and "  ✖ KeePassXC · arch keepassxc : marqué périmé" in sortie and " dégradation(s)" in sortie


def flathub_avec(**champs):
    base = json.loads(SAIN[FLAT]["corps"])
    base.update(champs)
    return {FLAT: reponse_json(base)}


def degrade(code, sortie, mot):
    return code == 1 and mot in sortie and "Sources : " in sortie and " dégradation(s)" in sortie


def non_verifie(code, sortie, mot=""):
    return code == 2 and "non vérifié" in sortie and mot in sortie and "saines" not in sortie


def principal():
    print("1. Tout sain")
    code, sortie = passer()
    attendues = {ARCH, FLAT, FLAT_COM, DEB, FED, MSIX, BRANCHES, BODHI}
    verifier(code == 0 and "Sources : 7 vérifiée(s), saines (0 admise(s))." in sortie and set(REQUETES) == attendues
             and "1 paquet(s) openSUSE" in sortie and "Fedora : f45 (Bodhi)" in sortie
             and "catalogue : 2 logiciel(s) lu(s)" in sortie,
             "sain : code 0, témoin, chaque source à son chemin, Fedora f45 (pas f46, en préparation)", sortie)
    # Le compte rendu ne doit jamais être coupé : les dégradations viennent en dernier, juste avant le résumé.
    code, sortie = passer(reponses={ARCH: PERIME, **flathub_avec(metadata={}), DEB: {"statut": 503, "corps": b""}})
    lignes = sortie.splitlines()
    rang = {m: max((i for i, l in enumerate(lignes) if l.startswith(m)), default=-1) for m in ("  ℹ", "  ?", "  ✖")}
    premier_point = min((i for i, l in enumerate(lignes) if l.startswith("  · ")), default=-1)
    verifier(code == 1 and -1 < rang["  ℹ"] < rang["  ?"] < rang["  ✖"] < premier_point,
             "ordre : ℹ, puis ?, puis ✖ juste avant les lignes « · » et le résumé", sortie)

    print("2. Dégradations")
    perime = reponse_json({"results": [{"pkgname": "keepassxc", "repo": "extra", "pkgver": "2.7",
                                        "flag_date": "2026-06-22T20:03:01Z"}]})
    code, sortie = passer(reponses={ARCH: perime})
    verifier(degrade(code, sortie, "marqué périmé") and "depuis le 2026-06-22" in sortie, "Arch périmé", sortie)
    seul_testing = reponse_json({"results": [{"pkgname": "keepassxc", "repo": "extra-testing", "flag_date": None},
                                             {"pkgname": "keepassxc-autre", "repo": "extra", "flag_date": None}]})
    code, sortie = passer(reponses={ARCH: seul_testing})
    verifier(degrade(code, sortie, "arch keepassxc : absent"), "Arch : seulement dans testing ou un autre nom = absent",
             sortie)
    code, sortie = passer(reponses=flathub_avec(is_free_license=False, project_license="LicenseRef-proprietary"))
    verifier(degrade(code, sortie, "licence différente"), "Flathub : licence devenue non libre", sortie)
    code, sortie = passer(reponses=flathub_avec(project_license="MIT"))
    verifier(degrade(code, sortie, "licence différente"), "Flathub : autre licence libre que celle du catalogue",
             sortie)
    libre = json.loads(SAIN[FLAT_COM]["corps"]) | {"is_free_license": True, "project_license": "GPL-3.0-only"}
    code, sortie = passer(reponses={FLAT_COM: reponse_json(libre)})
    verifier(degrade(code, sortie, "le catalogue la dit non libre"), "Flathub : FLATHUB_PAS_LIBRE redevenue libre",
             sortie)
    code, sortie = passer(reponses=flathub_avec(is_eol=True))
    verifier(degrade(code, sortie, "en fin de vie"), "Flathub : fin de vie", sortie)
    code, sortie = passer(reponses=flathub_avec(metadata={"flathub::verification::verified": None}))
    verifier(code == 0 and "  ℹ KeePassXC · flathub org.keepassxc.KeePassXC : pas vérifié par son éditeur" in sortie
             and "Sources : 7 vérifiée(s), saines" in sortie and "✖" not in sortie,
             "Flathub : éditeur non vérifié, dit (ℹ), sans changer le code ni compter de dégradation", sortie)
    code, sortie = passer(reponses=flathub_avec(is_eol=True, metadata={}))
    verifier(degrade(code, sortie, "en fin de vie") and "ℹ KeePassXC" in sortie and sortie.count("✖") == 1,
             "Flathub : fin de vie et éditeur non vérifié : une dégradation, une information", sortie)
    absents = {ARCH: reponse_json({"results": []}), FLAT: {"statut": 404, "corps": b"{}"},
               DEB: reponse_json([]), FED: {"statut": 400, "corps": b"400: Bad Request", "type": "text/plain"},
               MSIX: {"statut": 200, "corps": index_winget(ids=("GIMP.GIMP.3",)), "type": "application/octet-stream"}}
    code, sortie = passer(reponses=absents)
    verifier(code == 1 and "Sources : 5 dégradation(s)" in sortie and sortie.count("absent de la source") == 5,
             "absent de chaque source (Arch, Flathub, winget, Debian, Fedora)", sortie)
    contrib = reponse_json([{"keepassxc": {"stable": {"1": {"component": "contrib", "architectures": ["amd64"]}}}}])
    code, sortie = passer(reponses={DEB: contrib})
    verifier(degrade(code, sortie, "hors de la section main"), "Debian : hors de main", sortie)
    source_seule = reponse_json([{"keepassxc": {"stable": {"1": {"component": "main", "architectures": ["source"]}}}}])
    code, sortie = passer(reponses={DEB: source_seule})
    verifier(degrade(code, sortie, "debian keepassxc : absent"), "Debian : un paquet source seul n'est pas un binaire",
             sortie)

    print("3. Admis")
    admis = {"format": 2, "admis": [{"source": "arch", "identifiant": "keepassxc", "constat": "perime",
                                     "detail": DETAIL_PERIME, "raison": "attendu de l'amont, revu à la main",
                                     "date": "2026-11-01", "jusqu_au": "2026-12-31"}]}
    code, sortie = passer(admis=admis, reponses={ARCH: perime})
    verifier(code == 0 and "≈ arch keepassxc : marqué périmé, admis le 2026-11-01 jusqu'au 2026-12-31 "
             f"({DETAIL_PERIME} ;" in sortie and "inutile" not in sortie, "admis : code 0, dit avec le constat", sortie)
    plus_tard = reponse_json({"results": [{"pkgname": "keepassxc", "repo": "extra", "pkgver": "2.7",
                                           "flag_date": "2026-11-20T00:00:00Z"}]})
    code, sortie = passer(admis=admis, reponses={ARCH: plus_tard})
    verifier(degrade(code, sortie, "marqué périmé") and f"pour « {DETAIL_PERIME} », constaté : « extra/keepassxc 2.7 "
             "depuis le 2026-11-20T00:00:00Z »" in sortie and "≈" not in sortie,
             "admis pour une autre valeur (nouveau drapeau) : une dégradation qui cite les deux", sortie)
    for nom, champ, valeur in (("un autre identifiant", "identifiant", "keepassxc-autre"),
                               ("une autre source", "source", "debian")):
        ailleurs = json.loads(json.dumps(admis))
        ailleurs["admis"][0][champ] = valeur
        code, sortie = passer(admis=ailleurs, reponses={ARCH: perime})
        verifier(degrade(code, sortie, "marqué périmé") and "≈" not in sortie,
                 f"admis pour {nom} (même constat) : ne couvre pas celui-ci", sortie)
    code, sortie = passer(admis=admis)
    verifier(code == 0 and "ℹ admission inutile, à retirer : arch keepassxc (perime)" in sortie,
             "admission qui ne sert plus (source saine) : dite", sortie)
    code, sortie = passer(admis=admis, reponses={ARCH: {"statut": 503, "corps": b""}})
    verifier(code == 2 and "inutile" not in sortie, "admission d'une source non vérifiée : rien dit d'elle", sortie)
    echu = json.loads(json.dumps(admis))
    echu["admis"][0]["jusqu_au"] = "2026-11-21"
    code, sortie = passer(admis=echu, reponses={ARCH: perime})
    verifier(degrade(code, sortie, "marqué périmé") and "! admission échue le 2026-11-21" in sortie,
             "admis échu : de nouveau une dégradation", sortie)
    code, sortie = passer(admis=echu)
    verifier(code == 0 and "ℹ admission échue le 2026-11-21, à retirer" in sortie, "admis échu et sans objet : dit",
             sortie)
    autre = json.loads(json.dumps(admis))
    autre["admis"][0]["constat"] = "absent"
    code, sortie = passer(admis=autre, reponses={ARCH: perime})
    verifier(degrade(code, sortie, "marqué périmé"), "admis pour un autre constat : ne couvre pas celui-ci", sortie)
    for nom, champ, valeur in (("sans raison", "raison", "ok"), ("plus d'un an", "jusqu_au", "2028-01-01"),
                               ("constat inconnu", "constat", "tout"), ("date fausse", "date", "hier"),
                               ("datée du futur", "date", "2026-11-23"), ("sans detail", "detail", " ")):
        mal = json.loads(json.dumps(admis))
        mal["admis"][0][champ] = valeur
        code, sortie = passer(admis=mal)
        verifier(code == 2 and "rien conclu" in sortie and not REQUETES, f"liste des admis {nom} : refusée", sortie)
    double = json.loads(json.dumps(admis))
    double["admis"].append(double["admis"][0])
    code, sortie = passer(admis=double)
    verifier(code == 2 and "deux fois" in sortie, "liste des admis : une entrée en double refusée", sortie)
    ancienne = json.loads(json.dumps(admis))
    ancienne["format"] = 1
    del ancienne["admis"][0]["detail"]
    code, sortie = passer(admis=ancienne)
    verifier(code == 2 and "format 2 attendu" in sortie and not REQUETES, "liste des admis au format 1 : refusée",
             sortie)

    print("4. Réponses refusées : non vérifié, jamais sain")
    cas = [
        ("délai dépassé (réponse qui attend)", {ARCH: {**perime, "attente": 3}}, "injoignable"),
        ("délai total dépassé (un octet à la fois)", {ARCH: {"statut": 200, "corps": b"", "goutte": True}}, "délai"),
        ("réponse géante annoncée", {ARCH: {**SAIN[ARCH], "longueur": str(cs.PLAFOND_JSON + 1)}}, "trop grande"),
        ("réponse géante non annoncée", {ARCH: {"statut": 200, "corps": b"", "flot": 40}}, "plus de"),
        ("longueur annoncée fausse", {ARCH: {**SAIN[ARCH], "longueur": "-1"}}, "mal annoncée"),
        ("réponse compressée", {ARCH: {**SAIN[ARCH], "en_tetes": {"Content-Encoding": "gzip"}}}, "compressée"),
        ("mauvais type", {ARCH: {**SAIN[ARCH], "type": "text/html"}}, "type de réponse"),
        ("JSON : clé en double", {ARCH: reponse_json(b'{"results": [], "results": []}')}, "en double"),
        ("JSON : NaN", {ARCH: reponse_json(b'{"results": [], "x": NaN}')}, "JSON piégé"),
        ("JSON : trop profond", {ARCH: reponse_json(b"[" * 200000 + b"]" * 200000)}, "illisible"),
        ("JSON : UTF-8 faux", {ARCH: reponse_json(b'{"results": ["\xff"]}')}, "illisible"),
        ("JSON : types faux", {ARCH: reponse_json({"results": "keepassxc"})}, "sans liste"),
        ("Flathub : autre application", {FLAT: reponse_json({"id": "org.autre.App"})}, "autre application"),
        ("Flathub : is_eol pas booléen", flathub_avec(is_eol="non"), "is_eol"),
        ("Flathub : is_eol absent", {FLAT: reponse_json({k: v for k, v in json.loads(SAIN[FLAT]["corps"]).items()
                                                         if k != "is_eol"})}, "is_eol"),
        ("longueur annoncée en chiffres non ASCII", {ARCH: {**SAIN[ARCH], "longueur": "²"}}, "mal annoncée"),
        ("corps tronqué (fin TLS propre)", {ARCH: {**SAIN[ARCH], "tronque": True}}, "incomplète"),
        ("corps coupé sans close_notify", {ARCH: {**SAIN[ARCH], "coupe": True}}, "lecture interrompue"),
        ("redirection hors liste", {ARCH: {"statut": 302, "corps": b"",
                                           "en_tetes": {"Location": "https://evil.example/x"}}}, "jamais suivie"),
        ("limite de requêtes", {ARCH: {"statut": 429, "corps": b""}}, "limite"),
        ("erreur du serveur", {ARCH: {"statut": 503, "corps": b""}}, "réponse 503"),
    ]
    for nom, reponses, mot in cas:
        code, sortie = passer(reponses=reponses)
        verifier(non_verifie(code, sortie, mot) and not any(h == "evil.example" for h, _ in REQUETES),
                 f"{nom} : code 2", sortie)
    code, sortie = passer(c=client(autorite=None))
    verifier(code == 2 and "certificat refusé" in sortie and "saines" not in sortie,
             "certificat d'une autre autorité : refusé", sortie)
    code, sortie = passer(c=client(port=PORT_SANS_FEDORA))
    verifier(non_verifie(code, sortie, "mdapi.fedoraproject.org : certificat refusé")
             and "Hostname mismatch" in sortie, "certificat sans le nom de l'hôte : refusé", sortie)
    try:
        client().obtenir("evil.example", "/api/v2/appstream/x")
        ko("hôte hors liste : accepté")
    except cs.NonVerifie:
        ok("hôte hors liste : refusé avant toute requête")
    try:
        client().obtenir("flathub.org", "/api/v1/autre")
        ko("chemin hors liste : accepté")
    except cs.NonVerifie:
        ok("chemin hors liste : refusé avant toute requête")

    print("5. Texte distant assaini")
    piege = "2.7\x1b]52;c;ZWNobyBwd24=\x07\x1b[2J‮​ \x9b31m\x00fin"
    code, sortie = passer(reponses={ARCH: reponse_json({"results": [
        {"pkgname": "keepassxc", "repo": "extra", "pkgver": piege, "flag_date": "2026-06-22\x1b[31m"}]})})
    interdits = [c for c in sortie if c != "\n" and (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F
                                                     or c in "‮​ ⁦⁩")]
    verifier(code == 1 and not interdits and "2.7?]52;c;ZWNobyBwd24=?" in sortie,
             "séquences d'échappement, bidi, invisibles : retirés de l'affichage", repr(sortie))
    code, sortie = passer(reponses=flathub_avec(project_license="MIT\x1b[2J‮", is_free_license=False))
    verifier(code == 1 and "\x1b" not in sortie and "‮" not in sortie and "licence différente" in sortie,
             "licence piégée : assainie", repr(sortie))
    code, sortie = passer(reponses=flathub_avec(project_license="MIT\x1b[2J‮", is_free_license=True))
    verifier(code == 2 and "\x1b" not in sortie and "‮" not in sortie and "licence illisible" in sortie,
             "licence hors de l'alphabet SPDX : rien conclu, assainie", repr(sortie))

    print("6. Identifiant hostile dans le catalogue")
    for hostile in ("../../etc", "-rf", "a;b", "a b", "x\x1b[2J", "a/b", "a?name=b", "a%2e", "é", "", "a" * 200):
        code, sortie = passer(cat=catalogue(paquets={"arch": [hostile], "debian": [], "fedora": [], "opensuse": []},
                                            flatpak=None, winget=None))
        envoye = any(hostile and hostile in p for _, p in REQUETES if p.startswith("/packages"))
        verifier(code == 2 and "hors de l'alphabet" in sortie and not envoye and "\x1b" not in sortie,
                 f"paquet {hostile[:20]!r} : jamais envoyé, code 2", sortie)
    for champ, hostile in (("flatpak", "org..x.y"), ("flatpak", "org.x"), ("winget", "Sans/Point"),
                           ("winget", "-x.y")):
        code, sortie = passer(cat=catalogue(**{champ: hostile}))
        verifier(code == 2 and "hors de l'alphabet" in sortie and not any(hostile in p for _, p in REQUETES),
                 f"{champ} {hostile!r} : jamais envoyé", sortie)
    code, sortie = passer(cat={"format": 2, "logiciels": []})
    verifier(code == 2 and "rien conclu" in sortie, "catalogue d'un autre format : rien conclu", sortie)
    code, sortie = passer(cat='{"format": 1, "format": 1}')
    verifier(code == 2 and "rien conclu" in sortie, "catalogue piégé (clé en double) : rien conclu", sortie)

    print("7. Index de winget")
    for nom, corps, mot in (
        ("trop vieux", index_winget(date=AUJOURD_HUI - datetime.timedelta(days=30)), "trop vieux"),
        ("daté du futur (J+10)", index_winget(date=AUJOURD_HUI + datetime.timedelta(days=10)), "dans le futur"),
        ("vide", index_winget(ids=()), "vide"),
        ("abîmé", index_winget(piege="abime"), "quick_check"),
        ("table packages virtuelle (fts5)", index_winget(piege="virtuelle"), "table virtuelle"),
        ("table virtuelle ailleurs", index_winget(piege="virtuelle-ailleurs"), "table virtuelle"),
        ("date de 12 chiffres", index_winget(ecrit="999999999999"), "sans date lisible"),
        ("date en chiffres non ASCII", index_winget(ecrit="²"), "sans date lisible"),
        ("flux deflate abîmé", index_winget(piege="deflate"), "illisible"),
        ("entrée chiffrée", index_winget(piege="chiffre"), "illisible (RuntimeError)"),
        ("sans table", index_winget(piege="sans-table"), "sans table"),
        ("vue à la place de la table", index_winget(piege="vue"), "de type view"),
        ("pas une archive", b"PK\x03\x04pas une archive", "illisible"),
        ("archive sans index", b"", "illisible"),
    ):
        code, sortie = passer(reponses={MSIX: {"statut": 200, "corps": corps, "type": "application/octet-stream"}})
        verifier(non_verifie(code, sortie, mot), f"index {nom} : code 2", sortie)
    # Les réglages défensifs ne se voient pas par une lecture (un déclencheur ne part que sur une écriture, que
    # query_only refuse déjà) : on les observe là où ils sont posés, sur la connexion elle-même.
    poses, connecter = [], sqlite3.connect

    class Observee(sqlite3.Connection):
        def setconfig(self, op, valeur=True):
            poses.append((op, bool(valeur)))
            return super().setconfig(op, valeur)

        def execute(self, sql, *args):
            poses.append(sql)
            return super().execute(sql, *args)

    sqlite3.connect = lambda *a, **k: connecter(*a, factory=Observee, **k)
    try:
        code, sortie = passer(reponses=msix(index_winget(piege="declencheur")))
    finally:
        sqlite3.connect = connecter
    attendus = [(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True), (sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False),
                (sqlite3.SQLITE_DBCONFIG_ENABLE_TRIGGER, False), (sqlite3.SQLITE_DBCONFIG_ENABLE_VIEW, False),
                "PRAGMA query_only = 1"]
    verifier(code == 0 and all(a in poses for a in attendus),
             "index avec un déclencheur : lu en mode défensif, sans déclencheur ni vue, en lecture seule", sortie)
    ancien = cs.PLAFOND_INDEX
    cs.PLAFOND_INDEX = 1024
    try:
        code, sortie = passer()
        verifier(non_verifie(code, sortie, "trop grand"), "index plus grand que le plafond (bombe) : code 2", sortie)
    finally:
        cs.PLAFOND_INDEX = ancien

    print("8. Hors ligne")
    debut = time.monotonic()
    code, sortie = passer(env="1")
    verifier(code == 2 and not REQUETES and "hors ligne demandé" in sortie and time.monotonic() - debut < 1,
             "VANGUARD_HORS_LIGNE=1 : aucune requête, code 2", sortie)
    # Un port ouvert puis refermé à l'instant : sûr d'être fermé ici (le 9 pourrait servir sur une machine).
    libre = socket.socket()
    libre.bind(("127.0.0.1", 0))
    port_ferme = libre.getsockname()[1]
    libre.close()
    c = cs.Client(relier=lambda h: ("127.0.0.1", port_ferme), pause=0, delai=2)
    code, sortie = passer(c=c)
    verifier(code == 2 and "injoignable" in sortie and "saines" not in sortie,
             "serveurs injoignables : code 2, rien de sain", sortie)
    # Un catalogue vidé (export raté, liste retirée) ne prouve rien : jamais « 0 vérifiée(s), saines ».
    code, sortie = passer(cat={"format": 1, "flathub_pas_libre": [], "logiciels": []})
    verifier(code == 2 and not REQUETES and "aucune source vérifiée" in sortie and "saines" not in sortie,
             "catalogue vide : code 2, rien de sain", sortie)

    print("9. Une panne sur une source ne cache pas les dégradations des autres")
    for nom, reponses, mot in (
        ("redirection vers une adresse qui ne se découpe pas",
         {FLAT: {"statut": 302, "corps": b"", "en_tetes": {"Location": "http://[x"}}}, "jamais suivie"),
        ("longueur annoncée « ² »", {FLAT: {**SAIN[FLAT], "longueur": "²"}}, "mal annoncée"),
        ("section Debian en liste", {DEB: reponse_json([{"keepassxc": {"stable": {"1": {
            "component": ["main"], "architectures": ["amd64"]}}}}])}, "section illisible"),
        ("flux deflate abîmé", msix(index_winget(piege="deflate")), "index de winget illisible"),
        ("entrée chiffrée", msix(index_winget(piege="chiffre")), "RuntimeError"),
        ("date de 12 chiffres", msix(index_winget(ecrit="999999999999")), "sans date lisible"),
        ("table virtuelle", msix(index_winget(piege="virtuelle")), "table virtuelle"),
        ("corps tronqué", {FLAT: {**SAIN[FLAT], "tronque": True}}, "incomplète"),
    ):
        code, sortie = passer(reponses={ARCH: PERIME, **reponses})
        verifier(avec_perime(code, sortie) and mot in sortie and "non vérifié" in sortie,
                 f"{nom} : non vérifié, et Arch périmé toujours dit (code 1)", sortie)
    # Le filet lui-même, quel que soit le défaut qu'une réponse fera lever demain : une exception imprévue.
    # Deux paquets Fedora : une panne de la branche (lue une fois pour tout le passage) est gardée, pas relancée.
    deux_fedora = catalogue(paquets={"arch": ["keepassxc"], "debian": ["keepassxc"], "fedora": ["keepassxc", "kpcli"],
                                     "opensuse": ["keepassxc"]})
    for nom, cible, appels_permis in (("flathub", "flathub", 2), ("branche de Fedora", "branche_fedora", 1)):
        vraie, appels = getattr(cs, cible), []

        def piegee(*_args, **_options):
            appels.append(1)
            raise TypeError("imprévu")

        setattr(cs, cible, piegee)
        try:
            code, sortie = passer(cat=deux_fedora, reponses={ARCH: PERIME})
        finally:
            setattr(cs, cible, vraie)
        verifier(avec_perime(code, sortie) and "non vérifié (panne : TypeError)" in sortie
                 and len(appels) == appels_permis,
                 f"exception imprévue ({nom}) : « panne », la source non vérifiée, le code 1 tient "
                 f"({len(appels)} appel(s))", sortie)
    debut = time.monotonic()
    code, sortie = passer(reponses={ARCH: PERIME, FLAT: {"statut": 200, "corps": b"", "goutte_en_tetes": True}})
    duree = time.monotonic() - debut
    verifier(avec_perime(code, sortie) and "délai dépassé" in sortie and duree < 4 + 2 + 2,
             f"en-têtes au goutte-à-goutte : coupé au délai total ({duree:.1f} s)", sortie)

    print("10. Champ absent : non vérifié, jamais sain")
    for nom, reponses, mot in (
        ("flag_date absent (Arch)", {ARCH: reponse_json({"results": [{"pkgname": "keepassxc", "repo": "extra",
                                                                      "pkgver": "2.8.0"}]})}, "flag_date absent"),
        ("seule la suite unstable (Debian)", {DEB: reponse_json([{"keepassxc": {"unstable": {"1": {
            "component": "main", "architectures": ["amd64"]}}}}])}, "suite inattendue (unstable)"),
        ("stable et unstable (Debian)", {DEB: reponse_json([{"keepassxc": {
            "stable": {"1": {"component": "main", "architectures": ["amd64"]}},
            "unstable": {"2": {"component": "main", "architectures": ["amd64"]}}}}])}, "suite inattendue"),
        ("nom d'un autre paquet (Fedora)", {FED: reponse_json({"version": "1", "basename": "autre"})},
         "autre paquet"),
        ("nom absent (Fedora)", {FED: reponse_json({"version": "1"})}, "autre paquet"),
        ("Bodhi : une version en préparation parmi les publiées",
         bodhi({"name": "F45", "branch": "f45", "state": "current", "id_prefix": "FEDORA"},
               {"name": "F46", "branch": "f46", "state": "pending", "id_prefix": "FEDORA"}), "en état pending"),
        ("Bodhi : aucune version publiée", bodhi({"name": "EPEL-9", "branch": "epel9", "state": "current",
                                                  "id_prefix": "FEDORA-EPEL"}), "aucune version publiée"),
        ("Bodhi : sur plusieurs pages", {BODHI: reponse_json({"page": 1, "pages": 2, "releases": []})},
         "plusieurs pages"),
        ("Bodhi : nom tordu", bodhi({"name": "F45-x", "branch": "f45", "state": "current", "id_prefix": "FEDORA"}),
         "version illisible"),
        ("Bodhi : dernière publiée absente de mdapi", {BRANCHES: reponse_json(["f44", "rawhide"])},
         "absente de mdapi"),
    ):
        code, sortie = passer(reponses=reponses)
        verifier(non_verifie(code, sortie, mot), f"{nom} : code 2", sortie)
    code, sortie = passer(reponses={FED: {"statut": 404, "corps": b"{}"}, **bodhi(
        {"name": "F44", "branch": "f44", "state": "current", "id_prefix": "FEDORA"})})
    verifier(degrade(code, sortie, "pas dans Fedora 44") and ("mdapi.fedoraproject.org", "/f44/pkg/keepassxc")
             in REQUETES, "Fedora : la branche est celle de Bodhi (f44 ici), pas la plus haute de mdapi", sortie)
    sans_winget = catalogue()
    sans_winget["logiciels"][0]["winget_id"] = sans_winget["logiciels"][0].pop("winget")
    code, sortie = passer(cat=sans_winget)
    verifier(code == 2 and "? ? KeePassXC : non vérifié (entrée du catalogue illisible" in sortie
             and "saines" not in sortie, "clé winget renommée dans le catalogue : non vérifié, jamais « pas de source »",
             sortie)
    sans_flatpak = catalogue()
    del sans_flatpak["logiciels"][0]["flatpak"]
    code, sortie = passer(cat=sans_flatpak)
    verifier(code == 2 and "entrée du catalogue illisible" in sortie, "clé flatpak absente : non vérifié", sortie)
    for nom, opensuse in (("aucune source", []), ("openSUSE seul (non couvert)", ["keepassxc"])):
        cat = catalogue()
        cat["logiciels"].append({"nom": "Vide", "licence": None, "flatpak": None, "winget": None,
                                 "paquets": {"arch": [], "debian": [], "fedora": [], "opensuse": opensuse}})
        code, sortie = passer(cat=cat)
        verifier(code == 2 and "? ? Vide : non vérifié (aucune source vérifiable pour ce logiciel)" in sortie
                 and "catalogue : 3 logiciel(s) lu(s)" in sortie, f"logiciel avec {nom} : dit, code 2", sortie)

    print("11. Magasin de certificats et variables d'OpenSSL")
    anciennes = {v: os.environ.get(v) for v in ("SSL_CERT_FILE", "SSL_CERT_DIR")}
    os.environ["SSL_CERT_FILE"] = os.path.join(TRAVAIL, "ca.pem")
    os.environ["SSL_CERT_DIR"] = TRAVAIL
    try:
        code, sortie = passer(c=client(autorite=None))
    finally:
        for v, valeur in anciennes.items():
            if valeur is None:
                os.environ.pop(v, None)
            else:
                os.environ[v] = valeur
    verifier(code == 2 and "certificat refusé" in sortie and "saines" not in sortie,
             "SSL_CERT_FILE et SSL_CERT_DIR vers l'autorité des essais : sans effet, toujours refusé", sortie)
    for variable in cs.ENV_OPENSSL:
        fini = subprocess.run([sys.executable, "-I", os.path.join(ICI, "controle-sources.py")], capture_output=True,
                              text=True, env={"PATH": os.environ.get("PATH", ""), "VANGUARD_HORS_LIGNE": "1",
                                              variable: "/dev/null"}, timeout=60)
        verifier(fini.returncode == 2 and f"rien conclu, {variable} posée(s)" in fini.stdout,
                 f"{variable} posée : rien conclu, code 2", fini.stdout + fini.stderr)


# ── Campagne C5 : les contrôles ajoutés après elle, chacun essayé seul ──


class FauxClient:
    """Rend des réponses déjà lues, sans réseau : pour les lecteurs de chaque source, essayés un à un."""

    def __init__(self, json_=None, octets=None):
        self.json_, self.octets = json_ or {}, octets

    def json(self, hote, chemin, **options):
        r = self.json_.get((hote, chemin), self.json_.get(hote))
        if isinstance(r, Exception):
            raise r
        return r

    def obtenir(self, hote, chemin, **options):
        return self.octets


def msix_sql(script, ecrit="auto", date=AUJOURD_HUI):
    """Un source2.msix dont la base est faite par `script` (SQL) ; `ecrit` : la date posée dans metadata."""
    base = sqlite3.connect(":memory:")
    base.executescript(script)
    if ecrit == "auto":
        ecrit = str(int(datetime.datetime(date.year, date.month, date.day, tzinfo=datetime.UTC).timestamp()))
    if ecrit is not None:
        base.execute("INSERT INTO metadata (name, value) VALUES ('lastwritetime', ?)", (ecrit,))
    base.commit()
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Public/index.db", base.serialize())
    return tampon.getvalue()


SAINES_SQL = ("CREATE TABLE metadata (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);"
              "CREATE TABLE packages (rowid INTEGER PRIMARY KEY, id TEXT NOT NULL, latest_version TEXT);"
              "INSERT INTO packages (id) VALUES ('Mozilla.Firefox');")


def index_lu(octets, aujourd_hui=AUJOURD_HUI):
    """(index, None) ou (None, raison) : ce que rend lire_index_winget sur ces octets."""
    try:
        return cs.lire_index_winget(FauxClient(octets=octets), aujourd_hui), None
    except cs.NonVerifie as e:
        return None, str(e)


def leve(fonction, *args):
    """La raison du NonVerifie levé, ou None si rien n'est levé (le résultat est alors rendu à part)."""
    try:
        fonction(*args)
    except cs.NonVerifie as e:
        return str(e)
    return None


def admis_entree(**changes):
    entree = {"source": "arch", "identifiant": "keepassxc", "constat": "perime", "detail": DETAIL_PERIME,
              "raison": "correctif amont attendu, suivi", "date": "2026-11-01", "jusqu_au": "2026-12-31"}
    entree.update(changes)
    return entree


def lire_admis_avec(*entrees):
    chemin = ecrire("admis-essai.json", {"format": 2, "admis": list(entrees)})
    try:
        return cs.lire_admis(chemin, AUJOURD_HUI), None
    except cs.NonVerifie as e:
        return None, str(e)


def section_12():
    print("12. Campagne C5 : délais, schéma de l'index, casse, licences, admissions, lecteurs")
    # n° 1 : un hôte à plusieurs adresses muettes. Une file d'attente pleine (listen(0), déjà remplie) laisse la
    # connexion sans réponse ; la résolution patchée rend cinq fois cette adresse. Avant la correction : 5 × 1 s.
    plein = socket.socket()
    plein.bind(("127.0.0.1", 0))
    plein.listen(0)
    port_plein = plein.getsockname()[1]
    remplis = []
    for _ in range(4):
        r = socket.socket()
        r.setblocking(False)
        r.connect_ex(("127.0.0.1", port_plein))
        remplis.append(r)
    time.sleep(0.2)
    vraie = socket.getaddrinfo
    adresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port_plein))] * 5
    try:
        socket.getaddrinfo = lambda *a, **k: adresses
        c = cs.Client(ctx=client().ctx, relier=lambda h: ("muet.example", port_plein), pause=0, delai=1,
                      delai_total=2)
        debut = time.monotonic()
        raison = leve(c.obtenir, *ARCH)
        duree = time.monotonic() - debut
        verifier(raison is not None and "délai dépassé" in raison and duree < 2.6,
                 f"cinq adresses muettes : arrêté à l'échéance de la requête ({duree:.1f} s, 2 s permises)",
                 str(raison))

        def lente(*a, **k):
            time.sleep(5)
            return adresses

        socket.getaddrinfo = lente
        c = cs.Client(ctx=client().ctx, relier=lambda h: ("lent.example", port_plein), pause=0, delai=1,
                      delai_total=2)
        debut = time.monotonic()
        raison = leve(c.obtenir, *ARCH)
        duree = time.monotonic() - debut
        verifier(raison is not None and duree < 2.6,
                 f"résolution du nom qui ne finit pas : non vérifié en {duree:.1f} s", str(raison))
    finally:
        socket.getaddrinfo = vraie
        for r in remplis:
            r.close()
        plein.close()

    # n° 2 et 9 : l'échéance de tout le passage.
    c = cs.Client(ctx=client().ctx, relier=lambda h: ("127.0.0.1", PORT), pause=0, delai_passage=0)
    raison = leve(c.obtenir, *ARCH)
    verifier(raison is not None and "délai du passage dépassé" in raison and c.requetes == 0,
             "passage échu : plus aucune requête",
             str(raison))
    c = cs.Client(ctx=client().ctx, relier=lambda h: ("127.0.0.1", PORT), pause=0, delai=2, delai_total=8,
                  delai_passage=1.5)
    debut = time.monotonic()
    code, sortie = passer(c=c, reponses=avec(*ARCH, statut=200, corps=b"", goutte=True))
    duree = time.monotonic() - debut
    verifier(non_verifie(code, sortie, "? arch keepassxc : non vérifié (délai du passage dépassé") and duree < 3,
             f"serveur qui goutte, passage de 1,5 s : coupé à l'échéance du passage ({duree:.1f} s)", sortie)

    # n° 3, 4 et 5 : l'index de winget, lu sans rien évaluer de la base.
    cas = (
        ("colonne calculée dans packages", SAINES_SQL.replace(
            "latest_version TEXT)", "latest_version TEXT, x TEXT GENERATED ALWAYS AS (upper(id)) VIRTUAL)"),
         "colonne cachée ou calculée"),
        ("colonne calculée (STORED) dans metadata", SAINES_SQL.replace(
            "value TEXT NOT NULL)", "value TEXT NOT NULL, x TEXT GENERATED ALWAYS AS (value) STORED)"),
         "colonne cachée ou calculée"),
        ("table virtuelle derrière un commentaire", SAINES_SQL + "CREATE VIRTUAL /* rien */ TABLE autre USING fts5(x);",
         "table virtuelle"),
        ("metadata à deux lignes lastwritetime", SAINES_SQL.replace("name TEXT PRIMARY KEY NOT NULL", "name TEXT")
         + "INSERT INTO metadata VALUES ('lastwritetime', '1');", "sans date lisible"),
        ("metadata au schéma faux (value INTEGER)", SAINES_SQL.replace("value TEXT NOT NULL", "value INTEGER"),
         "schéma inattendu"),
        ("packages.id INTEGER", SAINES_SQL.replace("id TEXT NOT NULL", "id INTEGER"), "sans colonne id"),
        ("plus de 1000 tables", SAINES_SQL + "".join(f"CREATE TABLE t{i} (x TEXT);" for i in range(1001)),
         "trop de tables"),
        ("identifiants en blob ou trop longs seulement", SAINES_SQL.replace(
            "('Mozilla.Firefox')", "(CAST('Mozilla.Firefox' AS BLOB)), ('" + "a" * 129 + "')"), "vide"),
        ("valeur d'un million d'octets et plus", SAINES_SQL.replace(
            "('Mozilla.Firefox')", "('Mozilla.Firefox'), ('" + "b" * 1_100_000 + "')"), "illisible"),
    )
    for nom, script, mot in cas:
        index, raison = index_lu(msix_sql(script))
        verifier(index is None and mot in (raison or ""), f"index de winget, {nom} : non vérifié ({mot})", str(raison))
    index, raison = index_lu(msix_sql(SAINES_SQL, ecrit=None))
    verifier(index is None and "sans date lisible" in (raison or ""), "index sans ligne lastwritetime : refusé",
             str(raison))
    base = sqlite3.connect(":memory:")
    base.executescript(SAINES_SQL)
    base.execute("INSERT INTO metadata VALUES ('lastwritetime', CAST('1795132800' AS BLOB))")
    base.commit()
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w") as z:
        z.writestr("Public/index.db", base.serialize())
    index, raison = index_lu(tampon.getvalue())
    verifier(index is None and "sans date lisible" in (raison or ""), "date de l'index en blob : refusée", str(raison))
    # Un CHECK qui lèverait s'il était évalué (zeroblob au-delà de la longueur permise) : quick_check ne l'évalue pas.
    piege = SAINES_SQL.replace("latest_version TEXT)", "latest_version TEXT CHECK (length(zeroblob(2000000)) > 0))")
    index, raison = index_lu(msix_sql(piege))
    verifier(index is not None and "mozilla.firefox" in index[0], "CHECK de la base jamais évalué à la lecture",
             str(raison))
    ancien = cs.DELAI_SQLITE
    cs.DELAI_SQLITE = -1
    try:
        index, raison = index_lu(msix_sql(SAINES_SQL))
    finally:
        cs.DELAI_SQLITE = ancien
    verifier(index is None and "illisible" in (raison or ""),
             "borne de temps de SQLite dépassée : lecture interrompue, non vérifié", str(raison))
    for jours, lu in ((14, True), (15, False), (-2, True), (-3, False)):
        index, raison = index_lu(msix_sql(SAINES_SQL, date=AUJOURD_HUI - datetime.timedelta(days=jours)))
        verifier((index is not None) == lu, f"index daté de J{-jours:+d} : {'lu' if lu else 'refusé'}", str(raison))

    # n° 6 et 12 : la casse de l'identifiant winget.
    verifier((cs.winget({"mozilla.firefox": {"Mozilla.Firefox"}}, "mozilla.firefox") or [("",)])[0][0] == "casse",
             "identifiant winget dans une autre casse : constat « casse »")
    verifier(cs.winget({"mozilla.firefox": {"Mozilla.Firefox", "mozilla.firefox"}}, "mozilla.firefox") == [],
             "identifiant winget présent dans sa casse exacte : sain")
    verifier((cs.winget({"editeur.autre": {"Editeur.Autre"}}, "Editeur.Voulu") or [("",)])[0][0] == "absent",
             "Editeur.Voulu absent quand seul Editeur.Autre est là : absent")
    code, sortie = passer(cat=catalogue(winget="mozilla.firefox"))
    verifier(degrade(code, sortie, "autre casse"), "catalogue en minuscules, index en majuscules : code 1", sortie)

    # n° 7 et 13 : les licences, comparées dans les deux sens.
    for nom, catal, projet, constat in (
        ("licence ajoutée par Flathub", "GPL-3.0", "GPL-3.0-or-later AND MIT", True),
        ("GPL-3.0 contre GPL-2.0-only", "GPL-3.0", "GPL-2.0-only", True),
        ("même licence, -or-later et +", "GPL-3.0+", "GPL-3.0-or-later", False),
        ("exception laissée de côté", "LGPL-2.1", "LGPL-2.1-only WITH Qt-exception-1.0", False),
    ):
        reponse = {"id": "org.exemple.Appli", "is_eol": False, "is_free_license": True, "project_license": projet,
                   "metadata": {"flathub::verification::verified": True}}
        constats = cs.flathub(FauxClient(json_={"flathub.org": reponse}), "org.exemple.Appli", catal, False)
        verifier(any(c[0] == "licence" for c in constats) == constat,
                 f"{nom} : {'constat licence' if constat else 'sain'}", repr(constats))
    verifier(leve(cs.normaliser_licences, "GPL-3.0 AND <script>") is not None,
             "morceau de licence hors de l'alphabet SPDX : rien conclu")

    # n° 8 et 14 : une valeur coupée à l'affichage garde son empreinte ; l'admission vaut pour la valeur entière.
    long_a, long_b = "2." + "9" * 60, "2." + "9" * 59 + "8"
    verifier(cs.exact(long_a, 40) != cs.exact(long_b, 40) and "[sha256:" in cs.exact(long_a, 40),
             "deux pkgver longs au même début : détails différents (empreinte)")
    verifier(cs.exact("2.8.0", 40) == "2.8.0", "valeur courte et propre : affichée telle quelle")

    def perime(pkgver):
        return {ARCH: reponse_json({"results": [{"pkgname": "keepassxc", "repo": "extra", "pkgver": pkgver,
                                                 "flag_date": "2026-06-22T20:03:01Z"}]})}

    detail = f"extra/keepassxc {cs.exact(long_a, 40)} depuis le 2026-06-22T20:03:01Z"
    admis = {"format": 2, "admis": [admis_entree(detail=detail)]}
    code, sortie = passer(admis=admis, reponses=perime(long_a))
    verifier(code == 0 and "admis le" in sortie, "pkgver long admis à l'identique : admis", sortie)
    code, sortie = passer(admis=admis, reponses=perime(long_b))
    verifier(degrade(code, sortie, "admis le 2026-11-01"), "autre pkgver long, même début : dégradation", sortie)

    # n° 10 : rien qui agisse sur le terminal, ni qui ressemble à un blanc.
    for c in ("\u3164", "\u2800", "\u115f", "\u00a0", "\u2003", "\u0301", "\u20dd", "\u05d0", "\u202e"):
        verifier(cs.propre("a" + c + "b") == "a?b", f"propre() remplace U+{ord(c):04X}")
    verifier(cs.propre("éa b-1.0") == "éa b-1.0", "propre() garde les lettres accentuées et l'espace simple")

    # n° 15 et 16 : admissions hors du catalogue, openSUSE, Ubuntu dit.
    for nom, entree in (("valable", admis_entree(identifiant="inexistant")),
                        ("échue", admis_entree(identifiant="inexistant", date="2026-01-01", jusqu_au="2026-11-21"))):
        code, sortie = passer(admis={"format": 2, "admis": [entree]})
        verifier(non_verifie(code, sortie, "source absente du catalogue"),
                 f"admission {nom} pour une source absente du catalogue : rien conclu", sortie)
    _, raison = lire_admis_avec(admis_entree(source="opensuse"))
    verifier(raison is not None and "refusé" in raison, "admission pour openSUSE (jamais jugé) : refusée", str(raison))
    code, sortie = passer()
    verifier(code == 0 and "Ubuntu et ses dérivées" in sortie, "compte rendu : Ubuntu dit non couvert", sortie)

    # n° 29 : la liste des admis, champ par champ.
    for nom, entree, lu in (
        ("source inconnue", admis_entree(source="gentoo"), False),
        ("jusqu_au avant date", admis_entree(jusqu_au="2026-10-01"), False),
        ("champ en trop", {**admis_entree(), "note": "x"}, False),
        ("raison faite d'espaces", admis_entree(raison=" " * 20), False),
        ("constat d'information (pas une dégradation)", admis_entree(constat="editeur-non-verifie"), False),
        ("jusqu_au égal à aujourd'hui", admis_entree(jusqu_au=AUJOURD_HUI.isoformat()), True),
    ):
        resultat, raison = lire_admis_avec(entree)
        valable = resultat is not None and len(resultat[0]) == 1
        verifier(valable == lu, f"admission, {nom} : {'admise' if lu else 'refusée'}", str(raison))
    _, raison = lire_admis_avec(admis_entree(), admis_entree())
    verifier(raison is not None and "deux fois" in raison, "admission en double : refusée", str(raison))
    admis = {"format": 2, "admis": [admis_entree(detail=DETAIL_PERIME[:-1])]}
    code, sortie = passer(admis=admis, reponses={ARCH: PERIME})
    verifier(degrade(code, sortie, "admis le"), "détail constaté qui prolonge le détail admis : dégradation", sortie)

    # n° 23 et 25 : les lecteurs de chaque source.
    def madison(versions, nom="keepassxc"):
        return FauxClient(json_={"api.ftp-master.debian.org": [{nom: {"stable": versions}}]})

    for nom, c, attendu in (
        ("arm64 seul", madison({"1": {"component": "main", "architectures": ["arm64"]}}), "absent"),
        ("non-free seul", madison({"1": {"component": "non-free", "architectures": ["amd64"]}}), "hors-main"),
        ("réponse d'un autre paquet", madison({"1": {"component": "main", "architectures": ["amd64"]}}, "autre"),
         "absent"),
    ):
        constats = cs.debian(c, "keepassxc")
        verifier(constats and constats[0][0] == attendu, f"Debian, {nom} : {attendu}", repr(constats))
    raison = leve(cs.flathub, FauxClient(json_={"flathub.org": {"id": "org.KeePassXC.KeePassXC"}}),
                  "org.keepassxc.KeePassXC", "GPL-3.0", False)
    verifier(raison is not None and "autre application" in raison, "Flathub, id d'une autre casse : non vérifié",
             str(raison))
    raison = leve(cs.fedora, FauxClient(json_={"mdapi.fedoraproject.org": {"version": "1", "basename": "keepassxc-x"}}),
                  "f45", "keepassxc")
    verifier(raison is not None and "autre paquet" in raison, "Fedora, basename plus long : non vérifié", str(raison))
    for nom, resultats, attendu in (
        ("core-testing seul", [{"pkgname": "keepassxc", "repo": "core-testing", "pkgver": "1", "flag_date": None}],
         "absent"),
        ("flag_date vide", [{"pkgname": "keepassxc", "repo": "extra", "pkgver": "1", "flag_date": ""}], "perime"),
    ):
        constats = cs.arch(FauxClient(json_={"archlinux.org": {"results": resultats}}), "keepassxc")
        verifier(constats and constats[0][0] == attendu, f"Arch, {nom} : {attendu}, jamais sain", repr(constats))
    bodhi_gele = {"pages": 1, "releases": [{"name": "F45", "branch": "f45", "state": "frozen", "id_prefix": "FEDORA"}]}
    raison = leve(cs.branche_fedora, FauxClient(json_={"bodhi.fedoraproject.org": bodhi_gele}))
    verifier(raison is not None and "frozen" in raison, "Bodhi, version gelée dans les publiées : non vérifié",
             str(raison))
    for statut in (403, 500):
        code, sortie = passer(reponses=avec(*FLAT, statut=statut, corps=b"{}", type="application/json"))
        verifier(non_verifie(code, sortie, f"réponse {statut}"), f"Flathub répond {statut} : non vérifié", sortie)

    # n° 27 : les variables d'OpenSSL, écrites en dur ; posée vide, elle compte aussi.
    verifier(cs.ENV_OPENSSL == ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES"),
             "variables d'OpenSSL refusées : les trois, nommées")
    fini = subprocess.run([sys.executable, "-I", os.path.join(ICI, "controle-sources.py")], capture_output=True,
                          text=True, env={"PATH": os.environ.get("PATH", ""), "VANGUARD_HORS_LIGNE": "1",
                                          "OPENSSL_CONF": ""}, timeout=60)
    verifier(fini.returncode == 2 and "OPENSSL_CONF posée" in fini.stdout, "OPENSSL_CONF posée vide : rien conclu",
             fini.stdout + fini.stderr)

    # n° 30 : le vrai outil, sur les vrais fichiers du dépôt, hors ligne ; le client par défaut ; la liste fermée.
    fini = subprocess.run([sys.executable, "-I", os.path.join(ICI, "controle-sources.py")], capture_output=True,
                          text=True, env={"PATH": os.environ.get("PATH", ""), "VANGUARD_HORS_LIGNE": "1"}, timeout=60)
    verifier(fini.returncode == 2 and "non vérifiée(s)" in fini.stdout and "lecture impossible" not in fini.stdout,
             "vrai outil, vrais catalogue et admis, hors ligne : lus, puis rien conclu", fini.stdout + fini.stderr)
    verifier(cs.Client(ctx=client().ctx).relier("archlinux.org") == ("archlinux.org", 443),
             "client par défaut : l'hôte permis, port 443")
    raison = leve(client().obtenir, "flathub.org", "/cache/source2.msix")
    verifier(raison is not None and "hors de la liste fermée" in raison,
             "chemin de winget demandé à flathub.org : hors de la liste fermée", str(raison))


try:
    principal()
    section_12()
finally:
    SERVEUR.shutdown()
    SANS_FEDORA.shutdown()
    shutil.rmtree(TRAVAIL, ignore_errors=True)

if ECHECS:
    print(f"✖ {ECHECS} essai(s) du contrôle des sources en échec")
    sys.exit(1)
print("✔ contrôle des sources : essais hors ligne verts")
