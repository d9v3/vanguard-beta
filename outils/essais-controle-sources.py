#!/usr/bin/env python3
"""Essais hors ligne de outils/controle-sources.py : un faux serveur HTTPS sur la boucle locale, signé par une autorité
jetable (openssl), répond à la place d'Arch, Flathub, winget, Debian et Fedora. Rien ne sort de l'ordinateur ; les
réponses et le catalogue sont inventés. Le nom vérifié dans le certificat reste celui de l'hôte permis : seuls
l'autorité et l'adresse jointe changent.
  1. Tout sain : code 0 et son témoin ; chaque source interrogée, au bon chemin.
  2. Périmé (Arch), licence changée (Flathub, FLATHUB_PAS_LIBRE devenue libre aussi), fin de vie, éditeur non
     vérifié, absent de chaque source, hors de main (Debian) : code 1 et le témoin « N dégradation(s) ».
  3. Admis (liste versionnée) : code 0 et dit ; échu : de nouveau une dégradation ; liste mal faite : rien conclu.
  4. Délai, réponse géante (annoncée ou non), compressée, mauvais type, JSON piégé (clé en double, NaN, trop
     profond, UTF-8 faux), réponse d'une autre application, redirection hors liste (jamais suivie), certificat d'une
     autre autorité, certificat sans le nom de l'hôte : non vérifié, code 2, jamais sain.
  5. Séquences d'échappement, bidi et invisibles dans un champ distant : rien de tout ça à l'écran.
  6. Identifiant hostile dans le catalogue : jamais envoyé, code 2.
  7. Index de winget : trop vieux, sans table, piégé (vue à la place de la table, déclencheur), bombe : code 2.
  8. VANGUARD_HORS_LIGNE=1 : aucune requête, code 2, en moins d'une seconde.
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
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
            if r.get("flot"):
                self.send_header("Connection", "close")
                self.end_headers()
                for _ in range(r["flot"]):
                    self.wfile.write(b" " * 65536)
                return
            self.send_header("Content-Length", r.get("longueur", str(len(r["corps"]))))
            self.end_headers()
            self.wfile.write(r["corps"])
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


def serveur(nom):
    s = ThreadingHTTPServer(("127.0.0.1", 0), Gestion)
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


def index_winget(ids=("Mozilla.Firefox", "GIMP.GIMP.3"), date=AUJOURD_HUI, piege=None):
    base = sqlite3.connect(":memory:")
    base.execute("CREATE TABLE metadata (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
    ecrit = int(datetime.datetime(date.year, date.month, date.day, tzinfo=datetime.UTC).timestamp())
    base.execute("INSERT INTO metadata VALUES ('lastwritetime', ?)", (str(ecrit),))
    if piege == "vue":
        base.execute("CREATE TABLE vraie (id TEXT)")
        base.execute("CREATE VIEW packages AS SELECT id FROM vraie")
    elif piege != "sans-table":
        base.execute("CREATE TABLE packages (rowid INTEGER PRIMARY KEY, id TEXT NOT NULL, latest_version TEXT)")
        base.executemany("INSERT INTO packages (id, latest_version) VALUES (?, '1.0')", [(i,) for i in ids])
    if piege == "declencheur":
        base.execute("CREATE TABLE journal (x TEXT)")
        base.execute("CREATE TRIGGER t AFTER INSERT ON packages BEGIN INSERT INTO journal VALUES ('x'); END")
    base.commit()
    donnees = base.serialize()
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Public/index.db", donnees)
        z.writestr("AppxManifest.xml", "<Package/>")
    return tampon.getvalue()


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
    ("mdapi.fedoraproject.org", "/branches"): reponse_json(["epel9", "f44", "f45", "rawhide", "src_f45"]),
    ("mdapi.fedoraproject.org", "/f45/pkg/keepassxc"): reponse_json({"version": "2.8.0", "release": "1.fc45"}),
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
        {"nom": "KeePassXC", "licence": "GPL-3.0", "paquets": {"arch": ["keepassxc"], "debian": ["keepassxc"],
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
    chemin_admis = ecrire("admis.json", admis if admis is not None else {"format": 1, "admis": []})
    tampon = io.StringIO()
    ancien = os.environ.get("VANGUARD_HORS_LIGNE")
    if env is not None:
        os.environ["VANGUARD_HORS_LIGNE"] = env
    try:
        with contextlib.redirect_stdout(tampon):
            code = cs.principal(["--catalogue", chemin_cat, "--admis", chemin_admis], client=c or client(),
                                aujourd_hui=AUJOURD_HUI)
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
    attendues = {ARCH, FLAT, FLAT_COM, DEB, FED, MSIX, ("mdapi.fedoraproject.org", "/branches")}
    verifier(code == 0 and "Sources : 7 vérifiée(s), saines (0 admise(s))." in sortie and set(REQUETES) == attendues
             and "1 paquet(s) openSUSE" in sortie, "sain : code 0, témoin, chaque source à son chemin", sortie)

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
    admis = {"format": 1, "admis": [{"source": "arch", "identifiant": "keepassxc", "constat": "perime",
                                     "raison": "attendu de l'amont, revu à la main", "date": "2026-11-01",
                                     "jusqu_au": "2026-12-31"}]}
    code, sortie = passer(admis=admis, reponses={ARCH: perime})
    verifier(code == 0 and "≈ arch keepassxc : marqué périmé, admis le 2026-11-01" in sortie, "admis : code 0, dit",
             sortie)
    echu = json.loads(json.dumps(admis))
    echu["admis"][0]["jusqu_au"] = "2026-11-21"
    code, sortie = passer(admis=echu, reponses={ARCH: perime})
    verifier(degrade(code, sortie, "marqué périmé") and "admission échue le 2026-11-21" in sortie,
             "admis échu : de nouveau une dégradation", sortie)
    autre = json.loads(json.dumps(admis))
    autre["admis"][0]["constat"] = "absent"
    code, sortie = passer(admis=autre, reponses={ARCH: perime})
    verifier(degrade(code, sortie, "marqué périmé"), "admis pour un autre constat : ne couvre pas celui-ci", sortie)
    for nom, champ, valeur in (("sans raison", "raison", "ok"), ("plus d'un an", "jusqu_au", "2028-01-01"),
                               ("constat inconnu", "constat", "tout"), ("date fausse", "date", "hier")):
        mal = json.loads(json.dumps(admis))
        mal["admis"][0][champ] = valeur
        code, sortie = passer(admis=mal)
        verifier(code == 2 and "rien conclu" in sortie and not REQUETES, f"liste des admis {nom} : refusée", sortie)
    double = json.loads(json.dumps(admis))
    double["admis"].append(double["admis"][0])
    code, sortie = passer(admis=double)
    verifier(code == 2 and "deux fois" in sortie, "liste des admis : une entrée en double refusée", sortie)

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
        ("Flathub : is_eol absent", flathub_avec(is_eol="non"), "is_eol"),
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
    code, sortie = passer(reponses=flathub_avec(project_license="MIT\x1b[2J‮", is_free_license=True))
    verifier(code == 1 and "\x1b" not in sortie and "‮" not in sortie, "licence piégée : assainie", repr(sortie))

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
        ("sans table", index_winget(piege="sans-table"), "sans table"),
        ("vue à la place de la table", index_winget(piege="vue"), "sans table"),
        ("pas une archive", b"PK\x03\x04pas une archive", "illisible"),
        ("archive sans index", b"", "illisible"),
    ):
        code, sortie = passer(reponses={MSIX: {"statut": 200, "corps": corps, "type": "application/octet-stream"}})
        verifier(non_verifie(code, sortie, mot), f"index {nom} : code 2", sortie)
    code, sortie = passer(reponses={MSIX: {"statut": 200, "corps": index_winget(piege="declencheur"),
                                           "type": "application/octet-stream"}})
    verifier(code == 0, "index avec un déclencheur : lu sans rien exécuter (lecture seule)", sortie)
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
    c = cs.Client(relier=lambda h: ("127.0.0.1", 9), pause=0, delai=2)
    code, sortie = passer(c=c)
    verifier(code == 2 and "injoignable" in sortie and "saines" not in sortie,
             "serveurs injoignables : code 2, rien de sain", sortie)
    # Un catalogue vidé (export raté, liste retirée) ne prouve rien : jamais « 0 vérifiée(s), saines ».
    code, sortie = passer(cat={"format": 1, "flathub_pas_libre": [], "logiciels": []})
    verifier(code == 2 and not REQUETES and "aucune source vérifiée" in sortie and "saines" not in sortie,
             "catalogue vide : code 2, rien de sain", sortie)


try:
    principal()
finally:
    SERVEUR.shutdown()
    SANS_FEDORA.shutdown()
    shutil.rmtree(TRAVAIL, ignore_errors=True)

if ECHECS:
    print(f"✖ {ECHECS} essai(s) du contrôle des sources en échec")
    sys.exit(1)
print("✔ contrôle des sources : essais hors ligne verts")
