#!/usr/bin/env python3
"""Garde-fou : rien de personnel ne part sur GitHub. Ni dans le code, ni dans un message de commit, ni dans le nom de
l'auteur, ni dans une page de version, un ticket ou une capture d'écran.

Lancé tout seul : à chaque commit (crochets outils/hooks/pre-commit et commit-msg, actifs avec
`git config core.hooksPath outils/hooks`), avant chaque envoi (outils/deployer.sh), avant chaque page de version
(outils/publier-version.sh), avant chaque ticket du journal (outils/journal-vers-github.py) et avant d'écrire les
captures du README (outils/captures.py).

Ce qui est personnel est lu sur cet ordinateur, jamais écrit dans le dépôt, qui le publierait lui-même :
- ~/.config/vanguard-dev/confidentiel.txt : une expression par ligne (nom, courriels, adresse…), « # » en commentaire ;
- le courriel et le nom de l'identité Git de l'ordinateur, le nom complet du compte, ses dossiers (/home/<compte>…) ;
- les appareils de la base de Vanguard (noms, adresses MAC), les réseaux Wi-Fi enregistrés et leurs bornes, le nom de
  l'ordinateur.
S'y ajoute, reconnu à sa forme, ce qui pourrait être la donnée de quelqu'un d'autre (les gens chez qui la clé passe) :
compte d'un dossier personnel (« C:\\Users\\<nom> »), courriel, SID de Windows. Les valeurs inventées des tests sont
permises (COMPTES_INVENTES : alice, bob, Zoé… ; courriels d'exemple ; SID de la documentation de Microsoft). Un
ticket du journal, lui, est masqué avant l'envoi (masquer_autrui), adresses MAC et IP comprises.

Depuis la racine du dépôt :
    python3 outils/confidentialite.py --commit           ce qui va être commité : lignes ajoutées, fichiers, auteur
    python3 outils/confidentialite.py --message FICHIER  un message de commit
    python3 outils/confidentialite.py --envoi            les commits pas encore sur GitHub
    python3 outils/confidentialite.py --texte < FICHIER  un texte à publier
    python3 outils/confidentialite.py --binaire FICHIER… des programmes compilés (textes lisibles, métadonnées)
    python3 outils/confidentialite.py --depot            les fichiers et tout l'historique (avant de rendre le dépôt
                                                         public)
    python3 outils/confidentialite.py --plage AVANT APRÈS
                                                         les commits de AVANT (exclu) à APRÈS : ceux d'un envoi
Avec --generique (la CI de GitHub) : seulement ce qui se reconnaît à sa forme (dossier personnel d'un compte,
courriel, SID de Windows), sans rien lire de la machine qui le lance : sur GitHub, son compte « runner » et
/home/runner ne sont à personne.
Sort en erreur (code 1) en disant quoi et où dès qu'un détail personnel paraît.
"""

import getpass
import ipaddress
import json
import os
import random
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import pwd
except ImportError:  # Windows
    pwd = None

PRIVE = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "vanguard-dev/confidentiel.txt"
MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
# Adresse que GitHub donne à chaque compte pour signer ses commits sans montrer son courriel.
ANONYME = "@users.noreply.github.com"

# Noms d'appareils et de réseaux sans rien de personnel : sortes d'appareils, pièces, produits courants. Un nom fait
# seulement de ces mots n'est pas caché (il paraît aussi dans le code : « 8009 Chromecast », réseau « Salon » des tests).
MOTS_GENERIQUES = set(
    "imprimante printer box routeur router modem téléphone telephone phone tablette tablet ordinateur computer pc "
    "portable laptop console télé tele tv télévision television caméra camera enceinte speaker montre watch nas "
    "serveur server switch répéteur repeater borne wifi hp lg local gateway _gateway localhost salon cuisine chambre "
    "bureau garage maison home office kitchen living room bedroom chromecast airplay echo alexa nest google apple "
    "iphone ipad macbook imac android galaxy pixel kindle fire roku sonos xbox playstation nintendo raspberrypi "
    "raspberry pi synology brother epson canon samsung sony".split()
)
DISTRIBUTIONS = {"omarchy", "archlinux", "arch", "ubuntu", "fedora", "debian", "linuxmint", "mint", "pop-os",
                 "manjaro", "endeavouros", "cachyos", "bazzite", "opensuse", "localhost"}


@dataclass(frozen=True)
class Terme:
    texte: str
    origine: str
    motif: str


def generique(nom: str) -> bool:
    mots = re.findall(r"[\wÀ-ÿ-]+", nom.lower())
    return bool(mots) and all(m in MOTS_GENERIQUES or m in DISTRIBUTIONS for m in mots)


def motif_texte(texte: str) -> str:
    """Le texte comme mot entier (« Chez Max » pas dans « Chez Maxime »), espaces souples (retour à la ligne compris)."""
    corps = r"\s+".join(re.escape(m) for m in texte.split())
    debut = r"(?<!\w)" if re.match(r"\w", texte) else ""
    fin = r"(?!\w)" if re.search(r"\w$", texte) else ""
    return debut + corps + fin


def motif_mac(mac: str) -> str:
    """Une adresse MAC sous ses trois écritures : « aa:bb:… » ou « aa-bb-… » (Windows), « aabb… », et sans les zéros de
    tête (« 3c:8d:a:… », comme l'écrit arp sous macOS)."""
    octets = mac.lower().split(":")
    sans_zeros = ":".join(f"0?{o[1]}" if o[0] == "0" else o for o in octets)
    return rf"(?<![0-9a-f:-])(?:{'[:-]'.join(octets)}|{''.join(octets)}|{sans_zeros})(?![0-9a-f])"


def compte() -> str:
    return os.environ.get("USER") or getpass.getuser()


def dossiers_vanguard():
    """Dossier des données de cet ordinateur, et celui de la clé branchée : la base des appareils vit sur les deux."""
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    local = base / "vanguard" if (base / "vanguard").is_dir() else None
    cle = None
    for media in (Path("/run/media") / compte(), Path("/media") / compte()):
        try:
            for d in media.iterdir():
                if (d / "vanguard.cle").is_file():
                    cle = d / "donnees"
        except OSError:
            continue
    return local, cle


def appareils(*bases):
    """Noms (appareils, surnoms, réseaux) qui pourraient nommer quelqu'un, et adresses MAC, des bases d'appareils."""
    noms, macs = set(), set()
    for base in bases:
        try:
            texte = base.read_text()
            donnees = json.loads(texte)
        except (OSError, ValueError):
            continue
        macs |= {m.lower() for m in MAC.findall(texte)}
        for reseau in donnees.get("reseaux", {}).values():
            noms.add(reseau.get("nom") or "")
            for appareil in reseau.get("appareils", {}).values():
                noms |= {appareil.get(champ) or "" for champ in ("nom", "surnom")}
    return {n for n in noms if len(n) >= 3 and not generique(n)}, macs


def nmcli(*args):
    try:
        return subprocess.run(["nmcli", *args], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def reseaux_enregistres():
    """Réseaux Wi-Fi et VPN enregistrés (nom de la connexion et nom du Wi-Fi), et les bornes déjà vues."""
    noms, bornes = set(), set()
    for ligne in nmcli("-t", "-f", "NAME,TYPE", "connection", "show").splitlines():
        nom, _, genre = ligne.rpartition(":")
        if not nom or genre not in ("802-11-wireless", "vpn", "wireguard"):
            continue
        noms.add(nom.replace("\\:", ":"))
        if genre == "802-11-wireless":
            ssid, _, vues = nmcli("-g", "802-11-wireless.ssid,802-11-wireless.seen-bssids", "connection", "show",
                                  nom.replace("\\:", ":")).partition("\n")
            noms.add(ssid.strip().replace("\\:", ":"))
            bornes |= {m.lower() for m in MAC.findall(vues.replace("\\", ""))}
    return {n for n in noms if n}, bornes


def termes():
    """Tout ce qui ne doit jamais être publié, avec d'où ça vient."""
    liste = []

    def ajouter(texte, origine, motif=None):
        if texte and not any(t.texte.lower() == texte.lower() for t in liste):
            liste.append(Terme(texte, origine, motif or motif_texte(texte)))

    if PRIVE.is_file():
        for ligne in PRIVE.read_text().splitlines():
            if ligne.strip() and not ligne.lstrip().startswith("#"):
                ajouter(ligne.strip(), "liste privée")
    for cle in ("user.email", "user.name"):
        valeur = subprocess.run(["git", "config", "--global", cle], capture_output=True, text=True).stdout.strip()
        if len(valeur) >= 5 and not valeur.endswith(ANONYME):
            ajouter(valeur, "identité Git de l'ordinateur")
    if pwd:
        try:
            ajouter(pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip(), "nom complet du compte")
        except KeyError:
            pass
    moi = re.escape(compte())
    hote = socket.gethostname().split(".")[0]
    ajouter(f"/home/{compte()}", "dossier personnel",
            rf"(?:/home|/Users|/run/media|/media)/{moi}(?![\w.-])|[A-Za-z]:\\+Users\\+{moi}(?![\w.-])")
    ajouter(f"{compte()}@{hote}", "compte et nom de l'ordinateur")
    if len(hote) >= 4 and hote.lower() not in DISTRIBUTIONS and not generique(hote):
        ajouter(hote, "nom de l'ordinateur")
    noms, macs = appareils(*(d / "appareils.json" for d in dossiers_vanguard() if d))
    reseaux, bornes = reseaux_enregistres()
    for nom in sorted(noms | {n for n in reseaux if not generique(n)}):
        if len(nom) >= 4:
            ajouter(nom, "appareil ou réseau de la maison")
    for mac in sorted(macs | bornes):
        ajouter(mac, "adresse MAC de la maison", motif_mac(mac))
    return liste


class Detecteur:
    def __init__(self, liste, autrui=False):
        self.termes = liste
        self.motif = re.compile("|".join(f"(?P<t{i}>{t.motif})" for i, t in enumerate(liste)), re.IGNORECASE) \
            if liste else None
        self.autrui = autrui

    def trouver(self, texte: str, autrui=None):
        """(terme, numéro de ligne) de chaque détail personnel du texte ; avec `autrui`, aussi ce qui pourrait être
        la donnée de quelqu'un d'autre (donnees_d_autrui)."""
        trouves = [(self.termes[int(m.lastgroup[1:])], texte.count("\n", 0, m.start()) + 1)
                   for m in self.motif.finditer(texte)] if self.motif else []
        if self.autrui if autrui is None else autrui:
            trouves += [(t, texte.count("\n", 0, p) + 1) for t, p in donnees_d_autrui(texte)]
        return trouves


# --- Masque : adresses remplacées (captures du README, tickets du journal) ------------------------------------------

MAC_TIRETS = re.compile(r"(?<![0-9A-Fa-f-])[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f-])")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
# Valeurs d'un octet selon leur nombre de chiffres : un remplaçant garde la longueur de l'original.
OCTETS = {1: range(0, 10), 2: range(10, 100), 3: range(100, 256)}
# Réseau, box et diffusion : les mêmes chez tout le monde, gardés.
HOTES_FIXES = {0, 1, 254, 255}
LOCAUX = [ipaddress.ip_network(n) for n in
          ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")]
# Services DNS publics connus (fournisseur() de src/machine/dns.rs) : les mêmes pour tout le monde, gardés.
RESOLVEURS = [ipaddress.ip_network(n) for n in (
    "1.1.1.0/24", "1.0.0.0/24", "8.8.8.8/32", "8.8.4.4/32", "9.9.9.0/24", "149.112.112.0/24", "208.67.222.0/24",
    "208.67.220.0/24", "45.90.28.0/24", "45.90.30.0/24", "94.140.14.0/24", "94.140.15.0/24", "194.242.2.0/24",
    "185.228.168.0/24", "185.228.169.0/24", "76.76.2.0/24", "76.76.10.0/24", "100.100.100.100/32",
    "2606:4700::/32", "2001:4860::/32", "2620:fe::/32", "2620:119::/32", "2a07:a8c0::/32", "2a07:a8c1::/32",
    "2a10:50c0::/32", "2a07:e340::/32")]
# Adresses réservées à la documentation (RFC 5737, RFC 3849) : elles remplacent les adresses publiques.
DOCUMENTATION = ("192.0.2.", "203.0.113.", "198.51.100.")
DOC6 = ipaddress.ip_network("2001:db8::/32")


class Masque:
    """Remplaçants des adresses de la maison, pour une passe. Tirés au hasard : un remplaçant calculé sans secret
    (empreinte de l'adresse) se retrouverait en essayant toutes les adresses possibles, 2²⁴ par fabricant pour une
    adresse MAC. Chacun a la longueur de l'original : les tableaux restent alignés."""

    def __init__(self, textes):
        self.hasard = random.SystemRandom()
        self.adresses = {}  # vraie adresse (MAC, IPv4, IPv6) → remplaçant
        self.reseaux = {}  # trois premiers octets d'un réseau local → ceux du réseau inventé
        locales = {a for t in textes for a in IPV4.findall(t) if self.locale(a)}
        self.reels = {a.rsplit(".", 1)[0] for a in locales}
        # Tous les hôtes d'un réseau sont tirés ensemble, dans l'ordre : un tableau trié par adresse le reste.
        for prefixe in sorted(self.reels):
            self.reseau(prefixe, sorted({int(a.rsplit(".", 1)[1]) for a in locales if a.startswith(prefixe + ".")}))

    @staticmethod
    def locale(adresse):
        try:
            ip = ipaddress.IPv4Address(adresse)
        except ValueError:
            return False
        return any(ip in r for r in LOCAUX) and not any(ip in r for r in RESOLVEURS)

    def reseau(self, prefixe, hotes):
        """Réseau inventé de la même sorte (10.x.y, 172.16-31.y, 192.168.y…), puis ses hôtes : même nombre de
        chiffres, même ordre, réseau, box et diffusion gardés."""
        if prefixe not in self.reseaux:
            o1, o2, o3 = prefixe.split(".")
            if o1 == "10":
                deuxiemes = OCTETS[len(o2)]
            elif o1 == "172":
                deuxiemes = range(16, 32)
            elif o1 == "100":
                deuxiemes = [x for x in range(64, 128) if len(str(x)) == len(o2)]
            else:  # 192.168, 169.254
                deuxiemes = [int(o2)]
            pris = self.reels | set(self.reseaux.values())
            libres = [f"{o1}.{a}.{b}" for a in deuxiemes for b in OCTETS[len(o3)] if f"{o1}.{a}.{b}" not in pris]
            self.reseaux[prefixe] = self.hasard.choice(libres)
        faux = self.reseaux[prefixe]
        deja = {int(v.rsplit(".", 1)[1]) for k, v in self.adresses.items() if k.startswith(prefixe + ".")}
        for chiffres, valeurs in OCTETS.items():
            a_tirer = [h for h in hotes if h not in HOTES_FIXES and len(str(h)) == chiffres]
            choix = sorted(self.hasard.sample([v for v in valeurs if v not in HOTES_FIXES | deja], len(a_tirer)))
            for reel, neuf in zip(a_tirer, choix):
                self.adresses[f"{prefixe}.{reel}"] = f"{faux}.{neuf}"
        for h in hotes:
            if h in HOTES_FIXES:
                self.adresses[f"{prefixe}.{h}"] = f"{faux}.{h}"

    def ipv4(self, adresse):
        if adresse in self.adresses:
            return self.adresses[adresse]
        try:
            ip = ipaddress.IPv4Address(adresse)
        except ValueError:
            return adresse
        if self.locale(adresse):
            prefixe, hote = adresse.rsplit(".", 1)
            self.reseau(prefixe, [int(hote)])
        elif not ip.is_global or ip.is_multicast or any(ip in r for r in RESOLVEURS):
            return adresse
        else:
            self.adresses[adresse] = self.publique(adresse)
        return self.adresses[adresse]

    def publique(self, adresse):
        """Adresse de documentation de même longueur ; sinon (7, 8 ou 15 caractères), quatre nombres au hasard de
        mêmes longueurs, qui ne mènent ni chez soi ni à un service connu."""
        pris = set(self.adresses.values())
        for prefixe in DOCUMENTATION:
            chiffres = len(adresse) - len(prefixe)
            if chiffres in OCTETS:
                libres = [f"{prefixe}{h}" for h in OCTETS[chiffres] if h not in HOTES_FIXES]
                libres = [a for a in libres if a not in pris]
                if libres:
                    return self.hasard.choice(libres)
        while True:
            faux = ".".join(str(self.hasard.choice(OCTETS[len(o)])) for o in adresse.split("."))
            ip = ipaddress.IPv4Address(faux)
            if ip.is_global and faux != adresse and faux not in pris and not any(ip in r for r in RESOLVEURS):
                return faux

    def ipv6(self, adresse):
        if adresse in self.adresses:
            return self.adresses[adresse]
        try:
            ip = ipaddress.IPv6Address(adresse)
        except ValueError:
            return adresse
        groupes = adresse.split(":")
        premier = next(i for i, g in enumerate(groupes) if g) if any(groupes) else 0
        # Le premier groupe dit seulement la sorte d'adresse (2xxx Internet, fdxx réseau local, fe80 lien local) ;
        # une adresse presque vide (« fe80::1 », « fd00::1 ») est la même chez tout le monde.
        if (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip in DOC6
                or any(ip in r for r in RESOLVEURS) or sum(len(g) for g in groupes[premier + 1 :]) <= 4):
            return adresse
        while True:
            faux = ":".join(g if i <= premier or not g else self.hexa(len(g)) for i, g in enumerate(groupes))
            if faux != adresse and faux not in self.adresses.values():
                self.adresses[adresse] = faux
                return faux

    def hexa(self, longueur):
        chiffres = "0123456789abcdef"
        return self.hasard.choice(chiffres[1:]) + "".join(self.hasard.choice(chiffres) for _ in range(longueur - 1))

    def mac(self, adresse):
        cle = adresse.lower()
        if cle not in self.adresses:
            octets = cle.split(":")
            premier = int(octets[0], 16)
            while True:
                if premier & 0x02:
                    # Adresse aléatoire (téléphones…) : aléatoire elle aussi, mêmes bits de sorte.
                    debut = [f"{(self.hasard.randrange(256) & 0xFC) | (premier & 0x03):02x}"]
                    debut += [f"{self.hasard.randrange(256):02x}" for _ in range(2)]
                else:
                    # Préfixe du fabricant gardé : son nom est écrit en clair à côté.
                    debut = octets[:3]
                faux = ":".join(debut + [f"{self.hasard.randrange(256):02x}" for _ in range(3)])
                if faux != cle and faux not in self.adresses.values():
                    self.adresses[cle] = faux
                    break
        return self.adresses[cle]

    def mac_tirets(self, adresse):
        """Écriture de Windows (« 3C-22-FB-… ») : le même remplaçant, écrit pareil."""
        faux = self.mac(adresse.replace("-", ":")).replace(":", "-")
        return faux.upper() if any(c.isupper() for c in adresse) else faux

    def texte(self, t):
        t = MAC.sub(lambda m: self.mac(m.group()), t)
        t = MAC_TIRETS.sub(lambda m: self.mac_tirets(m.group()), t)
        t = IPV4.sub(lambda m: self.ipv4(m.group()), t)
        return IPV6.sub(lambda m: self.ipv6(m.group()), t)

    def termes(self):
        """Les vraies adresses remplacées, pour vérifier qu'aucune ne reste."""
        return [Terme(a, "adresse de la maison",
                      motif_mac(a) if MAC.fullmatch(a) else rf"(?<![\w.:]){re.escape(a)}(?![\w:]|\.\d)")
                for a, faux in self.adresses.items() if a != faux]


# --- Données des autres ----------------------------------------------------------------------------------------------
# Ce que les listes ne peuvent pas connaître d'avance : les gens chez qui la clé est passée (leur journal d'erreurs
# revient ici, puis part en tickets), un journal recopié dans un test. Leurs données ont une forme : compte d'un
# dossier personnel, courriel, SID de Windows, numéro de série, nom d'un appareil du réseau local, nom du Wi-Fi.

# Dossiers communs à tous les ordinateurs : ils ne nomment personne.
COMPTES_COMMUNS = {"public", "default", "default user", "all users", "defaultuser0", "shared", "guest",
                   "wdagutilityaccount"}
# Comptes inventés des tests, et des machines de GitHub (« runner ») : permis dans le dépôt, masqués dans un ticket
# (quelqu'un peut vraiment s'appeler Alice).
COMPTES_INVENTES = {"alice", "bob", "zoé", "jean dupont", "moi", "x", "a", "a&b", "root", "runner", "capture", "user",
                    "utilisateur", "compte", "account", "username", "nom", "name", "test", "zoé d'alice",
                    # Et sa forme dans une chaîne PowerShell, l'apostrophe doublée.
                    "zoé o'brien", "zoé o''brien"}
DEBUT_COMPTE_UNIX = re.compile(r"(?:/var/home|/run/media|/home|/Users|/media)/", re.IGNORECASE)
DEBUT_COMPTE_WINDOWS = re.compile(r"(?<![A-Za-z])[A-Za-z]:(\\\\|\\|/)Users\1", re.IGNORECASE)
FIN_COMPTE_WINDOWS = set("\\/\"\n\r\t:;,|<>*?)]")
COURRIEL = re.compile(r"(?<![\w.%+-])[\w.%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
# Adresses qui ne sont celles de personne : exemples, rôles (noreply…), identifiants publics (extension uBlock Origin).
DOMAINES_EXEMPLES = re.compile(r"(?:^|\.)(?:example\.(?:com|net|org)|exemple\.[a-z]+)$|\.(?:example|invalid|test|"
                               r"localhost|local)$|^users\.noreply\.github\.com$", re.IGNORECASE)
ROLES = {"noreply", "no-reply", "security", "support", "contact", "info", "admin", "abuse", "postmaster",
         "webmaster", "git"}
# kexguess2@matt.ucc.asn.au : extension de l'échange de clés de Dropbear (serveur SSH), un nom de protocole public.
COURRIELS_PUBLICS = {"ublock0@raymondhill.net", "kexguess2@matt.ucc.asn.au"}
# Noms d'algorithmes du protocole SSH (« hmac-md5-etm@openssh.com ») : la forme d'un courriel, pas une personne.
# Toujours des mots reliés par des tirets, ce que les comptes de ces domaines n'ont pas. Aussi tels qu'écrits dans
# sshd_config (« KexAlgorithms +nom », « -nom », « ^nom ») et sans égard à la casse (OpenSSH les compare ainsi).
ALGORITHME_SSH = re.compile(r"[a-z0-9]+(?:-[a-z0-9.]+)+@(?:openssh\.com|libssh\.org|lysator\.liu\.se)")
SID = re.compile(r"S-1-5-21-(\d+)-(\d+)-(\d+)")
# SID d'exemple de la documentation de Microsoft.
SID_EXEMPLE = ("1004336348", "1177238915", "682003330")
SERIE = re.compile(r"(?<!\w)(serial[ _]?number|serial no|serial|numéro de série|ioplatformuuid|ioplatformserialnumber|"
                   r"uuid)(?!\w)([ \t\"\d]*[:=][ \t\"]*)(?!<)([^\s\",;]+)", re.IGNORECASE)
WIFI_CLE = re.compile(r"(?<!\w)(ssid|all user profile|profil tous les utilisateurs|current user profile)(?!\w)"
                      r"([ \t\"\d]*[:=][ \t\"]*)(?!<)([^\n\r\"]*[^\s\"])", re.IGNORECASE)
LIGNE_WIFI = re.compile(r"wi-?fi|ssid|wlan|wireless|sans fil", re.IGNORECASE)
NOM_LOCAL = re.compile(r"(?<![\w.-])[\w-][\w.-]*?(?=\.(?:home\.arpa|internal|local|home|lan)(?![\w-]))",
                       re.IGNORECASE)
# Les licences des bibliothèques nomment leurs auteurs avec leur courriel : publics, voulus. Les relectures importées
# par cargo vet aussi, celui de chaque relecteur, recopiées telles quelles des registres publics de Google, Mozilla…
TIERS = {"LICENCES-TIERCES.txt", "Cargo.lock", "supply-chain/imports.lock"}


def comptes(texte):
    """(début, fin, nom) de chaque compte nommé par un dossier personnel : « /home/<nom> », « C:\\Users\\<nom> »."""
    for m in DEBUT_COMPTE_UNIX.finditer(texte):
        if re.search(r"[A-Za-z]:$", texte[max(0, m.start() - 2):m.start()]):
            continue  # « C:/Users/… » : un chemin de Windows, vu plus bas
        nom = re.match(r"[\w.-]*", texte[m.end():]).group()
        yield m.end(), m.end() + len(nom), nom
    for m in DEBUT_COMPTE_WINDOWS.finditer(texte):
        reste = texte[m.end():]
        fin = next((i for i, c in enumerate(reste) if c in FIN_COMPTE_WINDOWS), len(reste))
        # Un nom peut avoir des espaces ou une apostrophe (« Jean Dupont », « Zoé d'Alice ») : gardées seulement si le
        # chemin continue après ; sinon l'apostrophe peut fermer une chaîne (« 'C:\\Users\\bob' »).
        nom = reste[:fin] if reste[fin:fin + 1] in ("\\", "/") else re.split(r"[ ']", reste[:fin])[0]
        nom = nom.rstrip(" .")
        yield m.end(), m.end() + len(nom), nom


def compte_de_personne(nom, inventes=True):
    """Un compte qui nomme peut-être quelqu'un : ni dossier commun, ni variable (« %USERNAME% »), ni, avec `inventes`,
    compte inventé des tests."""
    bas = nom.lower()
    return (any(c.isalnum() for c in nom) and not any(c in nom for c in "%${<~") and bas not in COMPTES_COMMUNS
            and not (inventes and bas in COMPTES_INVENTES))


def courriel_de_personne(adresse):
    locale, _, domaine = adresse.rpartition("@")
    return not (DOMAINES_EXEMPLES.search(domaine) or locale.lower() in ROLES or adresse.lower() in COURRIELS_PUBLICS
                or ALGORITHME_SSH.fullmatch(adresse.lower().lstrip("+-^")))


def donnees_d_autrui(texte, courriels=True):
    """(terme, position) de ce qui pourrait être la donnée de quelqu'un d'autre : compte d'un dossier personnel,
    courriel, SID de Windows. Pas les adresses MAC et IP, ni les noms d'appareils ou de Wi-Fi : les tests en inventent
    (préfixe d'un vrai fabricant, réseau « Salon »), rien ne les distinguerait des vrais."""
    for debut, _, nom in comptes(texte):
        if compte_de_personne(nom):
            yield Terme(nom, "compte d'un dossier personnel (de quelqu'un ?)", ""), debut
    for m in COURRIEL.finditer(texte) if courriels else ():
        if courriel_de_personne(m.group()):
            yield Terme(m.group(), "courriel (de quelqu'un ?)", ""), m.start()
    for m in SID.finditer(texte):
        if m.groups() != SID_EXEMPLE and any(len(g) >= 5 for g in m.groups()):
            yield Terme(m.group(), "SID d'un compte Windows", ""), m.start()


def masquer_autrui(texte, masque):
    """Masque ce qui pourrait nommer quelqu'un dans un texte qui part sur GitHub (ticket du journal) : comptes des
    dossiers personnels, courriels, SID, numéros de série, noms du réseau local et du Wi-Fi ; adresses MAC et IP par
    `masque` (préfixe du fabricant gardé, réseau inventé). Second filet : Vanguard anonymise déjà le journal en
    l'écrivant (src/journal.rs)."""
    morceaux, fin = [], 0
    for debut, fin_du_nom, nom in sorted(comptes(texte)):
        if debut >= fin and compte_de_personne(nom, inventes=False):
            morceaux += [texte[fin:debut], "<compte>"]
            fin = fin_du_nom
    texte = COURRIEL.sub("<courriel>", "".join(morceaux) + texte[fin:])
    texte = SID.sub("S-1-5-21-0-0-0", texte)
    lignes = []
    for ligne in texte.splitlines(keepends=True):
        ligne = SERIE.sub(lambda m: m.group(1) + m.group(2) + "<numéro>", ligne)
        ligne = WIFI_CLE.sub(lambda m: m.group(1) + m.group(2) + "<wifi>", ligne)
        if LIGNE_WIFI.search(ligne):
            ligne = re.sub(r"« [^»\n]*? »", "« <wifi> »", ligne)
            ligne = re.sub(r"“[^”\n]*”", "“<wifi>”", ligne)
        lignes.append(ligne)
    return masque.texte(NOM_LOCAL.sub("<appareil>", "".join(lignes)))


# --- Où chercher -----------------------------------------------------------------------------------------------------

# Diff lu ligne à ligne : préfixes « a/ » et « b/ » imposés (diff.mnemonicPrefix ou diff.noPrefix les changent).
DIFF = ("-U0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/")


def git(*args):
    r = subprocess.run(["git", "-c", "core.quotePath=false", *args], capture_output=True, text=True, errors="replace")
    if r.returncode:
        raise SystemExit(f"confidentialité : git {' '.join(args)} a échoué : {r.stderr.strip()}")
    return r.stdout


def lignes_ajoutees(diff: str):
    """(fichier, numéro de ligne, texte) de chaque ligne ajoutée d'un diff -U0, et une entrée par fichier pour son nom."""
    fichier, numero, entete = None, 0, False
    for ligne in diff.splitlines():
        # « +++ » n'est un en-tête qu'avant le premier « @@ » du fichier : plus loin, c'est une ligne ajoutée qui
        # commence par « ++ ».
        if ligne.startswith("diff "):
            entete = True
        elif entete and ligne.startswith("+++ "):
            fichier = ligne[6:].rstrip("\t") if ligne.startswith("+++ b/") else None
            if fichier:
                yield fichier, 0, fichier
        elif ligne.startswith("@@"):
            entete = False
            m = re.search(r"\+(\d+)", ligne)
            numero = int(m.group(1)) if m else 0
        elif not entete and ligne.startswith("+") and fichier:
            yield fichier, numero, ligne[1:]
            numero += 1


def chercher_diff(detecteur, diff, prefixe=""):
    return [(f"{prefixe}{fichier}" + (f":{numero}" if numero else " (nom du fichier)"), terme)
            for fichier, numero, texte in lignes_ajoutees(diff)
            for terme, _ in detecteur.trouver(texte, False if fichier in TIERS else None)]


def identite(detecteur, texte, ou):
    return [(ou, terme) for terme, _ in detecteur.trouver(texte)]


def commit_en_cours(detecteur):
    trouves = []
    for variable, role in (("GIT_AUTHOR_IDENT", "auteur"), ("GIT_COMMITTER_IDENT", "committeur")):
        # « Nom <courriel> horodatage fuseau »
        trouves += identite(detecteur, git("var", variable).rsplit(" ", 2)[0], f"{role} du commit")
    diff = git("diff", "--cached", *DIFF, "--diff-filter=ACMR")
    return trouves + chercher_diff(detecteur, diff)


def message(detecteur, chemin):
    texte = Path(chemin).read_text(errors="replace").split("# ------------------------ >8 ------------------------")[0]
    texte = "\n".join(l for l in texte.splitlines() if not l.startswith("#"))
    return [(f"message du commit, ligne {n}", terme) for terme, n in detecteur.trouver(texte)]


def commits_a_envoyer(detecteur):
    return verifier_commits(detecteur, git("rev-list", "--reverse", "HEAD", "--not", "--remotes=origin").split())


def commits_de_la_plage(avant, apres):
    """Les commits d'un envoi : de `avant` (exclu, le commit d'avant sur GitHub) à `apres`. Branche neuve (`avant` vide
    ou fait de zéros) ou historique réécrit (`avant` disparu) : ceux qu'aucune autre branche de GitHub n'a déjà."""
    connu = avant.strip("0") and subprocess.run(["git", "cat-file", "-e", f"{avant}^{{commit}}"],
                                                capture_output=True).returncode == 0
    if connu:
        return git("rev-list", "--reverse", f"{avant}..{apres}").split()
    autres = [r for r in git("for-each-ref", "--format=%(refname)", "refs/remotes/origin").split()
              if r != "refs/remotes/origin/HEAD" and git("rev-parse", r).strip() != git("rev-parse", apres).strip()]
    return git("rev-list", "--reverse", apres, "--not", *autres).split()


def verifier_commits(detecteur, shas):
    trouves = []
    for sha in shas:
        court = sha[:9]
        entete = git("show", "-s", "--format=%an <%ae>%n%cn <%ce>%n%B", sha)
        auteurs, _, corps = entete.partition("\n")
        committeur, _, corps = corps.partition("\n")
        trouves += identite(detecteur, auteurs, f"{court} auteur")
        trouves += identite(detecteur, committeur, f"{court} committeur")
        trouves += [(f"{court} message, ligne {n}", t) for t, n in detecteur.trouver(corps)]
        diff = git("diff-tree", "-p", *DIFF, "--no-commit-id", "--root", "-r", "-m", "--first-parent", sha)
        trouves += chercher_diff(detecteur, diff, f"{court} ")
    return trouves


def depot_entier(detecteur):
    """Fichiers suivis, puis tout l'historique : contenus de toutes les versions de chaque fichier, messages, auteurs."""
    trouves = []
    for chemin in git("ls-files", "-z").split("\0"):
        if not chemin or not Path(chemin).is_file():
            continue
        brut = Path(chemin).read_bytes()
        if b"\0" in brut[:8000]:
            continue
        tiers = False if chemin in TIERS else None
        trouves += [(f"{chemin}:{n}", t) for t, n in detecteur.trouver(brut.decode(errors="replace"), tiers)]
        trouves += [(f"{chemin} (nom du fichier)", t) for t, _ in detecteur.trouver(chemin)]
    vus = set()
    for ligne in git("log", "--all", "--format=%h%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e").split("\x1e"):
        if not ligne.strip():
            continue
        court, auteur, committeur, corps = ligne.strip("\n").split("\x1f", 3)
        for texte, quoi in ((auteur, "auteur"), (committeur, "committeur"), (corps, "message")):
            for terme, _ in detecteur.trouver(texte):
                vus.add((f"historique : {quoi} de commit", terme))
    objets = {}
    for ligne in git("rev-list", "--objects", "--all").splitlines():
        sha, _, chemin = ligne.partition(" ")
        if chemin:
            objets.setdefault(sha, chemin)
    lot = subprocess.run(["git", "cat-file", "--batch"], input="".join(f"{s}\n" for s in objets).encode(),
                         capture_output=True, check=True).stdout
    position = 0
    while position < len(lot):
        fin = lot.index(b"\n", position)
        entete = lot[position:fin].decode().split()
        if len(entete) != 3:  # « <sha> missing »
            position = fin + 1
            continue
        sha, genre, taille = entete
        contenu = lot[fin + 1 : fin + 1 + int(taille)]
        position = fin + 2 + int(taille)
        if genre == "blob" and b"\0" not in contenu[:8000]:
            tiers = False if objets[sha] in TIERS or objets[sha].rsplit("/", 1)[-1] in TIERS else None
            for terme, _ in detecteur.trouver(contenu.decode(errors="replace"), tiers):
                vus.add((f"historique : {objets[sha]}", terme))
        for terme, _ in detecteur.trouver(objets.get(sha, "")):
            vus.add((f"historique : {objets[sha]} (nom du fichier)", terme))
    return trouves + sorted(vus, key=lambda v: (v[0], v[1].texte))


def chaines(chemin):
    """Textes lisibles d'un programme compilé : ASCII et UTF-8, puis UTF-16 (métadonnées d'un .exe)."""
    brut = Path(chemin).read_bytes()
    textes = [s.decode(errors="replace") for s in re.findall(rb"[\t\x20-\x7e\x80-\xff]{4,}", brut)]
    textes += [s.decode("utf-16-le") for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", brut)]
    return "\n".join(textes)


def rapport(trouves, quoi, en_clair=True) -> int:
    """Dit ce qui a été trouvé et où. Sans `en_clair` (CI : son journal est lisible sur GitHub, même après que
    l'historique a été réécrit), seulement le début de chaque valeur."""
    if not trouves:
        return 0
    print(f"Confidentialité : {len(trouves)} détail(s) personnel(s) dans {quoi}.", file=sys.stderr)
    fois = {}
    for trouve in trouves:
        fois[trouve] = fois.get(trouve, 0) + 1
    for (ou, terme), n in fois.items():
        valeur = terme.texte if en_clair else f"{terme.texte[:2]}… ({len(terme.texte)} caractères)"
        print(f"  {ou} — {terme.origine} : {valeur}" + (f" ({n} fois)" if n > 1 else ""), file=sys.stderr)
    if not en_clair:
        print("Valeurs coupées : le journal de la CI se lit sur GitHub. En entier, sur l'ordinateur de développement : "
              "python3 outils/confidentialite.py --generique --plage AVANT APRÈS.", file=sys.stderr)
    print("Remplace-les par des valeurs inventées (adresses MAC : garder les 3 premiers octets, ceux du fabricant). "
          f"Une expression de {PRIVE} qui n'a rien de personnel s'y retire.", file=sys.stderr)
    # Trouvé par sa forme (donnees_d_autrui), pas dans une liste : la donnée de quelqu'un, ou une valeur à ajouter
    # aux valeurs inventées permises.
    if any(not terme.motif for _, terme in fois):
        print("Donnée de quelqu'un d'autre ? Dans un test : comptes alice, bob, Zoé, Jean Dupont ; courriels "
              "@example.com ; SID d'exemple S-1-5-21-1004336348-1177238915-682003330-… (COMPTES_INVENTES, "
              "COURRIELS_PUBLICS de outils/confidentialite.py pour une valeur publique).", file=sys.stderr)
    return 1


def main():
    args = sys.argv[1:]
    if args[:1] in (["--message"], ["--binaire"]):
        args[1:] = [os.path.abspath(a) for a in args[1:]]
    os.chdir(git("rev-parse", "--show-toplevel").strip())
    generique = "--generique" in args
    if generique:
        args.remove("--generique")
    # Générique : sans la liste des détails de cet ordinateur (identité Git, compte, nom, appareils, Wi-Fi).
    detecteur = Detecteur([] if generique else termes(), autrui=True)
    if args[:1] == ["--commit"]:
        sys.exit(rapport(commit_en_cours(detecteur), "ce commit (rien n'est commité)"))
    if args[:1] == ["--message"] and len(args) == 2:
        sys.exit(rapport(message(detecteur, args[1]), "le message du commit (rien n'est commité)"))
    if args[:1] == ["--envoi"]:
        sys.exit(rapport(commits_a_envoyer(detecteur), "les commits à envoyer"))
    if args[:1] == ["--plage"] and len(args) == 3:
        shas = commits_de_la_plage(args[1], args[2])
        print(f"Confidentialité : {len(shas)} commit(s) relu(s).", file=sys.stderr)
        sys.exit(rapport(verifier_commits(detecteur, shas), "les commits envoyés", en_clair=not os.environ.get("CI")))
    if args[:1] == ["--texte"]:
        texte = sys.stdin.read()
        sys.exit(rapport([(f"ligne {n}", t) for t, n in detecteur.trouver(texte)], "le texte"))
    if args[:1] == ["--binaire"] and len(args) > 1:
        # Un programme range ses textes bout à bout, sans séparateur : une forme (dossier, courriel) s'y colle au
        # texte suivant et ne se juge plus. Seuls les détails connus d'ici sont cherchés ; les données des autres
        # l'ont été dans le code, à chaque commit.
        trouves = [(Path(f).name, t) for f in args[1:] for t, _ in detecteur.trouver(chaines(f), False)]
        sys.exit(rapport(trouves, "les programmes compilés"))
    if args[:1] == ["--depot"]:
        sys.exit(rapport(depot_entier(detecteur), "le dépôt et son historique"))
    raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
