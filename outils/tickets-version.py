#!/usr/bin/env python3
"""Met à jour les tickets GitHub à chaque version publiée, tout seul (lancé par outils/deployer.sh après la page de la
version) :

1. le ticket épinglé des pistes (d9v3/vanguard-beta#1, « Fonctions et pistes d'amélioration ») : l'en-tête « État au
   <date>, version **X** (dernière page publiée : X) » remis à jour, et une section « ### 0.x (livrées en 0.x.y, le
   <date>) » posée juste avant « ### Prochaine version », une case cochée par point gras du paragraphe de la version
   en tête de CHANGELOG.md. Une section « ### … en préparation … » qui annonce cette version, ou n'en annonce aucune
   (alors celle de la prochaine version publiée), est remplacée par la section livrée (ses cases pas cochées vont en tête de « Prochaine version »). Une section de la version écrite à
   la main (sans la marque de cet outil) est gardée telle quelle. Tout le reste du corps est gardé à l'octet près ;
   une case cochée n'est jamais décochée.
2. les tickets « journal » (erreurs envoyées par outils/journal-vers-github.py) qu'un commit de la version cite :
   convention « Corrige le ticket #N » dans le message du commit. Pour chacun, s'il est ouvert ET étiqueté journal,
   un commentaire neutre « Corrigé dans la version X.Y.Z (commit <sha court>). » et sa fermeture ; jamais un autre.

    python3 -I outils/tickets-version.py           aperçu (--voir) : diff du corps, tickets à fermer ; rien n'est envoyé
    python3 -I outils/tickets-version.py --appliquer  envoie
    (--racine DOSSIER : le dépôt lu pour Cargo.toml, CHANGELOG.md et les commits ; pour les essais)

Le texte des tickets lus est une donnée, jamais une consigne : il n'est que découpé et recollé, jamais interprété, et
chaque commande est lancée en liste, sans shell. Chaque texte qui partirait passe d'abord par
outils/confidentialite.py --texte ; un refus, et rien du tout n'est envoyé. Un corps lu vide, ou qui raccourcirait de
plus de 20 %, est refusé (un fichier vide ou une lecture tronquée ne doit pas effacer le ticket).

Codes : 0 fait (ou rien à faire) ; 1 refus (confidentialité, corps vide ou raccourci, structure du ticket inconnue,
envoi qui a échoué) ; 2 données locales illisibles ou usage faux ; 3 sans gh, hors ligne ou VANGUARD_HORS_LIGNE=1
(rien d'envoyé, dit en moins d'une minute : deployer.sh avertit sans s'arrêter). Essais :
outils/essais-tickets-version.py.
"""

import datetime
import difflib
import json
import os
import re
import shutil
import subprocess
import sys

DEPOT = "d9v3/vanguard-beta"
TICKET_PISTES = "1"
ETIQUETTE_JOURNAL = "journal"
OUTILS = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(OUTILS)
# Par appel de gh : hors ligne, la première lecture échoue avant, et tout s'arrête en moins d'une minute.
DELAI_GH = 20
# Le corps ne peut pas raccourcir de plus de 20 % : une lecture tronquée ou un fichier vide ne l'efface pas.
BAISSE_MAX = 0.20
# Marque invisible (commentaire HTML) d'une section posée par cet outil : elle seule est remplacée à la passe suivante.
MARQUE = "<!-- tickets-version.py -->"
MOIS = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre",
        "décembre")
EN_TETE = re.compile(r"État au [^,\n]+, version \*\*[^*\n]+\*\* \(dernière page publiée : [^)\n]+\)")
# « #12 » cité dans un message, mais pas « vanguard-beta#1 » (un autre dépôt), « C#7 », « ##3 » ni « &#64; » (une
# entité HTML, vue dans un vrai commit).
CITATION = re.compile(r"(?<![\w/#&-])#(\d{1,7})\b")
# Ce que gh dit quand le réseau manque (ou délai dépassé, code 124) : hors ligne, code 3.
RESEAU = re.compile(r"(?i)dial tcp|lookup |no such host|network|unreachable|connect|resolve|timeout|délai")


class Refus(Exception):
    """Rien n'est envoyé ; la raison est dite."""

    def __init__(self, raison, code=1):
        super().__init__(raison)
        self.code = code


def gh_reel(args, entree=None):
    """gh, en liste (jamais de shell), borné ; trop long, c'est un échec (code 124), pas une exception."""
    try:
        return subprocess.run(["gh", *args], input=entree, capture_output=True, text=True, timeout=DELAI_GH)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "délai dépassé")
    except OSError as e:
        return subprocess.CompletedProcess(args, 127, "", str(e))


def confidentialite_reelle(texte):
    """outils/confidentialite.py --texte, en Python isolé (-I) : (permis, ce qu'il a dit)."""
    try:
        r = subprocess.run([sys.executable, "-I", os.path.join(OUTILS, "confidentialite.py"), "--texte"],
                           input=texte, capture_output=True, text=True, cwd=RACINE, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"garde de confidentialité pas lancée : {e}"
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def date_fr(jour, annee=True):
    d = "1er" if jour.day == 1 else str(jour.day)
    return f"{d} {MOIS[jour.month - 1]}" + (f" {jour.year}" if annee else "")


def version_cargo(racine):
    try:
        with open(os.path.join(racine, "Cargo.toml"), encoding="utf-8") as f:
            m = re.search(r'(?m)^version = "(\d+\.\d+\.\d+)"', f.read())
    except OSError as e:
        raise Refus(f"Cargo.toml illisible : {e}", 2) from e
    if not m:
        raise Refus("version introuvable dans Cargo.toml", 2)
    return m.group(1)


def libelle(version):
    """« 0.95 » pour 0.95.0, « 0.94.1 » pour un correctif : comme les sections existantes."""
    a, b, c = version.split(".")
    return f"{a}.{b}" if c == "0" else version


def paragraphe_changelog(texte, version):
    """Le paragraphe en tête de CHANGELOG.md : (date « 12 novembre », titres des points gras)."""
    morceaux = re.split(r"(?m)^## ", texte, maxsplit=2)
    if len(morceaux) < 2:
        raise Refus("CHANGELOG.md : aucun paragraphe « ## »", 2)
    titre, _, corps = morceaux[1].partition("\n")
    noms = {version} | ({libelle(version)} if version.endswith(".0") else set())
    trouves = set(re.findall(r"\b\d+\.\d+(?:\.\d+)?\b", titre))
    if not noms & trouves:
        raise Refus(f"le paragraphe en tête de CHANGELOG.md (« {titre.strip()} ») ne nomme pas la version {version}", 2)
    m = re.match(r"(\d{1,2}(?:er)?) (\w+) \d{4}", titre)
    if not m or m.group(2) not in MOIS:
        raise Refus(f"date illisible dans « {titre.strip()} »", 2)
    # Un point peut tenir sur plusieurs lignes : recollé avant de lire son titre gras.
    points, courant = [], None
    for ligne in corps.split("\n"):
        if ligne.startswith("- "):
            courant = [ligne]
            points.append(courant)
        elif courant is not None and ligne.startswith("  "):
            courant.append(ligne.strip())
        else:
            courant = None
    titres = []
    for p in points:
        g = re.match(r"- \*\*(.+?)\*\*", " ".join(p))
        if g:
            t = g.group(1).strip().rstrip(" .:")
            if t and t not in titres:
                titres.append(t)
    if not titres:
        raise Refus("aucun point gras dans le paragraphe en tête de CHANGELOG.md", 2)
    return f"{m.group(1)} {m.group(2)}", titres


def _sections(lignes):
    """Débuts et fins des sections « ### » (jusqu'au titre suivant, « ## » ou « ### »)."""
    debuts = [i for i, l in enumerate(lignes) if l.startswith("### ")]
    bornes = [i for i, l in enumerate(lignes) if l.startswith("## ") or l.startswith("### ")] + [len(lignes)]
    return [(d, min(b for b in bornes if b > d)) for d in debuts]


def _version_annoncee(titre):
    m = re.search(r"\b\d+\.\d+(?:\.\d+)?\b", titre)
    return m.group(0) if m else None


def mettre_a_jour(corps, version, aujourdhui, date_version, titres):
    """Le nouveau corps du ticket des pistes, et ce qui a été fait (lignes dites). Fonction pure."""
    fin = "\r\n" if "\r\n" in corps else "\n"
    notes = []
    trouves = EN_TETE.findall(corps)
    if len(trouves) != 1:
        raise Refus(f"en-tête « État au …, version **…** (dernière page publiée : …) » trouvé {len(trouves)} fois")
    nouvel_en_tete = f"État au {date_fr(aujourdhui)}, version **{version}** (dernière page publiée : {version})"
    corps = EN_TETE.sub(lambda _: nouvel_en_tete, corps, count=1)

    lignes = corps.splitlines(keepends=True)
    nom = libelle(version)
    titre_livre = f"### {nom} (livrées en {version}"
    prochaine = auto = None
    a_la_main = None
    preparation = []
    # « En préparation » sans numéro : celle de la prochaine version publiée, donc de celle-ci, tant que sa section
    # livrée n'est pas encore posée. Après (passe répétée), elle a été réécrite à la main pour la suivante : gardée.
    sans_numero = []
    for d, f in _sections(lignes):
        t = lignes[d].rstrip("\r\n")
        if t.strip() == "### Prochaine version":
            prochaine = (d, f)
        elif t.startswith(titre_livre):
            if d + 1 < f and lignes[d + 1].strip() == MARQUE:
                auto = (d, f)
            else:
                a_la_main = (d, f)
        elif "en préparation" in t.lower() and _version_annoncee(t) in (version, nom):
            preparation.append((d, f))
        elif "en préparation" in t.lower() and _version_annoncee(t) is None:
            sans_numero.append((d, f))
    if auto is None:
        preparation = sorted(preparation + sans_numero)
    if a_la_main:
        notes.append(f"section {nom} écrite à la main : gardée telle quelle")
        return corps, notes
    if prochaine is None:
        raise Refus("section « ### Prochaine version » introuvable : rien n'est posé")

    # Un point déjà coché ailleurs (version du même jour, déjà dans le ticket) n'est pas répété.
    ailleurs = "".join(l for i, l in enumerate(lignes)
                       if not any(d <= i < f for d, f in [*preparation, *([auto] if auto else [])]))
    neufs = [t for t in titres if f"- [x] {t} (" not in ailleurs]
    bloc = [f"{titre_livre}, le {date_version}){fin}", f"{MARQUE}{fin}"]
    bloc += [f"- [x] {t} ({version}).{fin}" for t in neufs]
    bloc.append(fin)

    # Les cases pas cochées d'une section en préparation ne sont pas livrées : elles passent à la prochaine version.
    reportees = []
    for d, f in preparation:
        for l in lignes[d + 1:f]:
            if l.startswith("- [ ] "):
                reportees.append(l if l.endswith("\n") else l + fin)
    if reportees:
        notes.append(f"{len(reportees)} case(s) pas cochée(s) de « en préparation » reportée(s) à « Prochaine version »")

    retirees = sorted([*preparation, *([auto] if auto else [])])
    place = retirees[0][0] if retirees else prochaine[0]
    sortie = []
    for i, l in enumerate(lignes):
        if i == place:
            sortie += bloc
        if any(d <= i < f for d, f in retirees):
            continue
        sortie.append(l)
        if i == prochaine[0]:
            sortie += reportees
    nouveau = "".join(sortie)
    if preparation:
        notes.append(f"section « en préparation » de la {nom} remplacée par la section livrée")
    notes.append(f"section {nom} : {len(neufs)} case(s) cochée(s)" + (" (remplacée)" if auto else " (ajoutée)"))
    garder_les_cases(corps, nouveau, retirees, lignes)
    return nouveau, notes


def garder_les_cases(avant, apres, retirees, lignes):
    """Second filet : aucune case cochée hors des sections remplacées ne disparaît ni ne se décoche."""
    restantes = set(apres.splitlines())
    for i, l in enumerate(lignes):
        if any(d <= i < f for d, f in retirees):
            continue
        l = l.rstrip("\r\n")
        if l.lstrip().startswith("- [x]") and l not in restantes:
            raise Refus(f"une case cochée disparaîtrait : « {l[:80]} »")
    for l in avant.splitlines():
        s = l.lstrip()
        if s.startswith("- [x] ") and s.replace("- [x] ", "- [ ] ", 1) in {x.lstrip() for x in restantes} and \
                l not in restantes:
            raise Refus(f"une case cochée serait décochée : « {l[:80]} »")


def verifier_taille(avant, apres):
    if not avant.strip():
        raise Refus("ticket des pistes lu vide : rien n'est envoyé")
    if not apres.strip():
        raise Refus("nouveau corps vide : rien n'est envoyé")
    if len(apres) < (1 - BAISSE_MAX) * len(avant):
        raise Refus(f"le corps raccourcirait de plus de {int(BAISSE_MAX * 100)} % "
                    f"({len(avant)} → {len(apres)} caractères) : rien n'est envoyé")


def git(racine, *args):
    r = subprocess.run(["git", "-C", racine, *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise Refus(f"git {' '.join(args[:2])} a échoué : {r.stderr.strip()}", 2)
    return r.stdout


def recuperer_etiquette(racine, etiquette):
    """Prend cette seule étiquette à origin, sans en déplacer une d'ici (pas de « + ») ; rend la raison d'un échec."""
    ref = f"refs/tags/{etiquette}"
    try:
        r = subprocess.run(["git", "-C", racine, "fetch", "-q", "--no-tags", "--no-write-fetch-head", "origin",
                            f"{ref}:{ref}"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return "origin ne répond pas"
    return "pas sur origin" if r.returncode == 0 else f"git fetch : {r.stderr.strip()[:200]}"


def citations(racine, version):
    """{numéro: sha court} des tickets cités par les commits de la version (étiquette précédente exclue)."""
    def cle(e):
        return tuple(int(x) for x in e[1:].split("."))

    def lues():
        return [e for e in git(racine, "tag", "-l", "v*").split() if re.fullmatch(r"v\d+\.\d+\.\d+", e)]

    cible = f"v{version}"
    etiquettes = lues()
    if cible not in etiquettes:
        # La page de la version crée l'étiquette sur GitHub : elle n'est pas encore ici.
        pourquoi = recuperer_etiquette(racine, cible)
        etiquettes = lues()
        if cible not in etiquettes:
            raise Refus(f"étiquette {cible} absente : commits de la version pas lus ({pourquoi})", 2)
    avant = [e for e in etiquettes if cle(e) < cle(cible)]
    plage = f"{max(avant, key=cle)}..{cible}" if avant else cible
    sortie = git(racine, "log", "--no-show-signature", "--no-color", "--format=%h%x00%B%x1e", plage)
    cites = {}
    for bloc in sortie.split("\x1e"):
        sha, _, message = bloc.strip("\n").partition("\x00")
        for n in CITATION.findall(message):
            cites.setdefault(n, sha)  # le plus récent d'abord : c'est lui que la version porte
    return plage, cites


def lire_ticket(gh, numero, champs):
    r = gh(["issue", "view", numero, "-R", DEPOT, "--json", champs])
    if r.returncode != 0:
        return None, r
    try:
        return json.loads(r.stdout), r
    except ValueError:
        return None, r


def executer(argv, gh=gh_reel, verifier=confidentialite_reelle, aujourdhui=None, sortie=print):
    appliquer = "--appliquer" in argv
    racine = RACINE
    reste = list(argv)
    if "--racine" in reste:
        i = reste.index("--racine")
        if i + 1 >= len(reste):
            sortie("usage : --racine DOSSIER")
            return 2
        racine = reste.pop(i + 1)
        reste.pop(i)
    inconnus = [a for a in reste if a not in ("--voir", "--appliquer")]
    if inconnus or ("--voir" in reste and appliquer):
        sortie(f"usage : outils/tickets-version.py [--voir | --appliquer] (pas compris : {' '.join(inconnus)})")
        return 2
    aujourdhui = aujourdhui or datetime.date.today()

    if os.environ.get("VANGUARD_HORS_LIGNE") == "1":
        sortie("Tickets : hors ligne (VANGUARD_HORS_LIGNE=1) : rien n'est lu ni envoyé.")
        return 3
    if gh is gh_reel and shutil.which("gh") is None:
        sortie("Tickets : gh absent : rien n'est lu ni envoyé (pacman -S github-cli, puis gh auth login).")
        return 3

    try:
        version = version_cargo(racine)
        try:
            with open(os.path.join(racine, "CHANGELOG.md"), encoding="utf-8") as f:
                date_version, titres = paragraphe_changelog(f.read(), version)
        except OSError as e:
            raise Refus(f"CHANGELOG.md illisible : {e}", 2) from e

        donnees, r = lire_ticket(gh, TICKET_PISTES, "body")
        if donnees is None:
            message = (r.stderr or r.stdout).strip()
            if r.returncode in (124, 127) or RESEAU.search(message):
                sortie(f"Tickets : GitHub injoignable (hors ligne ?) : rien n'est envoyé. gh : {message[:200]}")
                return 3
            raise Refus(f"ticket {DEPOT}#{TICKET_PISTES} illisible : {message[:200]}")
        avant = donnees.get("body") or ""
        verifier_taille(avant, avant or "x")
        apres, notes = mettre_a_jour(avant, version, aujourdhui, date_version, titres)
        verifier_taille(avant, apres)

        code_git = 0
        try:
            plage, cites = citations(racine, version)
        except Refus as e:
            sortie(f"Tickets du journal pas regardés : {e}")
            plage, cites, code_git = "", {}, e.code
        a_fermer, ecartes = [], []
        for n, sha in sorted(cites.items(), key=lambda x: int(x[0])):
            d, _ = lire_ticket(gh, n, "number,state,labels")
            if d is None:
                ecartes.append(f"#{n} (illisible ou absent)")
                continue
            etiquettes = {e.get("name") for e in d.get("labels") or []}
            if d.get("state") == "OPEN" and ETIQUETTE_JOURNAL in etiquettes and str(d.get("number")) == n:
                a_fermer.append((n, f"Corrigé dans la version {version} (commit {sha})."))
            else:
                ecartes.append(f"#{n} ({'pas « journal »' if ETIQUETTE_JOURNAL not in etiquettes else 'déjà fermé'})")

        # Chaque texte qui partirait passe la garde, AVANT le premier envoi : un refus, et rien ne part.
        textes = ([("ticket des pistes", apres)] if apres != avant else []) + [(f"#{n}", t) for n, t in a_fermer]
        for quoi, texte in textes:
            permis, dit = verifier(texte)
            if not permis:
                raise Refus(f"confidentialité : {quoi} refusé, rien n'est envoyé.\n{dit}")
    except Refus as e:
        sortie(f"Tickets : refus : {e}")
        return e.code

    sortie(f"Tickets de la version {version} ({'envoi' if appliquer else 'aperçu, rien n’est envoyé'}) :")
    for n in notes:
        sortie(f"  - {n}")
    if apres == avant:
        sortie(f"  {DEPOT}#{TICKET_PISTES} : déjà à jour.")
    else:
        sortie(f"  {DEPOT}#{TICKET_PISTES} : changements du corps :")
        for l in difflib.unified_diff(avant.splitlines(), apres.splitlines(), "avant", "après", n=1, lineterm=""):
            sortie("    " + l[:200])
    sortie(f"  Commits lus : {plage or '—'} ; tickets du journal à fermer : "
           + (", ".join(f"#{n}" for n, _ in a_fermer) or "aucun"))
    if ecartes:
        sortie("  Cités mais laissés : " + ", ".join(ecartes))
    if not appliquer:
        return code_git

    code = code_git
    if apres != avant:
        r = gh(["issue", "edit", TICKET_PISTES, "-R", DEPOT, "--body-file", "-"], apres)
        relu, _ = lire_ticket(gh, TICKET_PISTES, "body")
        if r.returncode != 0 or relu is None or (relu.get("body") or "").replace("\r\n", "\n") != \
                apres.replace("\r\n", "\n"):
            sortie(f"  ✖ ticket des pistes pas mis à jour (ou relu différent) : {(r.stderr or '').strip()[:200]}")
            code = 1
        else:
            sortie("  ✔ ticket des pistes mis à jour.")
    for n, texte in a_fermer:
        r = gh(["issue", "close", n, "-R", DEPOT, "--comment", texte])
        if r.returncode != 0:
            sortie(f"  ✖ #{n} pas fermé : {(r.stderr or '').strip()[:200]}")
            code = 1
        else:
            sortie(f"  ✔ #{n} commenté et fermé.")
    return code


if __name__ == "__main__":
    sys.exit(executer(sys.argv[1:]))
