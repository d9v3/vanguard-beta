#!/usr/bin/env python3
"""Essais de outils/tickets-version.py, sans GitHub : gh simulé (une fonction injectée, ou un faux programme mis en tête
du PATH), un dépôt git jetable aux valeurs inventées (compte « alice », adresse d'exemple). Rien ne part sur GitHub.

    python3 -I outils/essais-tickets-version.py

Ce qui est essayé : idempotence (deux passes, même corps), section posée juste avant « Prochaine version », reste du
corps intact, case cochée à la main gardée, « en préparation » remplacée (ses cases pas cochées reportées), section
écrite à la main gardée, ticket pas « journal » (ou fermé) jamais fermé, citations d'un autre dépôt ou d'une entité HTML
ignorées, confidentialité refusée (fonction et vraie garde) → rien d'envoyé, corps vide ou raccourci → refus, hors
ligne (VANGUARD_HORS_LIGNE=1, gh absent, gh sans réseau) → code 3 en moins d'une minute.
"""

import datetime
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

OUTILS = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(OUTILS, "tickets-version.py")
_spec = importlib.util.spec_from_file_location("tickets_version", SCRIPT)
tv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tv)

JOUR = datetime.date(2026, 11, 20)
TITRES = ["Premier point livré", "« Deuxième » point, avec virgule"]
CORPS = """État au 1er novembre 2026, version **0.1.0** (dernière page publiée : 0.1.0). Liste de suivi.

## Ce que fait l'outil
- [x] Lit le réseau « Salon ».
- [x] Coché à la main avant tout.

## À améliorer

### 0.1 (livrées en 0.1.0, le 1er novembre)
- [x] Ancien point (0.1.0).

### Prochaine version
- [ ] Point futur.
- [x] Coché à la main dans la prochaine version.

### Ensuite
- [ ] Plus tard, sans date.

## Limites assumées
Texte libre qui doit rester à l'octet près : `#12`, **gras**, <!-- commentaire -->.
"""
PREPARATION = """### 0.2 (en préparation : branche du jour)
- [x] Premier point livré
- [ ] Pas encore fait, reporté.

"""
CHANGELOG = """# Historique

## 20 novembre 2026 : version 0.2.0

- **Premier point livré.** Le détail suit, sur
  plusieurs lignes.
- **« Deuxième » point,
  avec virgule.** Détail.
- Un point sans gras, ignoré.

## 1er novembre 2026 : version 0.1.0

- **Ancien point.** Détail.
"""


def permis(_texte):
    return True, ""


def refuse(_texte):
    return False, "détail personnel (simulé)"


class FauxGh:
    """gh simulé : tickets en mémoire, chaque appel noté."""

    def __init__(self, corps=CORPS, tickets=None):
        self.tickets = {"1": {"number": 1, "state": "OPEN", "labels": [], "body": corps}}
        self.tickets.update(tickets or {})
        self.appels = []

    def __call__(self, args, entree=None):
        self.appels.append(list(args))
        verbe, numero = args[1], args[2]
        assert args[3:5] == ["-R", tv.DEPOT], args
        t = self.tickets.get(numero)
        if t is None:
            return subprocess.CompletedProcess(args, 1, "", "Could not resolve to an issue")
        if verbe == "view":
            champs = args[args.index("--json") + 1].split(",")
            return subprocess.CompletedProcess(args, 0, json.dumps({c: t.get(c) for c in champs}), "")
        if verbe == "edit":
            t["body"] = entree
        elif verbe == "close":
            t["state"] = "CLOSED"
            t.setdefault("commentaires", []).append(args[args.index("--comment") + 1])
        return subprocess.CompletedProcess(args, 0, "", "")

    def envois(self):
        return [a for a in self.appels if a[1] != "view"]


def depot_jetable(dossier, changelog=CHANGELOG, version="0.2.0"):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "alice", "GIT_AUTHOR_EMAIL": "alice@example.com",
           "GIT_COMMITTER_NAME": "alice", "GIT_COMMITTER_EMAIL": "alice@example.com"}

    def git(*a):
        subprocess.run(["git", "-C", dossier, *a], check=True, capture_output=True, env=env)

    git("init", "-q")
    git("commit", "-q", "--allow-empty", "-m", "Départ")
    git("tag", "v0.1.0")
    for message in ("Corrige le ticket #7", "Corrige le ticket #8", "Corrige le ticket #9",
                    "Voir vanguard-beta#5 et &#64; et C#6, sans citation"):
        git("commit", "-q", "--allow-empty", "-m", message)
    with open(os.path.join(dossier, "Cargo.toml"), "w", encoding="utf-8") as f:
        f.write(f'[package]\nname = "essai"\nversion = "{version}"\n')
    with open(os.path.join(dossier, "CHANGELOG.md"), "w", encoding="utf-8") as f:
        f.write(changelog)
    git("add", "Cargo.toml", "CHANGELOG.md")
    git("commit", "-q", "-m", "Version 0.2.0")
    git("tag", "v0.2.0")


TICKETS_JOURNAL = {
    "7": {"number": 7, "state": "OPEN", "labels": [{"name": "journal"}]},
    "8": {"number": 8, "state": "OPEN", "labels": [{"name": "bug"}]},
    "9": {"number": 9, "state": "CLOSED", "labels": [{"name": "journal"}]},
    "5": {"number": 5, "state": "OPEN", "labels": [{"name": "journal"}]},
    "6": {"number": 6, "state": "OPEN", "labels": [{"name": "journal"}]},
}


class CorpsDuTicket(unittest.TestCase):
    def maj(self, corps):
        return tv.mettre_a_jour(corps, "0.2.0", JOUR, "20 novembre", TITRES)[0]

    def test_section_posee_avant_prochaine_version_et_reste_intact(self):
        apres = self.maj(CORPS)
        bloc = ("### 0.2 (livrées en 0.2.0, le 20 novembre)\n" + tv.MARQUE + "\n"
                "- [x] Premier point livré (0.2.0).\n- [x] « Deuxième » point, avec virgule (0.2.0).\n\n")
        attendu = CORPS.replace("État au 1er novembre 2026, version **0.1.0** (dernière page publiée : 0.1.0)",
                                "État au 20 novembre 2026, version **0.2.0** (dernière page publiée : 0.2.0)")
        attendu = attendu.replace("### Prochaine version\n", bloc + "### Prochaine version\n")
        self.assertEqual(apres, attendu)

    def test_idempotent(self):
        une = self.maj(CORPS)
        self.assertEqual(self.maj(une), une)
        self.assertEqual(une.count("### 0.2 "), 1)

    def test_case_cochee_a_la_main_gardee(self):
        apres = self.maj(CORPS)
        for ligne in ("- [x] Coché à la main avant tout.", "- [x] Coché à la main dans la prochaine version."):
            self.assertIn(ligne, apres)

    def test_preparation_remplacee_et_cases_reportees(self):
        corps = CORPS.replace("### Prochaine version\n", PREPARATION + "### Prochaine version\n")
        apres, notes = tv.mettre_a_jour(corps, "0.2.0", JOUR, "20 novembre", TITRES)
        self.assertNotIn("en préparation", apres)
        self.assertEqual(apres, self.maj(CORPS).replace(
            "### Prochaine version\n", "### Prochaine version\n- [ ] Pas encore fait, reporté.\n"))
        self.assertTrue(any("reportée" in n for n in notes))
        self.assertEqual(self.maj(apres), apres)

    def test_preparation_d_une_autre_version_gardee(self):
        corps = CORPS.replace("### Prochaine version\n",
                              PREPARATION.replace("0.2 (en", "0.3 (en") + "### Prochaine version\n")
        self.assertIn("### 0.3 (en préparation", self.maj(corps))

    def test_section_ecrite_a_la_main_gardee(self):
        corps = CORPS.replace("### Prochaine version\n",
                              "### 0.2 (livrées en 0.2.0, le 20 novembre)\n- [x] Écrit à la main (0.2.0).\n\n"
                              "### Prochaine version\n")
        apres = self.maj(corps)
        self.assertIn("- [x] Écrit à la main (0.2.0).", apres)
        self.assertNotIn(tv.MARQUE, apres)

    def test_structure_inconnue_refusee(self):
        with self.assertRaises(tv.Refus):
            self.maj(CORPS.replace("### Prochaine version", "### Plus tard"))
        with self.assertRaises(tv.Refus):
            self.maj(CORPS.replace("État au", "Situation au"))

    def test_changelog_lu(self):
        self.assertEqual(tv.paragraphe_changelog(CHANGELOG, "0.2.0"), ("20 novembre", TITRES))
        with self.assertRaises(tv.Refus):
            tv.paragraphe_changelog(CHANGELOG, "0.3.0")


class Passage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        depot_jetable(self.tmp.name)
        self.lignes = []

    def tearDown(self):
        self.tmp.cleanup()

    def lancer(self, gh, *options, verifier=permis):
        return tv.executer([*options, "--racine", self.tmp.name], gh=gh, verifier=verifier, aujourdhui=JOUR,
                           sortie=self.lignes.append)

    def test_voir_n_envoie_rien(self):
        gh = FauxGh(tickets=dict(TICKETS_JOURNAL))
        self.assertEqual(self.lancer(gh), 0)
        self.assertEqual(gh.envois(), [])
        self.assertIn("tickets du journal à fermer : #7", "\n".join(self.lignes))

    def test_seul_un_ticket_journal_ouvert_est_ferme(self):
        gh = FauxGh(tickets=json.loads(json.dumps(TICKETS_JOURNAL)))
        self.assertEqual(self.lancer(gh, "--appliquer"), 0)
        fermes = [a[2] for a in gh.envois() if a[1] == "close"]
        self.assertEqual(fermes, ["7"])
        self.assertRegex(gh.tickets["7"]["commentaires"][0], r"^Corrigé dans la version 0\.2\.0 \(commit [0-9a-f]+\)\.$")
        self.assertEqual(gh.tickets["8"]["state"], "OPEN")  # pas « journal »
        self.assertEqual(gh.tickets["5"]["state"], "OPEN")  # vanguard-beta#5 : pas une citation
        self.assertEqual(gh.tickets["6"]["state"], "OPEN")  # C#6
        self.assertIn("### 0.2 (livrées en 0.2.0", gh.tickets["1"]["body"])
        # Deuxième passe : corps inchangé, rien de plus envoyé.
        avant = gh.tickets["1"]["body"]
        n = len(gh.envois())
        self.assertEqual(self.lancer(gh, "--appliquer"), 0)
        self.assertEqual(gh.tickets["1"]["body"], avant)
        self.assertEqual(len(gh.envois()), n)

    def test_confidentialite_refusee_rien_envoye(self):
        gh = FauxGh(tickets=dict(TICKETS_JOURNAL))
        self.assertNotEqual(self.lancer(gh, "--appliquer", verifier=refuse), 0)
        self.assertEqual(gh.envois(), [])
        self.assertIn("confidentialité", "\n".join(self.lignes))

    def test_confidentialite_refusee_pour_un_commentaire_seul(self):
        gh = FauxGh(tickets=dict(TICKETS_JOURNAL))
        code = self.lancer(gh, "--appliquer", verifier=lambda t: (not t.startswith("Corrigé"), "simulé"))
        self.assertNotEqual(code, 0)
        self.assertEqual(gh.envois(), [])

    def test_corps_vide_refuse(self):
        gh = FauxGh(corps="")
        self.assertNotEqual(self.lancer(gh, "--appliquer"), 0)
        self.assertEqual(gh.envois(), [])

    def test_corps_raccourci_refuse(self):
        # Une énorme section « en préparation » remplacée par deux lignes : plus de 20 % en moins.
        enorme = "### 0.2 (en préparation)\n" + "".join(f"- [x] Point {i} déjà fait.\n" for i in range(200)) + "\n"
        gh = FauxGh(corps=CORPS.replace("### Prochaine version\n", enorme + "### Prochaine version\n"))
        self.assertNotEqual(self.lancer(gh, "--appliquer"), 0)
        self.assertEqual(gh.envois(), [])
        self.assertIn("raccourcirait", "\n".join(self.lignes))


FAUX_GH = r"""#!/usr/bin/env python3
import json, os, sys
etat = json.load(open(os.environ["FAUX_GH_ETAT"]))
with open(os.environ["FAUX_GH_JOURNAL"], "a") as j:
    j.write(json.dumps(sys.argv[1:]) + "\n")
if etat.get("hors_ligne"):
    sys.stderr.write("error connecting to api.github.com: dial tcp: lookup api.github.com: no such host\n")
    sys.exit(1)
a = sys.argv[1:]
t = etat["tickets"].get(a[2])
if t is None:
    sys.exit(1)
if a[1] == "view":
    champs = a[a.index("--json") + 1].split(",")
    print(json.dumps({c: t.get(c) for c in champs}))
"""


class FauxProgramme(unittest.TestCase):
    """Le vrai script, lancé comme deployer.sh le lancera, avec un faux gh en tête du PATH."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.depot = os.path.join(d, "depot")
        os.mkdir(self.depot)
        depot_jetable(self.depot)
        self.bin = os.path.join(d, "bin")
        os.mkdir(self.bin)
        with open(os.path.join(self.bin, "gh"), "w", encoding="utf-8") as f:
            f.write(FAUX_GH)
        os.chmod(os.path.join(self.bin, "gh"), 0o755)
        self.etat = os.path.join(d, "etat.json")
        self.journal = os.path.join(d, "appels.txt")

    def tearDown(self):
        self.tmp.cleanup()

    def lancer(self, etat, *options, path=None, **env):
        with open(self.etat, "w", encoding="utf-8") as f:
            json.dump(etat, f)
        tout = {**os.environ, "FAUX_GH_ETAT": self.etat, "FAUX_GH_JOURNAL": self.journal,
                "PATH": path if path is not None else f"{self.bin}:{os.environ.get('PATH', '')}", **env}
        if "VANGUARD_HORS_LIGNE" not in env:
            tout.pop("VANGUARD_HORS_LIGNE", None)
        debut = time.monotonic()
        r = subprocess.run([sys.executable, "-I", SCRIPT, *options, "--racine", self.depot], env=tout,
                           capture_output=True, text=True, timeout=90)
        return r, time.monotonic() - debut

    def envois(self):
        if not os.path.exists(self.journal):
            return []
        with open(self.journal, encoding="utf-8") as f:
            return [a for a in map(json.loads, f) if a[1] != "view"]

    def test_hors_ligne_code_3(self):
        etat = {"tickets": {"1": {"body": CORPS}}}
        for env, path in ((({"VANGUARD_HORS_LIGNE": "1"}), None), ({}, self.tmp.name)):
            r, duree = self.lancer(etat, "--appliquer", path=path, **env)
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            self.assertLess(duree, 60)
        r, duree = self.lancer({"hors_ligne": True, "tickets": {}}, "--appliquer")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("injoignable", r.stdout)
        self.assertLess(duree, 60)
        self.assertEqual(self.envois(), [])

    def test_voir_par_defaut(self):
        r, _ = self.lancer({"tickets": {"1": {"body": CORPS}, **TICKETS_JOURNAL}})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("rien n’est envoyé", r.stdout)
        self.assertIn("+### 0.2 (livrées en 0.2.0", r.stdout)
        self.assertEqual(self.envois(), [])

    def test_vraie_garde_de_confidentialite_refuse(self):
        # Un courriel qui n'est pas d'exemple dans le corps lu : la vraie garde refuse, rien ne part. Écrit en deux
        # morceaux pour que le crochet pre-commit ne le prenne pas pour un vrai.
        courriel = "quelquun" + "@" + "invente-pour-essai.ca"
        corps = CORPS.replace("Liste de suivi.", f"Liste de suivi ({courriel}).")
        r, _ = self.lancer({"tickets": {"1": {"body": corps}, **TICKETS_JOURNAL}}, "--appliquer")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("confidentialité", r.stdout)
        self.assertEqual(self.envois(), [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
