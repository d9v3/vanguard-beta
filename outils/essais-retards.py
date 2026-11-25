#!/usr/bin/env python3
"""Essais hors ligne de outils/retards.py : sorties de cargo, Cargo.toml, Cargo.lock et index inventés ; les épinglages
du vrai dépôt à la fin. Ce qui ne se lit pas doit être un échec, jamais « rien en retard ».
Lancé par outils/verifier.sh (étape essais-retards).
    python3 -I outils/essais-retards.py
"""

import contextlib
import datetime
import http.client
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ICI = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("retards", ICI / "retards.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

SORTIE = """    Updating crates.io index
     Locking 3 packages to latest Rust 1.95.0 compatible versions
    Updating aa v1.0.0 -> v1.0.1
 Downgrading bb v2.0.0 -> v1.9.0 (available: v3.0.0)
      Adding cc v0.1.0 (requires Rust 1.99)
    Removing dd v0.2.0
   Unchanged ee v0.3.0 (latest: v0.4.0)
note: to see how you depend on a package, run `cargo tree --invert <dep>@<ver>`
warning: not updating lockfile due to dry run
"""
VERROU = {
    "package": [
        {"name": "nous", "version": "1.0.0", "dependencies": ["aa", "ee 0.3.0", "gg 2.0.0 (registry+x)"]},
        {"name": "aa", "version": "1.0.0", "source": "registry"},
        {"name": "ee", "version": "0.3.0", "source": "registry"},
        {"name": "ee", "version": "0.1.0", "source": "registry"},
        {"name": "gg", "version": "2.0.0", "source": "registry"},
        {"name": "gg", "version": "1.0.0", "source": "registry"},
    ]
}
RAISON = {"manifeste": "Cargo.toml", "nom": "aa", "version": "1.0.0", "raison": "voulue"}


class Cargo(unittest.TestCase):
    def test_lu(self):
        lues = r.lire_cargo(SORTIE)
        self.assertEqual([x["genre"] for x in lues], ["change", "recul", "ajout", "retrait", "reste"])
        self.assertEqual((lues[1]["apres"], lues[1]["libre"]), ("1.9.0", "3.0.0"))
        self.assertEqual(lues[4]["libre"], "0.4.0")

    def test_rien_a_faire(self):
        self.assertEqual(r.lire_cargo("     Locking 0 packages to latest\nwarning: not updating lockfile due to dry run\n"), [])

    def test_illisible(self):
        for nom, sortie in {
            "vide": "",
            "sans preuve de fin": SORTIE.replace(r.PREUVE, ""),
            "sans annonce": SORTIE.replace("Locking 3 packages", "note 3 packages"),
            "annonce fausse": SORTIE.replace("Locking 3", "Locking 4"),
            "annonce en double": SORTIE + "     Locking 3 packages to latest\n",
            "flèche changée": SORTIE.replace("->", "=>"),
            "suffixe inconnu": SORTIE.replace("v0.4.0)", "v0.4.0) piège"),
            "verbe connu, ligne inconnue": SORTIE + "    Unchanged quelque chose d'autre\n",
            "nom hostile": SORTIE.replace("Updating aa", "Updating a;a"),
        }.items():
            with self.subTest(nom), self.assertRaises(r.Illisible):
                r.lire_cargo(sortie)

    def test_code_de_cargo(self):
        for code, sortie in ((101, SORTIE), (0, "")):
            faux = mock.Mock(returncode=code, stdout=sortie.encode())
            with self.subTest(code), mock.patch.object(r.subprocess, "run", return_value=faux):
                with self.assertRaises(r.Illisible):
                    r.interroger("Cargo.toml")

    def test_verrou_change(self):
        with tempfile.TemporaryDirectory() as d:
            racine = Path(d)
            (racine / "Cargo.lock").write_text("avant")

            def ecrit(*_, **__):
                (racine / "Cargo.lock").write_text("après")
                return mock.Mock(returncode=0, stdout=SORTIE.encode())

            with mock.patch.object(r, "RACINE", racine), mock.patch.object(r.subprocess, "run", ecrit):
                with self.assertRaisesRegex(r.Illisible, "a changé"):
                    r.interroger("Cargo.toml")

    def test_delai_depasse(self):
        with mock.patch.object(r.subprocess, "run", side_effect=r.subprocess.TimeoutExpired("cargo", 1)):
            with self.assertRaisesRegex(r.Illisible, "5 minutes"):
                r.interroger("Cargo.toml")


    def lancer(self, code, sortie, verrou=""):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Cargo.lock").write_text(verrou)
            faux = mock.Mock(return_value=mock.Mock(returncode=code, stdout=sortie.encode()))
            with mock.patch.object(r, "RACINE", Path(d)), mock.patch.object(r.subprocess, "run", faux):
                return r.interroger("Cargo.toml"), faux

    def test_jamais_hors_ligne(self):
        with mock.patch.dict(r.os.environ, {"CARGO_NET_OFFLINE": "true"}):
            _, faux = self.lancer(0, SORTIE)
        self.assertEqual(faux.call_args.kwargs["env"]["CARGO_NET_OFFLINE"], "false")

    def test_index_relu(self):
        sans = SORTIE.replace("    Updating crates.io index\n", "")
        registre = 'source = "registry+https://exemple"'
        self.assertEqual(len(self.lancer(0, sans)[0]), 5)
        self.assertEqual(len(self.lancer(0, SORTIE, registre)[0]), 5)
        with self.assertRaisesRegex(r.Illisible, "index"):
            self.lancer(0, sans, registre)

    def test_epinglee_retiree(self):
        dit = (
            "    Updating crates.io index\nerror: failed to select a version for the requirement `aa = \"=1.0.0\"`\n"
            "  version 1.0.0 is yanked\nlocation searched: crates.io index\n"
        )
        with self.assertRaisesRegex(r.Retiree, "aa 1.0.0, épinglée, est retirée"):
            self.lancer(101, dit)
        for nom, code, sortie in (
            ("autre code", 1, dit),
            ("autre version", 101, dit.replace("version 1.0.0 is", "version 2.0.0 is")),
            ("pas retirée", 101, dit.replace("is yanked", "is missing")),
            ("pas épinglée", 101, dit.replace('"=1.0.0"', '"^1.0.0"')),
        ):
            with self.subTest(nom), self.assertRaises(r.Illisible):
                self.lancer(code, sortie)


class Verrou(unittest.TestCase):
    def test_directes(self):
        self.assertEqual(r.directes(VERROU, "nous"), {"aa": {"1.0.0"}, "ee": {"0.3.0"}, "gg": {"2.0.0"}})

    def test_directes_illisibles(self):
        for nom, verrou in {
            "deux racines": {"package": [*VERROU["package"], {"name": "nous", "version": "2.0.0"}]},
            "pas de racine": {"package": VERROU["package"][1:]},
            "deux versions, aucune dite": {"package": [{"name": "nous", "version": "1", "dependencies": ["ee"]}, *VERROU["package"][2:]]},
            "dépendance absente": {"package": [{"name": "nous", "version": "1", "dependencies": ["zz"]}]},
            "version absente": {"package": [{"name": "nous", "version": "1", "dependencies": ["aa 9.0.0"]}, VERROU["package"][1]]},
        }.items():
            with self.subTest(nom), self.assertRaises(r.Illisible):
                r.directes(verrou, "nous")

    def test_racine_du_meme_nom_sur_crates_io(self):
        double = {"package": [*VERROU["package"], {"name": "nous", "version": "0.1.0", "source": "registry"}]}
        self.assertIn("aa", r.directes(double, "nous"))


class Retards(unittest.TestCase):
    def retards(self, lignes, demandees, gardees=frozenset()):
        compte = sum(x.startswith(("Updating", "Downgrading", "Adding")) for x in lignes)
        return r.retards(r.lire_cargo("\n".join([f"Locking {compte} packages", *lignes, r.PREUVE])), demandees, gardees)

    def test_nommes_et_comptes(self):
        lues = r.lire_cargo(SORTIE)
        demandees = {"aa": {"1.0.0"}, "bb": {"2.0.0"}, "ee": {"0.3.0"}}
        self.assertEqual(
            r.retards(lues, demandees, {("ee", "0.3.0")}),
            ([("aa", "1.0.0", [("1.0.1", "cargo update suffit")]), ("bb", "2.0.0", [("3.0.0", "Cargo.toml à changer")]),
              ("ee", "0.3.0", [("0.4.0", "gardée exprès")])], 0),
        )  # fmt: skip
        self.assertEqual(r.retards(lues, {}, set()), ([], 3))

    def test_autre_version_du_meme_nom(self):
        self.assertEqual(r.retards(r.lire_cargo(SORTIE), {"ee": {"0.9.0"}}, set())[1], 3)

    def test_rien_de_neuf(self):
        for x in ({"genre": "reste", "libre": None}, {"genre": "change", "apres": "1.0.0", "libre": None}):
            with self.subTest(x):
                self.assertEqual(r.retards([{"nom": "aa", "avant": "1.0.0", **x}], {"aa": {"1.0.0"}}, set()), ([], 0))

    def test_les_deux_nouvelles(self):
        dit = self.retards(["Updating aa v8.2.0 -> v8.2.2 (available: v9.0.0)"], {"aa": {"8.2.0"}})
        self.assertEqual(dit[0], [("aa", "8.2.0", [("8.2.2", "cargo update suffit"), ("9.0.0", "Cargo.toml à changer")])])
        dit = self.retards(["Updating aa v1.0.0 -> v1.0.1 (available: v1.0.1)"], {"aa": {"1.0.0"}})
        self.assertEqual(dit[0], [("aa", "1.0.0", [("1.0.1", "cargo update suffit")])])

    def test_recul(self):
        self.assertEqual(self.retards(["Downgrading aa v2.0.0 -> v1.9.0"], {"aa": {"2.0.0"}}), ([], 0))

    def test_deux_versions_du_meme_nom_bougent(self):
        # Vrai cas (cargo 1.100) : aucun « a -> b », la bibliothèque demandée se perdait.
        lignes = ["Removing syn v2.0.100", "Removing syn v3.0.8", "Adding syn v2.0.119", "Adding syn v3.0.10 (available: v4.0.0)"]
        self.assertEqual(
            self.retards(lignes, {"syn": {"3.0.8"}}),
            ([("syn", "3.0.8", [("3.0.10", "cargo update suffit"), ("4.0.0", "Cargo.toml à changer")])], 1),
        )
        self.assertEqual(self.retards(lignes, {"syn": {"2.0.100"}})[0][0][2], [("2.0.119", "cargo update suffit")])

    def test_remplacante(self):
        for retiree, ajouts, prise in (
            ("0.3.1", ["0.3.9", "0.3.10", "0.4.0"], "0.3.10"),
            ("0.0.4", ["0.0.5", "0.1.0"], "0.1.0"),
            ("1.0.0", ["2.0.0", "10.0.0", "10.0.0-rc.1"], "10.0.0"),
            ("1.0.0-rc.1", ["1.0.0-rc.2", "1.0.0"], "1.0.0"),
        ):
            with self.subTest(retiree):
                lignes = [f"Removing aa v{retiree}", *(f"Adding aa v{a}" for a in ajouts)]
                self.assertEqual(self.retards(lignes, {"aa": {retiree}})[0][0][2], [(prise, "cargo update suffit")])

    def test_remplacante_plus_vieille(self):
        self.assertEqual(self.retards(["Removing aa v1.0.2", "Adding aa v1.0.1"], {"aa": {"1.0.2"}}), ([], 0))

    def test_retiree_sans_remplacante(self):
        self.assertEqual(self.retards(["Removing aa v1.0.0"], {}), ([], 0))
        with self.assertRaisesRegex(r.Illisible, "sans remplaçante"):
            self.retards(["Removing aa v1.0.0", "Adding bb v1.0.1"], {"aa": {"1.0.0"}})

    def test_ligne_semver(self):
        for version, ligne in (("1.2.3", ("1",)), ("0.3.4", ("0", "3")), ("0.0.4", ("0", "0", "4")), ("0.0.0", ("0", "0", "0"))):
            self.assertEqual(r.ligne_semver(version), ligne)


class Gardees(unittest.TestCase):
    def ecarts(self, liste, pins=None, verrous=None):
        return r.ecarts_gardees(liste, {"Cargo.toml": {"aa": {"1.0.0"}}} if pins is None else pins, verrous or {})

    def test_juste(self):
        self.assertEqual(self.ecarts([RAISON]), [])

    def test_ecarts(self):
        for nom, liste, dit in (
            ("sans raison écrite", [], "sans raison"),
            ("raison vide", [{**RAISON, "raison": " "}], "mal écrite"),
            ("champ inconnu", [{**RAISON, "jusqua": "x"}], "champ inconnu"),
            ("plus épinglée", [RAISON, {**RAISON, "nom": "zz"}], "n'y est pas épinglée"),
            ("autre version", [{**RAISON, "version": "1.0.1"}], "n'y est pas épinglée"),
            ("autre manifeste", [{**RAISON, "manifeste": "fuzz/Cargo.toml"}], "n'y est pas épinglée"),
            ("en double", [RAISON, RAISON], "en double"),
            ("verrou absent", [{**RAISON, "comme": "x/Cargo.lock"}], "retient aucune"),
        ):
            with self.subTest(nom):
                self.assertIn(dit, " | ".join(self.ecarts(liste)))

    def test_comme(self):
        liste = [{**RAISON, "comme": "Cargo.lock"}]
        self.assertEqual(self.ecarts(liste, verrous={"Cargo.lock": VERROU}), [])
        autre = {"package": [{"name": "aa", "version": "1.0.1"}]}
        self.assertIn("retient 1.0.1", " | ".join(self.ecarts(liste, verrous={"Cargo.lock": autre})))

    def test_epinglees_partout(self):
        m = {
            "dependencies": {"aa": "=1.0.0", "libre": "1.0", "borne": ">=1, <2"},
            "dev-dependencies": {"bb": {"version": "= 2.0.0"}},
            "build-dependencies": {"alias": {"package": "cc", "version": "=3.0.0"}, "locale": {"path": "x"}},
            "target": {"cfg(windows)": {"dependencies": {"dd": "=4.0.0"}}},
            "workspace": {"dependencies": {"ee": ">=5, =5.0.0"}},
        }
        self.assertEqual(r.epinglees(m), {"aa": {"1.0.0"}, "bb": {"2.0.0"}, "cc": {"3.0.0"}, "dd": {"4.0.0"}, "ee": {"5.0.0"}})


class Manifestes(unittest.TestCase):
    def test_sans_celui_de_vanguard(self):
        for dit in (b"", b"fuzz/Cargo.lock\0"):
            with mock.patch.object(r.subprocess, "run", return_value=mock.Mock(stdout=dit)):
                with self.assertRaises(r.Illisible):
                    r.manifestes()


class Dates(unittest.TestCase):
    JOUR = datetime.date(2026, 11, 25)
    INDEX = 'pas du json\n{"vers":"1.0.0","pubtime":"2026-11-01T00:00:00Z"}\n{"vers":"1.0.1","pubtime":"2026-11-20T00:00:00Z"}\n{"vers":"1.0.2"}\n'

    def test_adresse(self):
        for nom, fin in (("a", "1/a"), ("ab", "2/ab"), ("abc", "3/a/abc"), ("YARA-x", "ya/ra/yara-x")):
            self.assertEqual(r.adresse_index(nom), f"https://index.crates.io/{fin}")

    def test_age(self):
        for version, dit in (("1.0.0", "parue le 2026-11-01"), ("1.0.1", "attendre"), ("1.0.2", "inconnue"), ("9.9.9", "inconnue")):
            with self.subTest(version), mock.patch.object(r, "telecharger_index", return_value=self.INDEX):
                dite = r.age_dit("aa", version, self.JOUR)
                self.assertIn(dit, dite)
                self.assertEqual("attendre" in dite, version == "1.0.1")

    def test_bord_du_delai(self):
        for jours, attendre in ((r.DELAI - 1, True), (r.DELAI, False)):
            index = f'{{"vers":"1","pubtime":"{self.JOUR - datetime.timedelta(days=jours)}T00:00:00Z"}}'
            with mock.patch.object(r, "telecharger_index", return_value=index):
                self.assertEqual("attendre" in r.age_dit("aa", "1", self.JOUR), attendre)

    def test_panne(self):
        for panne in (OSError("x"), ValueError("x"), http.client.IncompleteRead(b""), RecursionError()):
            with mock.patch.object(r, "telecharger_index", side_effect=panne):
                self.assertIn("inconnue", r.age_dit("aa", "1.0.0", self.JOUR))

    def test_reponse_geante(self):
        with mock.patch.object(r, "PLAFOND", 10), mock.patch.object(r.urllib.request, "urlopen", return_value=io.BytesIO(b"x" * 11)):
            with self.assertRaises(ValueError):
                r.telecharger_index("aa")


class Programme(unittest.TestCase):
    def lancer(self, *args, **remplace):
        sortie = io.StringIO()
        with mock.patch.object(r.sys, "argv", ["retards.py", *args]), contextlib.redirect_stdout(sortie):
            with contextlib.redirect_stderr(sortie), contextlib.ExitStack() as pile:
                for nom, valeur in remplace.items():
                    pile.enter_context(mock.patch.object(r, nom, valeur))
                code = r.main()
        return code, sortie.getvalue()

    def test_depot(self):
        code, dit = self.lancer("--gardees")
        self.assertEqual(code, 0, dit)
        self.assertIn("chacune avec sa raison", dit)

    def test_retard_jamais_un_echec(self):
        code, dit = self.lancer(interroger=lambda m: r.lire_cargo(SORTIE))
        self.assertEqual(code, 0, dit)
        self.assertRegex(dit, r"(?m)^retards : 0 bibliothèque\(s\) demandée\(s\), \d+ autre\(s\)$")

    def test_epinglee_retiree_dite(self):
        def retiree(m):
            if m != "fuzz/Cargo.toml":
                return r.lire_cargo(SORTIE)
            raise r.Retiree("aa 1.0.0, épinglée, est retirée")

        code, dit = self.lancer(interroger=retiree)
        self.assertEqual(code, 0, dit)
        self.assertIn("\n  aa 1.0.0, épinglée, est retirée", dit)
        self.assertRegex(dit, r"(?m)^retards : .*, 1 Cargo\.toml NON VÉRIFIÉ\(S\)$")

    def test_retard_dit(self):
        lues = r.lire_cargo(SORTIE.replace("Updating aa v1.0.0 -> v1.0.1", "Updating aa v1.0.0 -> v1.0.1 (available: v2.0.0)"))
        code, dit = self.lancer(
            interroger=lambda m: lues, directes=lambda *_: {"aa": {"1.0.0"}}, age_dit=lambda *_: "parue hier"
        )
        self.assertEqual(code, 0, dit)
        self.assertIn("  aa 1.0.0 -> 1.0.1 (cargo update suffit, parue hier) ; 2.0.0 (Cargo.toml à changer, parue hier)\n", dit)

    def test_liste_de_travers(self):
        for panne in (ValueError("x"), TypeError("x"), AttributeError("x"), KeyError("x"), UnicodeDecodeError("utf-8", b"", 0, 1, "x")):
            code, dit = self.lancer(charger=mock.Mock(side_effect=panne))
            self.assertEqual(code, 1)
            self.assertIn("non vérifiés", dit)

    def test_echecs(self):
        def panne(_):
            raise r.Illisible("essai")

        for nom, remplace, dit in (
            ("cargo illisible", {"interroger": panne}, "non vérifiés : essai"),
            ("sans liste", {"GARDEES": "outils/absent.toml"}, "non vérifiés"),
            ("liste sans entrée", {"GARDEES": "rust-toolchain.toml"}, "sans raison"),
            ("aucun manifeste", {"manifestes": mock.Mock(side_effect=r.Illisible("vide"))}, "non vérifiés : vide"),
        ):
            with self.subTest(nom):
                code, sortie = self.lancer(**remplace)
                self.assertEqual(code, 1, sortie)
                self.assertIn(dit, sortie)
                self.assertNotIn("retards : ", sortie)

    def test_usage(self):
        for args in (("--tout",), ("--gardees", "x"), ("",)):
            self.assertEqual(self.lancer(*args)[0], 2)


if __name__ == "__main__":
    unittest.main()
