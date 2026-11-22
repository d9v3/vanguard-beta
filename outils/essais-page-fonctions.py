#!/usr/bin/env python3
"""Essais de outils/page-fonctions.py : les couleurs lues dans la fenêtre (et l'échec clair si elles ne se lisent
plus), la section « À venir » tirée d'un faux ticket (texte échappé, cases cochées écartées, refus de confidentialité,
hors ligne), le remplissage du gabarit en un seul passage, et la visite guidée (capture manquante = échec clair,
chaque image décrite et dimensionnée, section et onglet présents). Aucun réseau : le ticket est un fichier inventé.

    python3 -I outils/essais-page-fonctions.py
"""
import contextlib
import importlib.util
import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RACINE = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("page_fonctions", RACINE / "outils/page-fonctions.py")
pf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pf)

COULEURS = (RACINE / "fenetre/src/couleurs.rs").read_text(encoding="utf-8")
DESSIN = (RACINE / "fenetre/src/dessin/mod.rs").read_text(encoding="utf-8")

# Un faux ticket : valeurs inventées, rien de personnel.
TICKET = """# Fonctions et pistes d'amélioration

## Fait
- [ ] hors de la section, jamais montré

## À améliorer

### Prochaine version
- [ ] Une piste avec <script>alert(1)</script> et un [lien](https://exemple.test/x) et `code` et **gras**
- [x] Une piste déjà faite, jamais montrée
- [ ] Écrire {{VERSION}} et /* pas un commentaire */ tels quels

### Groupe vide
- [x] tout est fait ici

### Ensuite
- [ ] """ + "mot " * 80 + """

## Autre section
- [ ] pas une piste
"""


def bloc(css: str, selecteur: str) -> dict[str, str]:
    """Les jetons (--nom: valeur) du bloc qui suit le sélecteur."""
    i = css.index(selecteur)
    corps = css[i:css.index("}", i)]
    return dict(re.findall(r"--([a-z0-9-]+): ([^;]+)", corps))


def rgb(diese: str) -> tuple[int, int, int]:
    n = int(diese.lstrip("#"), 16)
    return n >> 16, (n >> 8) & 255, n & 255


class Jetons(unittest.TestCase):
    def test_lus_dans_la_fenetre(self):
        j = pf.jetons(COULEURS, DESSIN)
        clair = bloc(j["JETONS"], ":root {")
        sombre = bloc(j["JETONS"], ':root[data-theme="dark"]')
        self.assertEqual(sombre, bloc(j["JETONS"], ':root:not([data-theme="light"])'))
        sombre_rs, clair_rs = pf.palettes(COULEURS)
        self.assertEqual(clair["fond"], pf._hex(clair_rs["fond"]))
        self.assertEqual(sombre["accent"], pf._hex(sombre_rs["accent"]))
        self.assertEqual(j["FOND_SOMBRE"], sombre["fond"])
        self.assertEqual(j["FOND_CLAIR"], clair["fond"])
        self.assertRegex(clair["rayon"], r"^\d+px$")
        self.assertIn("color-scheme: dark", j["JETONS"].split(":root[data-theme")[1])

    def test_texte_lisible_aa(self):
        """Chaque couleur écrite en texte tient 4,5:1 sur le fond et les deux surfaces, dans les deux thèmes."""
        j = pf.jetons(COULEURS, DESSIN)["JETONS"]
        for sel in (":root {", ':root[data-theme="dark"]'):
            t = bloc(j, sel)
            for texte in ("encre", "doux", "discret", "lien", "bon"):
                for fond in ("fond", "surface", "surface-2"):
                    with self.subTest(theme=sel, texte=texte, fond=fond):
                        self.assertGreaterEqual(pf.contraste(rgb(t[texte]), rgb(t[fond])), pf.AA)

    def test_couleurs_illisibles_echec_clair(self):
        for casse in (COULEURS.replace("const PREREGLAGES", "const AUTRE_NOM"),
                      re.sub(r"0x[0-9a-fA-F]{6}", "ROUGE", COULEURS, count=1), ""):
            with self.subTest(debut=casse[:30]), self.assertRaises(SystemExit):
                pf.jetons(casse, DESSIN)

    def test_dessin_illisible_echec_clair(self):
        for casse in (DESSIN.replace("RAYON_CARTE", "RAYON"), DESSIN.replace("from_rgba_premultiplied", "x"), ""):
            with self.subTest(debut=casse[:30]), self.assertRaises(SystemExit):
                pf.jetons(COULEURS, casse)


class AVenir(unittest.TestCase):
    def setUp(self):
        self.dossier = tempfile.TemporaryDirectory()
        self.addCleanup(self.dossier.cleanup)

    def ticket(self, texte: str) -> Path:
        f = Path(self.dossier.name) / "ticket.md"
        f.write_text(texte, encoding="utf-8")
        return f

    def test_cases_ouvertes_seules_et_echappees(self):
        h = pf.a_venir(self.ticket(TICKET))
        self.assertNotIn("<script>", h)
        self.assertIn("&lt;script&gt;", h)
        self.assertNotIn("exemple.test", h)  # un lien du ticket devient son texte
        self.assertIn("<code>code</code>", h)
        self.assertIn("<b>gras</b>", h)
        self.assertNotIn("déjà faite", h)
        self.assertNotIn("Groupe vide", h)
        self.assertNotIn("jamais montré", h)
        self.assertNotIn("pas une piste", h)
        self.assertIn("3 pistes encore ouvertes", h)
        self.assertIn('<details class="replie" open><summary><span>Prochaine version', h)
        self.assertIn(" …</li>", h)  # la piste trop longue est coupée

    def test_hors_ligne(self):
        with mock.patch.dict(os.environ, {"VANGUARD_HORS_LIGNE": "1"}):
            h = pf.a_venir(None)
        self.assertIn("pas disponible", h)
        self.assertIn("hors ligne", h)
        self.assertIn(pf.TICKET_URL, h)

    def test_sans_case_ouverte(self):
        self.assertIn("aucune case ouverte", pf.a_venir(self.ticket("## À améliorer\n### X\n- [x] fait\n")))

    def test_refus_de_confidentialite(self):
        # Un chemin de compte Windows inventé, assemblé ici pour que ce fichier-ci ne porte pas le motif entier.
        chemin = "C:\\" + "Users\\" + "Gas" + "ton\\Documents"
        with contextlib.redirect_stderr(io.StringIO()):
            h = pf.a_venir(self.ticket(f"## À améliorer\n### Prochaine version\n- [ ] lire {chemin}\n"))
        self.assertIn("confidentialité refusée", h)
        self.assertNotIn("Documents", h)


HISTORIQUE = """# Historique

## 3 mars 2031 : version 9.8.7

- **Un titre avec `code` et <balise>.** Une première phrase courte. Une seconde qu'on ne montre pas.
- **Un autre titre** suivi d'un texte bien trop long pour une carte : """ + "mot " * 80 + """
- un point sans gras, ignoré

## 1er mars 2031 : version 9.8.6

- **Ancien point.** Jamais montré.
"""


class Nouveautes(unittest.TestCase):
    def test_points_de_sa_version_seulement_et_echappes(self):
        h = pf.nouveautes("9.8.7", HISTORIQUE)
        self.assertEqual(h.count("<li>"), 2)
        self.assertIn("<b>Un titre avec <code>code</code> et &lt;balise&gt;</b>", h)
        self.assertIn("<span>Une première phrase courte.</span>", h)
        self.assertNotIn("seconde", h)
        self.assertIn("<li><b>Un autre titre</b></li>", h)
        self.assertNotIn("Ancien", h)
        self.assertIn("2 changements dans la version 9.8.7", h)
        self.assertIn(pf.HISTORIQUE_URL, h)

    def test_version_absente_de_la_tete_echec_clair(self):
        """Jamais les nouveautés d'une autre version : un préfixe (9.8), une version plus longue ou sans paragraphe."""
        for v in ("9.8", "9.8.70", "9.8.5", "8.7"):
            with self.subTest(v=v), self.assertRaises(SystemExit):
                pf.nouveautes(v, HISTORIQUE)

    def test_sans_point_en_gras_echec_clair(self):
        with self.assertRaises(SystemExit):
            pf.nouveautes("9.8.7", "## 3 mars 2031 : version 9.8.7\n\n- rien en gras\n")

    def test_refus_de_confidentialite(self):
        chemin = "C:\\" + "Users\\" + "Gas" + "ton\\Documents"
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pf.nouveautes("9.8.7", f"## 3 mars 2031 : version 9.8.7\n\n- **Lire {chemin}.** Texte.\n")

    def test_paragraphe_plus_bas_et_tete_en_preparation(self):
        """La page d'une version se refait même quand la suivante est déjà « en préparation » en tête."""
        h = pf.nouveautes("9.8.6", "## 9.9 (en préparation)\n\n- **Pas encore.** Non.\n\n" + HISTORIQUE)
        self.assertIn("<b>Ancien point</b>", h)
        self.assertNotIn("Pas encore", h)
        self.assertNotIn("Un titre", h)

    def test_vrai_historique(self):
        """Le vrai CHANGELOG.md se lit pour la dernière version qu'il nomme."""
        tete = re.search(r"^## [^\n]*version ([0-9]+\.[0-9]+\.[0-9]+)",
                         (RACINE / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(tete)
        self.assertIn("<li><b>", pf.nouveautes(tete.group(1)))


class Remplir(unittest.TestCase):
    def test_un_seul_passage(self):
        page = pf.remplir("<!-- tête -->\n<p>{{A}}</p>\n<p>{{B}}</p>", {"A": "{{B}} /* garde */", "B": "deux"})
        self.assertIn("<p>{{B}} /* garde */</p>", page)
        self.assertIn("<p>deux</p>", page)
        self.assertNotIn("tête", page)

    def test_trou_inconnu(self):
        with self.assertRaises(SystemExit):
            pf.remplir("<p>{{INCONNU}}</p>", {})

    def test_gabarit_complet(self):
        """Le vrai gabarit : chaque trou a sa valeur, et la barre que document_entier cherche est là."""
        gabarit = (RACINE / "outils/page-fonctions.html").read_text(encoding="utf-8")
        trous = set(re.findall(r"\{\{([A-Z_]+)\}\}", re.sub(r"<!--.*?-->", "", gabarit, count=1, flags=re.S)))
        self.assertTrue({"JETONS", "A_VENIR", "NOUVEAUTES", "FOND_CLAIR", "FOND_SOMBRE"} <= trous)
        self.assertIn('<header class="barre-app"', gabarit)


class Visite(unittest.TestCase):
    GABARIT = (RACINE / "outils/page-fonctions.html").read_text(encoding="utf-8")

    def test_capture_manquante_echec_clair(self):
        with tempfile.TemporaryDirectory() as vide, self.assertRaises(SystemExit) as e:
            pf.captures(Path(vide))
        message = str(e.exception.code)
        self.assertIn("captures-fenetre.sh", message)
        self.assertIn(vide, message)

    def test_chaque_image_decrite_et_dimensionnee(self):
        images = re.findall(r"<img\b[^>]*>", self.GABARIT)
        self.assertGreaterEqual(len(images), len(pf.CAPTURES) + len(pf.VISITE))
        for img in images:
            with self.subTest(img=img[:60]):
                self.assertRegex(img, r'\balt="[^"]{12,}"')
                self.assertRegex(img, r'\bwidth="\{\{[A-Z_]+_L\}\}"')
                self.assertRegex(img, r'\bheight="\{\{[A-Z_]+_H\}\}"')

    def test_chaque_capture_de_la_visite_servie(self):
        """Chaque capture de VISITE a sa place dans la page, et la page n'en attend aucune autre."""
        attendues = {f"VISITE_{cle}" for cle in pf.VISITE}
        self.assertEqual(set(re.findall(r'src="\{\{(VISITE_[A-Z_]+)\}\}"', self.GABARIT)), attendues)

    def test_aucune_capture_du_terminal(self):
        """L'ancienne interface en terminal ne revient plus sur la page : seule la fenêtre est montrée."""
        self.assertFalse({"bilan.png", "reseau.png"} & {nom for nom, _ in pf.CAPTURES.values()})
        self.assertNotRegex(self.GABARIT, r"\{\{CAPTURE_(BILAN|RESEAU)\}\}")
        self.assertNotIn("dans le terminal :", self.GABARIT)

    def test_section_dans_main_et_son_onglet(self):
        main = self.GABARIT[self.GABARIT.index('<main class="cadre" id="contenu">'):self.GABARIT.index("</main>")]
        self.assertIn('\n  <section id="prise-en-main">', main)  # main > section : la recherche de la console la lit
        onglets = self.GABARIT[self.GABARIT.index('<nav class="onglets"'):self.GABARIT.index("</nav>")]
        self.assertIn('<a href="#prise-en-main">Prise en main</a>', onglets)
        self.assertIn('lang="en"', main[main.index('id="prise-en-main"'):main.index('id="securite"')])


if __name__ == "__main__":
    unittest.main(verbosity=1)
