#!/usr/bin/env python3
"""Rapport HTML d'un essai complet sous Linux (outils/test-linux/essai.sh), au même style que celui du test Windows :
verdict, étapes, vérifications, et la sortie de chaque commande à déplier.
    python3 outils/test-commun/rapport.py <dossier de résultats>   → <dossier>/rapport-test.html
"""

import html
import re
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
COMMANDE = re.compile(r"^vanguard (?P<args>.*) -> code (?P<code>\d+), (?P<duree>\d+) s(?P<delai> \(DÉLAI DÉPASSÉ\))? · (?P<fichier>\S+)$")

STYLE = """
:root{--fond:#0b0808;--carte:#160f10;--trait:#2e2224;--texte:#eee3db;--gris:#a8968c;--rouge:#ff5a4f;--vert:#5fd38d;--jaune:#f2c14e}
*{box-sizing:border-box}body{margin:0;background:var(--fond);color:var(--texte);font:15px/1.5 system-ui,'Segoe UI',sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 16px 60px}h1{margin:0 0 4px;font-size:26px}h1 b{color:var(--rouge)}
.sous{color:var(--gris);margin-bottom:22px}.bilan{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:26px}
.case{background:var(--carte);border:1px solid var(--trait);border-radius:10px;padding:12px 16px;min-width:150px}
.case b{display:block;font-size:24px}.case span{color:var(--gris);font-size:13px}
.etape{background:var(--carte);border:1px solid var(--trait);border-radius:10px;margin:0 0 12px;padding:14px 16px}
.etape h2{margin:0 0 8px;font-size:16px;display:flex;gap:8px;align-items:center}.pastille{width:10px;height:10px;border-radius:50%;background:var(--vert);flex:none}
.etape.rouge .pastille{background:var(--rouge)}.etape.grise .pastille{background:var(--gris)}
ul{margin:4px 0 8px;padding-left:4px;list-style:none}li{margin:2px 0}.ok{color:var(--vert)}.bug{color:var(--rouge)}.info{color:var(--gris)}
details{border-top:1px solid var(--trait);padding:6px 0}summary{cursor:pointer;display:flex;justify-content:space-between;gap:10px}
summary code{color:var(--texte);font-variant-ligatures:none}summary .d{color:var(--gris);white-space:nowrap}
pre{background:#000;border-radius:8px;padding:10px;overflow:auto;max-height:420px;font:12.5px/1.45 Consolas,monospace;color:#ddd}
.verdict{border-radius:12px;padding:16px 20px;font-size:20px;font-weight:600;margin-bottom:14px}
.verdict.vert{background:#0f2a1a;border:1px solid #1f6b3e;color:var(--vert)}.verdict.rouge{background:#2c0d0d;border:1px solid #7e1c1c;color:var(--rouge)}
"""


def court(args: str) -> str:
    """Les longs chemins réduits à leur nom de fichier, comme à l'écran."""
    return " ".join(Path(m).name if "/" in m else m for m in args.split(" ")) or "(menu)"


def main() -> None:
    dossier = Path(sys.argv[1])
    lignes = (dossier / "journal.txt").read_text(encoding="utf-8").splitlines()
    titre = lignes[0].strip("= ") if lignes else "Essai"
    etapes: list[dict] = []
    for ligne in lignes[1:]:
        if ligne.startswith("=== Fin"):
            continue
        if ligne.startswith("--- "):
            etapes.append({"titre": ligne[4:], "verifs": [], "commandes": []})
            continue
        if not etapes:
            etapes.append({"titre": "Démarrage", "verifs": [], "commandes": []})
        etape = etapes[-1]
        if m := COMMANDE.match(ligne):
            etape["commandes"].append(m.groupdict())
        elif ligne.startswith("OK "):
            etape["verifs"].append(("ok", ligne[3:].strip()))
        elif ligne.startswith("ÉCHEC "):
            etape["verifs"].append(("bug", ligne[6:].strip()))
        elif ligne.strip():
            etape["verifs"].append(("info", ligne.strip()))

    verifs = [v for e in etapes for v in e["verifs"]]
    commandes = [c for e in etapes for c in e["commandes"]]
    nb_ok = sum(1 for e, _ in verifs if e == "ok")
    nb_bug = sum(1 for e, _ in verifs if e == "bug")
    nb_echec = sum(1 for c in commandes if c["code"] != "0" or c["delai"])
    reussi = nb_bug == 0 and nb_echec == 0
    verdict = (
        f"✓ Tout est passé : {nb_ok} vérifications réussies"
        if reussi
        else f"✗ {nb_bug} problème(s) · {nb_echec} commande(s) en échec"
    )

    h = html.escape
    morceaux = [
        f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Test de Vanguard</title><style>{STYLE}</style></head><body><main>",
        f'<h1>Test de <b>Vanguard</b></h1><div class="sous">{h(titre)}</div>',
        f'<div class="verdict {"vert" if reussi else "rouge"}">{h(verdict)}</div>',
        f'<div class="bilan"><div class="case"><b class="ok">{nb_ok}</b><span>vérifications réussies</span></div>'
        f'<div class="case"><b class="{"bug" if nb_bug else "info"}">{nb_bug}</b><span>problèmes</span></div>'
        f"<div class=\"case\"><b>{len(commandes)}</b><span>commandes ({nb_echec} en échec)</span></div></div>",
    ]
    for e in etapes:
        rouge = any(v == "bug" for v, _ in e["verifs"]) or any(c["code"] != "0" or c["delai"] for c in e["commandes"])
        classe = "rouge" if rouge else ("grise" if not e["verifs"] and not e["commandes"] else "")
        morceaux.append(f'<section class="etape {classe}"><h2><span class="pastille"></span>{h(e["titre"])}</h2>')
        if e["verifs"]:
            signes = {"ok": "✓", "bug": "✗", "info": "·"}
            morceaux.append(
                "<ul>" + "".join(f'<li class="{v}">{signes[v]} {h(t)}</li>' for v, t in e["verifs"]) + "</ul>"
            )
        for c in e["commandes"]:
            fichier = dossier / c["fichier"]
            sortie = ANSI.sub("", fichier.read_text(encoding="utf-8", errors="replace")) if fichier.is_file() else ""
            if c["delai"]:
                etat = '<span class="bug">✗ délai dépassé</span>'
            elif c["code"] == "0":
                etat = '<span class="ok">✓</span>'
            else:
                etat = f'<span class="bug">✗ code {c["code"]}</span>'
            morceaux.append(
                f'<details><summary><code title="{h("vanguard " + c["args"])}">vanguard {h(court(c["args"]))}</code>'
                f'<span class="d">{etat} {c["duree"]} s</span></summary><pre>{h(sortie)}</pre></details>'
            )
        morceaux.append("</section>")
    morceaux.append("</main></body></html>")
    sortie = dossier / "rapport-test.html"
    sortie.write_text("".join(morceaux), encoding="utf-8")
    print(sortie)


if __name__ == "__main__":
    main()
