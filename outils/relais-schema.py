#!/usr/bin/env python3
"""Le relais (relais/worker.js) face à ce qu'il recopie : le détecteur de secrets de src/amelioration/texte.rs et le
schéma du lot, outils/veille/schema-envoi.json (lot A3). Lancé par outils/verifier.sh (étape relais-schema).

1. Les motifs du détecteur (bloc « MOTIFS DU DÉTECTEUR » du Worker) : chaque liste, chaque seuil, chaque borne, la
   ponctuation permise et les invisibles, comparés aux constantes de texte.rs.
2. Le schéma (bloc « SCHÉMA DU LOT » du Worker) : il n'emploie que les mots-clés que le Worker lit, chaque `$ref`
   mène quelque part, aucun motif n'emploie \\d, \\w ni \\s, chaque définition de la voie ouverte a sa vérification
   dans EN_PLUS, aucun entier n'est écrit en nombre à virgule ; puis il est comparé à schema-envoi.json, clé par clé,
   motif par motif, borne par borne. Si ce fichier manque (lot A3 pas encore fusionné), cette comparaison est sautée
   et c'est dit ; le reste est vérifié quand même.

--ecrire recopie schema-envoi.json dans le bloc du Worker (après une modification du schéma par Rust, A3).
"""

import argparse
import copy
import json
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
WORKER = RACINE / "relais" / "worker.js"
TEXTE = RACINE / "src" / "amelioration" / "texte.rs"
SCHEMA_DEFAUT = RACINE / "outils" / "veille" / "schema-envoi.json"

BLOC_SCHEMA = "SCHÉMA DU LOT"
BLOC_DETECTEUR = "MOTIFS DU DÉTECTEUR"

# Les mots-clés que lit `verifier` dans worker.js ; les annotations ne changent rien à ce qui passe.
MOTS_LUS = {
    "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems",
    "items", "properties", "required", "additionalProperties", "minProperties", "$ref", "$defs",
    "x-octets-max", "x-cle-unique", "x-voie", "x-lot-octets-max", "x-corps-octets-max",
}
ANNOTATIONS = {"$comment", "title", "description", "x-verifie-en-rust"}
TYPES = {"object", "array", "string", "integer", "boolean"}
SORTES_OUVERTES = {"texte", "nom", "version"}


def bornes_du_bloc(source, nom):
    """Les indices du texte entre les lignes « DÉBUT » et « FIN » du bloc `nom`."""
    debut = re.search(rf"^// ==== DÉBUT (?:DU|DES) {re.escape(nom)} =*\n", source, re.M)
    fin = re.search(rf"^// ==== FIN (?:DU|DES) {re.escape(nom)} =*$", source, re.M)
    if not debut or not fin or fin.start() < debut.end():
        raise SystemExit(f"worker.js : bloc « {nom} » introuvable")
    return debut.end(), fin.start()


def lire_bloc(source, nom, constante):
    """L'objet JSON de `const <constante> = … ;` dans le bloc `nom`."""
    a, b = bornes_du_bloc(source, nom)
    m = re.search(rf"^const {constante} = (.*);\s*\Z", source[a:b], re.M | re.S)
    if not m:
        raise SystemExit(f"worker.js : « const {constante} = …; » introuvable dans le bloc « {nom} »")
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError as e:
        raise SystemExit(f"worker.js : le bloc « {nom} » n'est pas du JSON strict : {e}")


def constante_js(source, nom):
    m = re.search(rf"^const {nom} = ([0-9 *]+);", source, re.M)
    if not m:
        raise SystemExit(f"worker.js : constante {nom} introuvable")
    valeur = 1
    for facteur in m.group(1).split("*"):
        valeur *= int(facteur)
    return valeur


# --- 1. Le détecteur face à texte.rs -------------------------------------------------------------------------------

CHAINE = r'"((?:[^"\\]|\\.)*)"'


def tableau_rust(texte, nom):
    m = re.search(rf"^(?:pub\(crate\) )?const {nom}: \[[^\]]*\] = \[(.*?)\];", texte, re.M | re.S)
    if not m:
        raise SystemExit(f"texte.rs : constante {nom} introuvable")
    return m.group(1)


def scalaire_rust(texte, nom):
    m = re.search(rf"^(?:pub\(crate\) )?const {nom}: \w+ = ([0-9.]+);", texte, re.M)
    if not m:
        raise SystemExit(f"texte.rs : constante {nom} introuvable")
    return float(m.group(1)) if "." in m.group(1) else int(m.group(1))


def corps_de_fonction(texte, signature):
    a = texte.find(signature)
    if a < 0:
        raise SystemExit(f"texte.rs : « {signature} » introuvable")
    return texte[a : texte.index("\n}\n", a)]


def detecteur_de_texte_rs(texte):
    chaines = lambda nom: re.findall(CHAINE, tableau_rust(texte, nom))
    mots = re.search(r'\[("mot de passe"[^\]]*)\]', texte)
    permis = re.search(r'"([^"]*)"\.contains\(x\)', corps_de_fonction(texte, "pub(crate) fn permis("))
    invisibles = [
        [int(a, 16), int(b or a, 16)]
        for a, b in re.findall(r"0x([0-9A-Fa-f]+)(?:\.\.=0x([0-9A-Fa-f]+))?", corps_de_fonction(texte, "fn invisible("))
    ]
    if not mots or not permis or not invisibles:
        raise SystemExit("texte.rs : les formes de « mot de passe », `permis` ou `invisible` introuvables")
    return {
        "prefixes": [[p, int(n)] for p, n in re.findall(r'\("([^"]*)",\s*(\d+)\)', tableau_rust(texte, "PREFIXES"))],
        "cles": chaines("CLES"),
        "cles_courtes": chaines("CLES_COURTES"),
        "cles_fortes": chaines("CLES_FORTES"),
        "cles_ligne": chaines("CLES_LIGNE"),
        "schemas": chaines("SCHEMAS"),
        "cles_sans_separateur": chaines("CLES_SANS_SEPARATEUR"),
        "mots_de_passe": re.findall(CHAINE, mots.group(1)),
        "marqueurs": chaines("MARQUEURS"),
        "extension_max": scalaire_rust(texte, "EXTENSION_MAX"),
        "entropie_longueur": scalaire_rust(texte, "ENTROPIE_LONGUEUR"),
        "entropie_seuil": scalaire_rust(texte, "ENTROPIE_SEUIL"),
        "bornes": {
            "texte": scalaire_rust(texte, "TEXTE_MAX"),
            "nom": scalaire_rust(texte, "NOM_MAX"),
            "version": scalaire_rust(texte, "VERSION_MAX"),
        },
        "ponctuation": permis.group(1),
        "invisibles": invisibles,
    }


# --- 2. Le schéma ----------------------------------------------------------------------------------------------------


def ecarts(a, b, chemin="", sortie=None):
    """Les chemins où deux arbres JSON diffèrent (1 et 1.0 diffèrent, comme true et 1)."""
    sortie = [] if sortie is None else sortie
    if type(a) is not type(b):
        sortie.append(f"{chemin or '/'} : {json.dumps(a, ensure_ascii=False)[:80]} ≠ {json.dumps(b, ensure_ascii=False)[:80]}")
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in b:
                sortie.append(f"{chemin}/{k} : seulement dans le Worker")
            elif k not in a:
                sortie.append(f"{chemin}/{k} : seulement dans schema-envoi.json")
            else:
                ecarts(a[k], b[k], f"{chemin}/{k}", sortie)
    elif isinstance(a, list):
        if len(a) != len(b):
            sortie.append(f"{chemin} : {len(a)} éléments ≠ {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            ecarts(x, y, f"{chemin}/{i}", sortie)
    elif a != b:
        sortie.append(f"{chemin} : {json.dumps(a, ensure_ascii=False)[:80]} ≠ {json.dumps(b, ensure_ascii=False)[:80]}")
    return sortie


def fautes_du_schema(schema, en_plus):
    """Ce que le Worker ne saurait pas vérifier tel qu'écrit : il serait plus lâche (ou plus strict) que Rust."""
    fautes = []
    defs = schema.get("$defs", {})

    def noeud(n, chemin, racine=False):
        if not isinstance(n, dict):
            fautes.append(f"{chemin} : un schéma doit être un objet")
            return
        for k in n:
            if k not in MOTS_LUS | ANNOTATIONS:
                fautes.append(f"{chemin} : mot-clé « {k} » que le Worker ne lit pas")
        if "$ref" in n:
            nom = n["$ref"].removeprefix("#/$defs/")
            if not n["$ref"].startswith("#/$defs/") or nom not in defs:
                fautes.append(f"{chemin} : $ref {n['$ref']} ne mène à rien")
            if set(n) - {"$ref"} - ANNOTATIONS:
                fautes.append(f"{chemin} : à côté de $ref, seules des annotations ({sorted(set(n) - {'$ref'} - ANNOTATIONS)})")
        if ("$defs" in n or "x-lot-octets-max" in n or "x-corps-octets-max" in n) and not racine:
            fautes.append(f"{chemin} : $defs et x-*-octets-max seulement à la racine")
        if "x-voie" in n and not re.fullmatch(r"/\$defs/[^/]+", chemin):
            fautes.append(f"{chemin} : x-voie seulement sur une définition (le Worker la reconnaît par son nom)")
        if "type" in n and (not isinstance(n["type"], str) or n["type"] not in TYPES):
            fautes.append(f"{chemin} : type {n['type']!r} (le Worker n'a que {sorted(TYPES)} ; « number » serait refusé)")
        if "properties" in n and n.get("additionalProperties") is not False:
            fautes.append(f"{chemin} : objet sans « additionalProperties: false » (le Worker ferme tout objet)")
        if "additionalProperties" in n and n["additionalProperties"] is not False:
            fautes.append(f"{chemin} : additionalProperties doit valoir false")
        if "pattern" in n:
            if re.search(r"\\[dDwWsS]", n["pattern"]):
                fautes.append(f"{chemin} : motif avec \\d, \\w ou \\s (ASCII en JavaScript, Unicode en Python)")
            try:
                re.compile(n["pattern"])
            except re.error as e:
                fautes.append(f"{chemin} : motif illisible ({e})")
        for k, v in n.get("properties", {}).items():
            noeud(v, f"{chemin}/properties/{k}")
        if "items" in n:
            noeud(n["items"], f"{chemin}/items")
        for k in n.get("x-cle-unique", []):
            cible = n.get("items", {})
            while "$ref" in cible:
                cible = defs.get(cible["$ref"].removeprefix("#/$defs/"), {})
            if k not in cible.get("properties", {}):
                fautes.append(f"{chemin} : x-cle-unique nomme « {k} », absent des entrées")

    noeud(schema, "", racine=True)
    for nom, d in defs.items():
        noeud(d, f"/$defs/{nom}")
        if isinstance(d, dict) and "x-voie" in d:
            if d["x-voie"] != "ouverte":
                fautes.append(f"/$defs/{nom} : x-voie {d['x-voie']!r} inconnue")
            if en_plus.get(nom) not in SORTES_OUVERTES:
                fautes.append(f"/$defs/{nom} : voie ouverte sans vérification dans EN_PLUS (worker.js) : tout lot refusé")
    for nom in en_plus:
        if nom not in defs:
            fautes.append(f"EN_PLUS (worker.js) nomme {nom}, absent des $defs")
    for k in ("x-lot-octets-max", "x-corps-octets-max"):
        if not isinstance(schema.get(k), int):
            fautes.append(f"/{k} : absent ou pas un entier (le Worker le lit)")
    return fautes


def en_json_du_worker(valeur, retrait=0):
    """Le schéma écrit pour le bloc du Worker : un objet par ligne, une liste de valeurs simples coupée à 118."""
    pas = "  "
    if isinstance(valeur, dict):
        if not valeur:
            return "{}"
        dedans = [
            f"{pas * (retrait + 1)}{json.dumps(k, ensure_ascii=False)}: {en_json_du_worker(v, retrait + 1)}"
            for k, v in valeur.items()
        ]
        tout = "{ " + ", ".join(d.strip() for d in dedans) + " }"
        if len(tout) + len(pas * retrait) <= 100 and all(not isinstance(v, (dict, list)) for v in valeur.values()):
            return tout
        return "{\n" + ",\n".join(dedans) + "\n" + pas * retrait + "}"
    if isinstance(valeur, list):
        if all(not isinstance(v, (dict, list)) for v in valeur):
            morceaux = [json.dumps(v, ensure_ascii=False) for v in valeur]
            tout = "[" + ", ".join(morceaux) + "]"
            if len(tout) + len(pas * retrait) <= 100:
                return tout
            lignes, ligne = [], pas * (retrait + 1)
            for m in morceaux:
                if len(ligne) + len(m) + 2 > 118 and ligne.strip():
                    lignes.append(ligne.rstrip())
                    ligne = pas * (retrait + 1)
                ligne += m + ", "
            lignes.append(ligne.rstrip().removesuffix(","))
            return "[\n" + ",\n".join(l.removesuffix(",") for l in lignes) + "\n" + pas * retrait + "]"
        return "[\n" + ",\n".join(pas * (retrait + 1) + en_json_du_worker(v, retrait + 1) for v in valeur) + "\n" + pas * retrait + "]"
    return json.dumps(valeur, ensure_ascii=False)


def ecrire(source, schema):
    a, b = bornes_du_bloc(source, BLOC_SCHEMA)
    bloc = source[a:b]
    debut = bloc.index("const SCHEMA = ")
    nouveau = bloc[:debut] + "const SCHEMA = " + en_json_du_worker(schema) + ";\n"
    if json.loads(nouveau[debut + len("const SCHEMA = ") : -2]) != schema:
        raise SystemExit("relais-schema.py : la réécriture ne redonne pas le schéma (bogue de ce script)")
    return source[:a] + nouveau + source[b:]


def lisible(chemin):
    chemin = chemin.resolve()
    return chemin.relative_to(RACINE) if chemin.is_relative_to(RACINE) else chemin


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--schema", type=Path, default=SCHEMA_DEFAUT, help="schema-envoi.json (par défaut : celui du dépôt)")
    p.add_argument("--ecrire", action="store_true", help="recopier schema-envoi.json dans le bloc du Worker")
    args = p.parse_args()

    source = WORKER.read_text(encoding="utf-8")
    if args.ecrire:
        if not args.schema.is_file():
            raise SystemExit(f"{args.schema} absent : rien à recopier")
        source = ecrire(source, json.loads(args.schema.read_text(encoding="utf-8")))
        WORKER.write_text(source, encoding="utf-8")
        print(f"bloc « {BLOC_SCHEMA} » de relais/worker.js réécrit d'après {args.schema}")

    fautes = []

    # 1. Le détecteur.
    attendu = detecteur_de_texte_rs(TEXTE.read_text(encoding="utf-8"))
    recopie = lire_bloc(source, BLOC_DETECTEUR, "DETECTEUR")
    fautes += [f"détecteur {e}" for e in ecarts(recopie, attendu)]
    print(f"détecteur : {sum(len(v) for v in attendu.values() if isinstance(v, list))} motifs comparés à texte.rs")

    # 2. Le schéma du Worker, seul.
    schema = lire_bloc(source, BLOC_SCHEMA, "SCHEMA")
    m = re.search(r"^const EN_PLUS = (\{.*\});$", source, re.M)
    if not m:
        raise SystemExit("worker.js : « const EN_PLUS = {…}; » introuvable (une ligne, JSON strict)")
    fautes += [f"schéma du Worker {f}" for f in fautes_du_schema(schema, json.loads(m.group(1)))]

    # La comparaison sait-elle voir un écart ? Une copie touchée doit différer, une copie intacte non.
    touche = copy.deepcopy(schema)
    touche.setdefault("$defs", {})["__essai__"] = {"type": "string"}
    if ecarts(schema, copy.deepcopy(schema)) or not ecarts(schema, touche) or not ecarts(1, 1.0):
        fautes.append("relais-schema.py : la comparaison ne voit pas les écarts (bogue de ce script)")

    # 3. Face à schema-envoi.json.
    if args.schema.is_file():
        reference = json.loads(args.schema.read_text(encoding="utf-8"))
        liste = ecarts(schema, reference)
        fautes += [f"schéma {e}" for e in liste[:60]]
        if len(liste) > 60:
            fautes.append(f"schéma : … {len(liste) - 60} écarts de plus")
        if liste:
            fautes.append("  (relais-schema.py --ecrire recopie schema-envoi.json dans le Worker ; puis node --test relais/essais/)")
        if constante_js(source, "TAILLE_MAX") != reference.get("x-corps-octets-max"):
            fautes.append("TAILLE_MAX (worker.js) ≠ x-corps-octets-max (schema-envoi.json)")
        print(f"schéma : comparé à {lisible(args.schema)}")
    else:
        print(f"comparaison avec schema-envoi.json sautée : {lisible(args.schema)} absent (lot A3 pas encore fusionné)")

    if fautes:
        print("\n".join(fautes))
        sys.exit(1)
    print("relais : détecteur et schéma conformes")


if __name__ == "__main__":
    main()
