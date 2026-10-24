#!/usr/bin/env python3
"""Les textes affichés par Vanguard comparés à ceux de master : chaque chaîne passée à tr!, trf!, trp!, tre!, trw!,
trwln! ou trpr! dans src/, ici et dans master. Un texte perdu (une traduction tombée avec du code retiré) ou nouveau
(à relire dans les deux langues) se voit avant le commit ; une optimisation « sans changement de comportement » doit
n'en montrer aucun. Lancé par outils/verifier.sh (étape « textes FR/EN »), ou à la main depuis la racine du dépôt :
    python3 outils/textes.py [RÉFÉRENCE]        (master par défaut)
Les deux ensembles sont pris sur tout src/, pas fichier par fichier : un module déplacé ou renommé ne fait pas paraître
tous ses textes « perdus » puis « nouveaux ». Sans la référence (clone partiel de la CI), rien n'est comparé : code 77,
« sautée » pour verifier.sh. Toujours 0 sinon : les écarts sont à lire, pas une erreur.
Une seule erreur (code 1) : un tutoiement dans un texte français affiché (premier argument de ces macros, première
chaîne d'une paire ("fr", "en") ou [fr, en], aide `///` de la ligne de commande dans main.rs). Vanguard vouvoie
depuis la 0.87 ; cette vérification tourne aussi sur master et sans la référence (--vouvoiement : elle seule)."""
import re
import subprocess
import sys

MACRO = re.compile(r'\btr(?:f|p|e|w|wln|pr)?!\s*\(')


def chaines(texte):
    """Les littéraux de chaîne de chaque appel de ces macros, jusqu'à sa parenthèse fermante (chaînes brutes r"…" et
    r#"…"# comprises)."""
    trouvees = set()
    for m in MACRO.finditer(texte):
        profondeur, j = 1, m.end()
        while j < len(texte) and profondeur:
            c = texte[j]
            brute = re.match(r'r(#*)"', texte[j:j + 10]) if c == 'r' and (j == 0 or not texte[j - 1].isalnum()) else None
            if brute:
                fin = '"' + brute.group(1)
                k = texte.find(fin, j + len(brute.group(0)))
                if k < 0:
                    break
                trouvees.add(texte[j:k + len(fin)])
                j = k + len(fin)
                continue
            if c == '"':
                k = j + 1
                while k < len(texte) and texte[k] != '"':
                    k += 2 if texte[k] == '\\' else 1
                trouvees.add(texte[j:k + 1])
                j = k + 1
                continue
            if c == "'" and texte[j + 1:j + 3] in ("\"'", "('", ")'"):
                # Un caractère '"', '(' ou ')' : ni une chaîne, ni une parenthèse.
                j += 3
                continue
            profondeur += c == '('
            profondeur -= c == ')'
            j += 1
    return trouvees


TUTOIEMENT = re.compile(r"(?<![\\\w'’-])(tu|te|ton|ta|tes|toi|t'|t’)(?![\w'’-])", re.IGNORECASE)
CHAINE = r'"((?:[^"\\]|\\.)*)"'
PAIRE = re.compile(r'[(\[]\s*' + CHAINE + r'\s*,\s*"(?:[^"\\]|\\.)*"\s*,?\s*[)\]]')


def tutoiements(fichier, texte):
    """Les textes français affichés qui tutoient encore, avec leur ligne. Le module de tests, en fin de fichier, est
    laissé : ses données imitent aussi des textes d'avant."""
    tests = re.search(r'^#\[cfg\(test\)\]\s*mod tests\b', texte, re.MULTILINE)
    texte = texte[:tests.start()] if tests else texte
    vus = []
    def note(debut, chaine):
        # Les \n d'un texte coupé à la main ne collent pas deux mots : « toi\nmême » se lit « toi ».
        if TUTOIEMENT.search(chaine.replace('\\n', ' ')):
            vus.append(f"{fichier}:{texte.count(chr(10), 0, debut) + 1} : {chaine[:90]}")
    for m in MACRO.finditer(texte):
        premiere = re.compile(r'\s*(?:r#*)?' + CHAINE).match(texte, m.end())
        if premiere:
            note(premiere.start(1), premiere.group(1))
    for m in PAIRE.finditer(texte):
        note(m.start(1), m.group(1))
    if fichier == 'src/main.rs':
        for m in re.finditer(r'^\s*///(.*)$', texte, re.MULTILINE):
            note(m.start(1), m.group(1))
    return sorted(set(vus))


def vouvoiement():
    restants = []
    for f in git('ls-files', '--cached', '--others', '--exclude-standard', 'src').stdout.split():
        if f.endswith('.rs'):
            try:
                with open(f, encoding='utf-8') as fichier:
                    restants += tutoiements(f, fichier.read())
            except FileNotFoundError:
                pass
    for ligne in restants:
        print("✖ tutoiement :", ligne)
    return len(restants)


def git(*args):
    return subprocess.run(['git', *args], capture_output=True, text=True, check=False)


def main():
    if vouvoiement():
        return 1
    if sys.argv[1:] == ['--vouvoiement']:
        return 0
    reference = sys.argv[1] if len(sys.argv) > 1 else 'master'
    if git('rev-parse', '--verify', '-q', f'{reference}^{{commit}}').returncode:
        print(f"pas de branche {reference} ici (clone partiel ?) : rien à comparer")
        return 77
    avant = set()
    for f in git('ls-tree', '-r', '--name-only', reference, 'src').stdout.split():
        if f.endswith('.rs'):
            avant |= chaines(git('show', f'{reference}:{f}').stdout)
    apres = set()
    for f in git('ls-files', '--cached', '--others', '--exclude-standard', 'src').stdout.split():
        if f.endswith('.rs'):
            try:
                with open(f, encoding='utf-8') as fichier:
                    apres |= chaines(fichier.read())
            except FileNotFoundError:
                pass
    print(len(avant), "chaînes dans", reference + ",", len(apres), "ici")
    print("perdues :", sorted(avant - apres)[:20])
    print("nouvelles :", sorted(apres - avant)[:20])
    return 0


if __name__ == '__main__':
    sys.exit(main())
