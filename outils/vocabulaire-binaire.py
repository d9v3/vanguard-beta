#!/usr/bin/env python3
"""Contrôle croisé du vocabulaire de la porte MCP (lot V1) : chaque morceau du vocabulaire doit se trouver, octet pour
octet, dans au moins un des programmes publiés (Linux, Windows).

Le vocabulaire (OUT_DIR/vocabulaire.txt, écrit par build.rs avec src/porte_mcp/sources.rs) est la liste des mots qu'une
réponse de la porte peut laisser sortir. La lecture des sources devine ce que rustc garde : neuf rondes adverses y ont
trouvé une ruse pour faire compter un texte que le programme n'écrit jamais (macro maison qui jette ses arguments, faux
attribut d'essai, `cfg` mal jugé, paquet monté sous le programme). Ce contrôle ne devine rien : il regarde les octets
que rustc a vraiment produits. Un morceau absent de tous les programmes est une ruse, du code mort ou une chaîne qui
n'est pas un texte du programme : dans tous les cas un échec, nommé.

Le programme porte lui-même son vocabulaire (include_str!) : ce bloc est d'abord retiré, sinon tout morceau s'y
trouverait. Le bloc doit y être exactement une fois, et le même dans chaque programme qui le porte : c'est aussi la
preuve que le vocabulaire contrôlé est celui que la porte de ces programmes-là emploie. Un programme où la porte n'est
pas servie (Windows aujourd'hui) ne le porte pas, rustc l'a retiré : ses textes comptent quand même ; il en faut au
moins un qui le porte. Les données embarquées que le programme
n'écrit pas comme des textes (--donnees : les règles YARA allégées, les noms des fabricants) sont retirées aussi : un
mot qui ne se trouve que dans une règle YARA n'est pas un texte de Vanguard.

    python3 -I outils/vocabulaire-binaire.py [--sources DOSSIER] [--donnees FICHIER]... [--a-cote NOM]... \\
        --vocabulaire FICHIER [--vocabulaire FICHIER]... -- PROGRAMME...

Plusieurs --vocabulaire : les candidats (un dossier de compilation garde parfois plusieurs OUT_DIR) ; celui que les
programmes portent est choisi par ses octets, jamais par sa date. --donnees : un fichier de données tel qu'il est
embarqué (octets bruts), ou un fichier fabricants.rs de build.rs, dont la chaîne NOMS est relue. --a-cote : une
donnée prise dans le dossier du vocabulaire choisi (l'OUT_DIR de la compilation de ces programmes, jamais un voisin
plus ancien). --sources : le dossier
où chercher, pour chaque morceau absent, les fichiers qui l'écrivent (une aide au message, rien de plus).

Code 0 : chaque morceau est dans un programme. 1 : des morceaux absents (chacun nommé, avec ses fichiers). 2 : rien
n'est conclu (fichier illisible, vocabulaire mal formé ou porté par aucun programme, présent deux fois, différent
d'un programme à l'autre, donnée introuvable) : jamais un vert. Lancé par outils/compiler-version.sh avant le repère
de la compilation (rien n'est publié sans lui) et par outils/verifier.sh (étape « vocabulaire-binaire ») ; ses essais :
outils/essais-vocabulaire-binaire.sh.
"""
import argparse
import re
import sys
from pathlib import Path

# La chaîne des noms des fabricants dans fabricants.rs (build.rs : `pub static NOMS: &str = {tous:?};`).
NOMS_FABRICANTS = re.compile(r'^pub static NOMS: &str = "((?:[^"\\]|\\.)*)";$', re.M)
# Les échappements de `{:?}` d'une chaîne Rust (str::escape_debug).
ECHAPPEMENT = re.compile(r"\\(u\{([0-9a-fA-F]{1,6})\}|.)", re.S)
SIMPLES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}


class Rien(Exception):
    """Rien n'est conclu (code 2)."""


def lire(chemin: str) -> bytes:
    try:
        return Path(chemin).read_bytes()
    except OSError as e:
        raise Rien(f"{chemin} illisible : {e.strerror}") from e


def chaine_rust(echappee: str) -> str:
    """Une chaîne écrite par `{:?}` (Debug de str), rendue à ses caractères."""

    def un(m: re.Match) -> str:
        if m.group(2) is not None:
            return chr(int(m.group(2), 16))
        if m.group(1) not in SIMPLES:
            raise Rien(f"échappement inconnu « \\{m.group(1)} » dans la chaîne des fabricants")
        return SIMPLES[m.group(1)]

    return ECHAPPEMENT.sub(un, echappee)


def donnee(chemin: str) -> bytes:
    """Les octets d'une donnée embarquée : le fichier tel quel, ou la chaîne NOMS d'un fabricants.rs."""
    brut = lire(chemin)
    if Path(chemin).name != "fabricants.rs":
        return brut
    trouve = NOMS_FABRICANTS.findall(brut.decode("utf-8", errors="strict"))
    if len(trouve) != 1:
        raise Rien(f"{chemin} : la chaîne NOMS n'y est pas une fois ({len(trouve)})")
    return chaine_rust(trouve[0]).encode("utf-8")


def morceaux(vocabulaire: bytes, chemin: str) -> list[bytes]:
    """Les morceaux d'un vocabulaire, vérifié dans la forme qu'écrit build.rs : UTF-8, une ligne par morceau, sans
    blanc, triés (par caractères, comme un BTreeSet de String), sans doublon, fin de ligne finale."""
    try:
        texte = vocabulaire.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Rien(f"{chemin} : pas en UTF-8 ({e})") from e
    if not texte.endswith("\n") or texte == "\n":
        raise Rien(f"{chemin} : vide ou sans fin de ligne finale, pas la forme de build.rs")
    lignes = texte[:-1].split("\n")
    if any(not l or any(x.isspace() for x in l) for l in lignes):
        raise Rien(f"{chemin} : ligne vide ou avec un blanc, pas la forme de build.rs")
    if any(a >= b for a, b in zip(lignes, lignes[1:])):
        raise Rien(f"{chemin} : lignes pas triées ou en double, pas la forme de build.rs")
    return [l.encode("utf-8") for l in lignes]


# Entre deux parts d'un programme (autour d'un bloc retiré, d'un programme à l'autre) : un octet qu'aucun texte UTF-8 ne
# contient. Un morceau, vérifié en UTF-8, ne peut donc jamais se trouver à cheval sur deux parts.
JOINT = b"\xff"


def retirer(parts: list[bytes], bloc: bytes) -> tuple[list[bytes], int]:
    """Les parts sans le bloc (chaque occurrence coupe la part où elle est) ; le nombre d'occurrences retirées."""
    restes, n = [], 0
    for part in parts:
        morceaux_de_part = part.split(bloc)
        n += len(morceaux_de_part) - 1
        restes.extend(morceaux_de_part)
    return restes, n


def ecrivent(fichiers: dict[Path, str], morceau: str) -> list[str]:
    """Les fichiers .rs qui contiennent le morceau tel quel (aide au message)."""
    return [str(f) for f, texte in fichiers.items() if morceau in texte]


def controler(args: argparse.Namespace) -> int:
    programmes = {p: lire(p) for p in args.programmes}
    candidats = {c: lire(c) for c in args.vocabulaire}
    # Le vocabulaire porté : un seul candidat (par ses octets), une seule fois, le même dans chaque programme qui le
    # porte. Un programme où la porte n'est pas servie (Windows aujourd'hui : refus_de_demarrer y rend la porte morte,
    # rustc la retire avec son vocabulaire) n'en porte aucun ; ses textes comptent quand même, ce sont ceux d'un
    # programme publié. Il en faut au moins un qui le porte.
    porte, sans_porte, parts = None, [], {}
    for chemin, octets in programmes.items():
        presents = {v for v in candidats.values() if v in octets}
        if len(presents) > 1:
            raise Rien(f"{chemin} : {len(presents)} des vocabulaires donnés y sont (il en faut un au plus)")
        if not presents:
            sans_porte.append(chemin)
            parts[chemin] = [octets]
            continue
        vocabulaire = presents.pop()
        if porte is not None and vocabulaire != porte:
            raise Rien(f"{chemin} : un autre vocabulaire que celui des autres programmes")
        porte = vocabulaire
        parts[chemin], n = retirer([octets], vocabulaire)
        if n != 1:
            raise Rien(f"{chemin} : le vocabulaire y est {n} fois (il en faut une) : forme non jugée")
    if porte is None:
        raise Rien(
            "aucun des programmes ne porte un des vocabulaires donnés : ce n'est pas le vocabulaire de ces programmes, "
            "ou les programmes ne sont pas ceux de cette compilation"
        )
    nom = next(c for c, v in candidats.items() if v == porte)
    liste = morceaux(porte, nom)
    # Les données embarquées qui ne sont pas des textes du programme : retirées partout ; chacune doit se trouver dans
    # au moins un programme, sinon l'option ne dirait pas ce qu'elle fait.
    for a in args.a_cote:
        if Path(a).name != a or a in (".", ".."):
            raise Rien(f"--a-cote {a} : un nom de fichier, pas un chemin")
    for chemin in args.donnees + [str(Path(nom).parent / a) for a in args.a_cote]:
        bloc = donnee(chemin)
        if not bloc:
            raise Rien(f"{chemin} : donnée vide")
        total = 0
        for programme, liste_parts in parts.items():
            parts[programme], n = retirer(liste_parts, bloc)
            total += n
        if total == 0:
            raise Rien(f"{chemin} : donnée introuvable dans les programmes, pas celle qu'ils embarquent")
    meule = JOINT.join(part for liste_parts in parts.values() for part in liste_parts)
    absents = [m for m in liste if m not in meule]
    if absents:
        print(
            f"✖ vocabulaire de la porte MCP : {len(absents)} morceau(x) sur {len(liste)} dans aucun des programmes "
            f"({', '.join(programmes)}) : une ruse de lecture, du code mort ou une chaîne qui n'est pas un texte du "
            "programme (src/porte_mcp/sources.rs)"
        )
        fichiers = {}
        if args.sources:
            for f in sorted(Path(args.sources).rglob("*.rs")):
                try:
                    fichiers[f] = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
        for m in absents:
            texte = m.decode("utf-8")
            ou = ecrivent(fichiers, texte)
            print(f"  « {texte} »" + (f" ({', '.join(ou[:3])}{', …' if len(ou) > 3 else ''})" if ou else ""))
        return 1
    sans = f" ; sans la porte : {', '.join(sans_porte)}" if sans_porte else ""
    print(f"✔ vocabulaire de la porte MCP : {len(liste)} morceaux, chacun dans un programme publié ({len(programmes)}{sans})")
    return 0


def main() -> int:
    analyse = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    analyse.add_argument("--vocabulaire", action="append", required=True, help="vocabulaire.txt candidat")
    analyse.add_argument("--donnees", action="append", default=[], help="donnée embarquée à retirer")
    analyse.add_argument("--a-cote", action="append", default=[], help="donnée à retirer, dans l'OUT_DIR choisi")
    analyse.add_argument("--sources", help="dossier des sources (aide au message)")
    analyse.add_argument("programmes", nargs="+", help="programmes publiés")
    args = analyse.parse_args()
    try:
        return controler(args)
    except Rien as e:
        print(f"✖ vocabulaire de la porte MCP non vérifié : {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
