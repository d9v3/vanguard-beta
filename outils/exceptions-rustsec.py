#!/usr/bin/env python3
"""Les avis admis, lus dans le deny.toml de chaque crate, le seul endroit où ils s'écrivent, avec leur raison.

cargo deny les lit là ; cargo audit n'a pas de deny.toml, il les reçoit d'ici : par --ignore (outils/verifier.sh,
outils/failles-programmes.sh) et par .cargo/audit.toml, que lisent un cargo audit lancé à la main et la vérification
de nuit de la CI. Ce fichier-là n'est qu'une copie des identifiants de deny.toml : --audit-toml refuse qu'il en ait un
de plus ou de moins, pour qu'une exception ne passe jamais en douce par cargo audit, ni ne s'y perde.
Chaque crate à part (fenêtre, banc de fuzzing, extensions) a son deny.toml : son Cargo.lock et ses programmes ne
reçoivent que les exceptions de celui-là, jamais celles de Vanguard (rsa et bincode, venues de YARA-X).
    python3 -I outils/exceptions-rustsec.py                    un identifiant RustSec par ligne, ceux de deny.toml
    python3 -I outils/exceptions-rustsec.py fenetre/deny.toml  ceux du deny.toml d'une crate (chemin depuis la racine)
    python3 -I outils/exceptions-rustsec.py --programmes deny.toml
                                                               celles qui valent pour les programmes publiés : leur
                                                               raison dit « vaut pour les programmes publiés » (sans
                                                               ces mots : non ; rsa et bincode, de développement) ;
                                                               sans date de relecture lisible, refusée
    python3 -I outils/exceptions-rustsec.py --relire deny.toml celles dont la date de relecture est passée, en clair
    python3 -I outils/exceptions-rustsec.py --audit-toml       .cargo/audit.toml comparé à deny.toml
"""

import datetime
import re
import sys
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
# Les mots exacts qui font valoir une exception pour les programmes publiés, et la date où la relire.
POUR_LES_PROGRAMMES = "vaut pour les programmes publiés"
A_RELIRE = re.compile(r"à relire au plus tard le (\d{4}-\d{2}-\d{2})")


def fichier_deny(nom: str) -> Path:
    """Le deny.toml nommé, depuis la racine du dépôt. Un autre nom, un chemin hors du dépôt ou un fichier absent sont
    refusés : jamais lus comme « aucune exception », ni pris ailleurs que dans le dépôt."""
    chemin = (RACINE / nom).resolve()
    if chemin.name != "deny.toml" or not chemin.is_relative_to(RACINE):
        sys.exit(f"✖ {nom} : seul un deny.toml du dépôt donne des exceptions")
    if not chemin.is_file():
        sys.exit(f"✖ {nom} : introuvable, ses exceptions ne sont pas lues")
    return chemin


def exceptions_deny(chemin: Path) -> list[tuple[str, str]]:
    """Les identifiants et les raisons de [advisories] ignore. Une exception d'une autre forme (toute une bibliothèque)
    n'a pas d'équivalent pour cargo audit : refusée plutôt que perdue en route."""
    with open(chemin, "rb") as f:
        exceptions = tomllib.load(f).get("advisories", {}).get("ignore", [])
    lues = []
    for e in exceptions:
        ident = e if isinstance(e, str) else e.get("id")
        if not ident:
            sys.exit(
                f"exception de {chemin.relative_to(RACINE)} sans identifiant RustSec, sans équivalent pour cargo"
                f" audit : {e}"
            )
        lues.append((ident, "" if isinstance(e, str) else e.get("reason", "")))
    return lues


def a_relire(exceptions: list[tuple[str, str]], jour: datetime.date) -> list[str]:
    """Les exceptions dont la date de relecture est passée. Une date impossible (31 février) compte comme passée :
    jamais lue comme « pas de date »."""
    dites = []
    for ident, raison in exceptions:
        for date in A_RELIRE.findall(raison):
            try:
                passee = datetime.date.fromisoformat(date) < jour
            except ValueError:
                passee = True
            if passee:
                dites.append(f"{ident} ({raison.split(',')[0]}) : à relire depuis le {date}")
    return dites


def sans_date(raison: str) -> bool:
    """Aucune date de relecture lisible : une faute de frappe la rendrait éternelle, et rien ne le dirait."""
    dates = A_RELIRE.findall(raison)
    try:
        return not [datetime.date.fromisoformat(date) for date in dates]
    except ValueError:
        return True


def main() -> None:
    if sys.argv[1:] == ["--audit-toml"]:
        deny = [ident for ident, _ in exceptions_deny(fichier_deny("deny.toml"))]
        chemin = RACINE / ".cargo" / "audit.toml"
        with open(chemin, "rb") as f:
            audit = tomllib.load(f).get("advisories", {}).get("ignore", [])
        if sorted(audit) != sorted(deny):
            sys.exit(
                f"✖ .cargo/audit.toml n'admet pas les mêmes failles que deny.toml : {sorted(audit)} contre "
                f"{sorted(deny)}. deny.toml fait foi (la raison y est) ; .cargo/audit.toml en recopie les identifiants."
            )
        return
    arguments = sys.argv[1:]
    mode = arguments[0] if arguments and arguments[0] in ("--programmes", "--relire") else ""
    if mode:
        arguments = arguments[1:]
        if not arguments:
            sys.exit(f"python3 -I outils/exceptions-rustsec.py {mode} <deny.toml d'une crate>")
    if len(arguments) > 1 or any(a.startswith("-") for a in arguments):
        sys.exit(
            "python3 -I outils/exceptions-rustsec.py [--audit-toml | [--programmes | --relire] <deny.toml d'une crate>]"
        )
    exceptions = exceptions_deny(fichier_deny(arguments[0] if arguments else "deny.toml"))
    if mode == "--relire":
        lignes = a_relire(exceptions, datetime.date.today())
    else:
        retenues = [(ident, raison) for ident, raison in exceptions if not mode or POUR_LES_PROGRAMMES in raison]
        fautives = [ident for ident, raison in retenues if mode and sans_date(raison)]
        if fautives:
            sys.exit(
                f"✖ {', '.join(fautives)} : admise pour les programmes publiés sans date lisible"
                " (« à relire au plus tard le AAAA-MM-JJ »)"
            )
        lignes = [ident for ident, _ in retenues]
    if lignes:
        print("\n".join(lignes))


if __name__ == "__main__":
    main()
