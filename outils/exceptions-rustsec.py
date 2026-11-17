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
    python3 -I outils/exceptions-rustsec.py --audit-toml       .cargo/audit.toml comparé à deny.toml
"""

import sys
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def fichier_deny(nom: str) -> Path:
    """Le deny.toml nommé, depuis la racine du dépôt. Un autre nom, un chemin hors du dépôt ou un fichier absent sont
    refusés : jamais lus comme « aucune exception », ni pris ailleurs que dans le dépôt."""
    chemin = (RACINE / nom).resolve()
    if chemin.name != "deny.toml" or not chemin.is_relative_to(RACINE):
        sys.exit(f"✖ {nom} : seul un deny.toml du dépôt donne des exceptions")
    if not chemin.is_file():
        sys.exit(f"✖ {nom} : introuvable, ses exceptions ne sont pas lues")
    return chemin


def exceptions_deny(chemin: Path) -> list[str]:
    """Les identifiants de [advisories] ignore. Une exception d'une autre forme (toute une bibliothèque) n'a pas
    d'équivalent pour cargo audit : refusée plutôt que perdue en route."""
    with open(chemin, "rb") as f:
        exceptions = tomllib.load(f).get("advisories", {}).get("ignore", [])
    identifiants = []
    for e in exceptions:
        ident = e if isinstance(e, str) else e.get("id")
        if not ident:
            sys.exit(
                f"exception de {chemin.relative_to(RACINE)} sans identifiant RustSec, sans équivalent pour cargo"
                f" audit : {e}"
            )
        identifiants.append(ident)
    return identifiants


def main() -> None:
    if sys.argv[1:] == ["--audit-toml"]:
        deny = exceptions_deny(fichier_deny("deny.toml"))
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
    if len(arguments) > 1 or any(a.startswith("-") for a in arguments):
        sys.exit("python3 -I outils/exceptions-rustsec.py [--audit-toml | <deny.toml d'une crate>]")
    deny = exceptions_deny(fichier_deny(arguments[0] if arguments else "deny.toml"))
    if deny:
        print("\n".join(deny))


if __name__ == "__main__":
    main()
