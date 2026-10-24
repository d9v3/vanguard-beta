#!/usr/bin/env python3
"""Fait des tickets GitHub (issues) avec les erreurs du journal de Vanguard : plantages, scripts PowerShell en échec,
vérifications impossibles, scans ratés. Un ticket par erreur ; quand elle revient, un commentaire s'ajoute au ticket
ouvert. Lancé par outils/deployer.sh avec gh, déjà connecté sur l'ordinateur de développement : aucun mot de passe
dans le programme ni sur la clé.

    python3 outils/journal-vers-github.py <fichier des entrées à envoyer>
    python3 outils/journal-vers-github.py --accord <fichier>   l'auteur a regardé ce qui attend : plafonds élargis

Le journal de la clé s'écrit sur n'importe quel ordinateur (la partition VANGUARDLOG est modifiable partout) : un
journal forgé ne doit pas devenir des centaines de tickets publics sous le compte de l'auteur. D'où des plafonds :
par passage (PLAFOND_PASSAGE : tickets créés, commentaires) et par jour (PLAFOND_JOUR, compté dans envois-github.json
à côté du fichier) ; le reste attend, et c'est dit (sortie et notification). Un envoi qui ferait plus de
SIGNATURES_MAX erreurs distinctes n'est pas une suite de vraies erreurs : rien ne part sans l'accord de l'auteur
(--accord). Chaque passage dit ce qu'il a envoyé (sortie, et notification au branchement, où personne ne lit).

Les entrées d'une même erreur (même signature) dans un même envoi partent ensemble : un seul ticket, ou un seul
commentaire qui les réunit (« vu N fois, systèmes…, versions… »), coupé sous la limite d'un corps de GitHub.

Les entrées envoyées sont retirées du fichier ; celles qui n'ont pas pu partir (pas d'Internet) y restent pour le
déploiement suivant. Le journal vient aussi des ordinateurs des autres (la clé l'écrit partout où elle passe) : Vanguard
l'anonymise en l'écrivant (src/journal.rs), puis, avant l'envoi, deux filets (outils/confidentialite.py) : ce qu'il
aurait laissé passer de cet ordinateur-ci, et ce qui pourrait nommer n'importe qui (comptes, courriels, SID, numéros
de série, noms d'appareils et du Wi-Fi ; adresses MAC et IP remplacées, préfixe du fabricant gardé).
"""

import datetime
import hashlib
import json
import os
import re
import signal
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import confidentialite  # noqa: E402

ETIQUETTE = "journal"
# Les écarts de l'autodiagnostic (« [autotest LNX-PFE-001] ») : une étiquette de plus, pour les trier.
ETIQUETTE_AUTOTEST = "autotest"
MASQUE = "‹masqué›"
# GitHub refuse un corps de plus de 65 536 caractères, que certains comptent en octets UTF-8 : marge prise en octets.
CORPS_MAX = 60_000
# Plafonds (voir plus haut) : par passage, par jour, et au-delà duquel rien ne part sans accord. Avec --accord, ceux du
# passage sont multipliés par ACCORD et celui du jour levé.
PLAFOND_PASSAGE = {"tickets": 5, "commentaires": 20}
PLAFOND_JOUR = {"tickets": 10, "commentaires": 40}
SIGNATURES_MAX = 50
ACCORD = 10
COMPTEURS = "envois-github.json"
# Un identifiant de règle ou de lecture (« LNX-PFE-001 », « AUT-LNX-002 ») : gardé tel quel dans la signature.
IDENTIFIANT = re.compile(r"\b[A-Z]{3}-[A-Z]{3}-\d{3}\b")


def entrees(texte):
    """Une entrée commence par « == date · vanguard x · système · langue · commande », puis « [contexte] »."""
    return [b.strip("\n") for b in re.split(r"(?m)^(?=== )", texte) if b.startswith("== ")]


def signature(entree):
    """Contexte, première ligne du détail, et une empreinte qui ignore les nombres (délais, codes, lignes) et les
    adresses : leurs remplaçants sont tirés au hasard à chaque envoi, la même erreur doit retrouver son ticket."""
    lignes = entree.splitlines()
    contexte = lignes[1].strip() if len(lignes) > 1 else ""
    detail = next((l.strip() for l in lignes[2:] if l.strip()), "")
    stable = f"{contexte} {detail}"
    for adresse in (confidentialite.MAC, confidentialite.MAC_TIRETS, confidentialite.IPV6, confidentialite.IPV4):
        stable = adresse.sub("<adresse>", stable)
    # Les identifiants à part : sans cela, « AUT-LNX-001 » et « AUT-LNX-002 » devenaient tous deux « AUT-LNX-# », et
    # deux lectures différentes tombaient dans le même ticket.
    morceaux = IDENTIFIANT.split(stable)
    ids = IDENTIFIANT.findall(stable)
    stable = "".join(re.sub(r"\d+", "#", m) + (ids[i] if i < len(ids) else "") for i, m in enumerate(morceaux))
    return contexte, detail, hashlib.sha1(stable.encode()).hexdigest()[:12]


def bloc(texte):
    """Le texte dans un bloc de code Markdown, dont la clôture est plus longue que toute suite de « ` » du texte : une
    entrée qui contient « ``` » ne doit pas sortir du bloc (une mention « @ » préviendrait alors quelqu'un)."""
    longueur = max([3] + [len(m) + 1 for m in re.findall(r"`{3,}", texte)])
    return f"{'`' * longueur}\n{texte}\n{'`' * longueur}"


def sans_arobase(texte):
    """« @ » devient « ＠ » (pleine chasse, qui se lit pareil). Ces tickets partent du compte du propriétaire du dépôt,
    et .github/workflows/claude.yml lance Claude, droits d'écriture compris, dès qu'un ticket ou un commentaire du
    propriétaire contient « @claude » : il cherche le texte tel quel, bloc de code ou non. Un nom de réseau ou de
    fichier venu d'un autre ordinateur ne doit pas pouvoir lui donner une consigne."""
    return texte.replace("@", "＠")


def en_tete(entree):
    """(version, système) de la ligne « == date · vanguard x · système · langue · commande »."""
    champs = entree.splitlines()[0].split(" · ")
    version = champs[1].removeprefix("vanguard ").strip() if len(champs) > 1 else "?"
    systeme = champs[2].strip() if len(champs) > 2 else "?"
    return version, systeme


def borne(texte, limite=CORPS_MAX):
    """Le texte coupé à `limite` octets UTF-8 (sans couper un caractère), et dit s'il l'a été."""
    octets = texte.encode("utf-8")
    if len(octets) <= limite:
        return texte
    note = "\n\n[… coupé : le corps dépassait la limite de GitHub]"
    garde = octets[: limite - len(note.encode("utf-8"))].decode("utf-8", errors="ignore")
    return garde + note


def corps_groupe(groupe):
    """Le corps d'un groupe d'entrées de même signature : une seule, ou « vu N fois » puis chacune dans son bloc."""
    if len(groupe) == 1:
        return bloc(groupe[0])
    versions = sorted({en_tete(e)[0] for e in groupe})
    systemes = sorted({en_tete(e)[1] for e in groupe})
    resume = (f"Vu {len(groupe)} fois dans cet envoi ; systèmes : {', '.join(systemes)} ; "
              f"versions : {', '.join(versions)}.")
    return resume + "\n\n" + "\n\n".join(bloc(e) for e in groupe)


def gh(*args):
    """gh, borné à une minute ; trop long, c'est un échec (code 124), pas une exception qui perdrait l'état."""
    try:
        return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "délai dépassé")


def remplacer(chemin, texte):
    """Écrit à côté puis remplace : un passage arrêté en route ne laisse pas un fichier à moitié écrit."""
    with open(chemin + ".nouveau", "w", encoding="utf-8") as f:
        f.write(texte)
    os.replace(chemin + ".nouveau", chemin)


def dire(titre, texte):
    """Sur la sortie, et par une notification : au branchement de la clé (deployer.sh), personne ne lit la sortie."""
    print(f"{titre} : {texte}")
    try:
        subprocess.run(["notify-send", "-a", "Vanguard", "-i", "vanguard", titre, texte],
                       capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


def lire_compteurs(chemin, jour):
    """Les envois du jour (tickets, commentaires) ; remis à zéro chaque jour, et si le fichier est illisible."""
    try:
        with open(chemin, encoding="utf-8") as f:
            c = json.load(f)
        if c.get("jour") == jour and all(isinstance(c.get(k), int) for k in PLAFOND_JOUR):
            return c
    except (OSError, ValueError, AttributeError):
        pass
    return {"jour": jour, **{k: 0 for k in PLAFOND_JOUR}}


def main():
    arguments = sys.argv[1:]
    accord = "--accord" in arguments
    arguments = [a for a in arguments if a != "--accord"]
    chemin = arguments[0]
    with open(chemin, encoding="utf-8") as f:
        liste = entrees(f.read())
    if not liste:
        return
    gh("label", "create", ETIQUETTE, "--color", "B60205",
       "--description", "Erreur rapportée par le journal de Vanguard", "--force")
    gh("label", "create", ETIQUETTE_AUTOTEST, "--color", "5319E7",
       "--description", "Écart trouvé par l'autodiagnostic de Vanguard", "--force")
    # Ticket de chaque erreur, noté ici : la recherche de GitHub met quelques minutes à voir un ticket tout neuf, et
    # deux déploiements rapprochés feraient sinon deux tickets.
    notes = os.path.join(os.path.dirname(os.path.abspath(chemin)), "tickets-github.json")
    try:
        with open(notes, encoding="utf-8") as f:
            ouverts = json.load(f)
    except (OSError, ValueError):
        ouverts = {}
    restantes = []
    personnel = confidentialite.Detecteur(confidentialite.termes()).motif
    # Un même réseau inventé pour tout l'envoi : les tickets d'une même maison restent comparables entre eux.
    masque = confidentialite.Masque(liste)
    # D'abord nettoyer chaque entrée et la ranger par signature, dans l'ordre de leur première apparition.
    groupes = {}
    for e in liste:
        if personnel:
            e, n = personnel.subn(MASQUE, e)
            if n:
                print(f"Journal : {n} détail(s) personnel(s) masqué(s) avant l'envoi : l'anonymisation de journal.rs "
                      "les a laissés passer.", file=sys.stderr)
        e = confidentialite.masquer_autrui(e, masque)
        # La signature d'abord, sur le texte tel quel : une erreur déjà envoyée retrouve son ticket.
        contexte, detail, sig = signature(e)
        e, contexte, detail = sans_arobase(e), sans_arobase(contexte), sans_arobase(detail)
        groupes.setdefault(sig, (contexte, detail, []))[2].append(e)
    dossier = os.path.dirname(os.path.abspath(chemin))
    if len(groupes) > SIGNATURES_MAX and not accord:
        # Rien n'est envoyé ni retiré : le fichier attend l'accord de l'auteur.
        dire("Vanguard : journal à regarder avant tout envoi",
             f"{len(groupes)} erreurs distinctes ({len(liste)} entrées) : plus que les {SIGNATURES_MAX} d'un vrai "
             f"journal ; peut-être forgé sur un autre ordinateur. Rien n'est envoyé sur GitHub. À regarder : {chemin} ; "
             f"pour l'envoyer quand même : python3 outils/journal-vers-github.py --accord {chemin}")
        return
    compteurs_chemin = os.path.join(dossier, COMPTEURS)
    compteurs = lire_compteurs(compteurs_chemin, datetime.date.today().isoformat())
    faits = {k: 0 for k in PLAFOND_PASSAGE}

    def reste(sorte):
        """Combien de tickets (ou commentaires) peuvent encore partir dans ce passage."""
        passage = PLAFOND_PASSAGE[sorte] * (ACCORD if accord else 1) - faits[sorte]
        if accord:
            return passage
        return min(passage, PLAFOND_JOUR[sorte] - compteurs[sorte])

    plafonnees = 0
    faites = set()

    def garder():
        """Ce qui n'est pas parti (envois ratés ou plafonnés, et les groupes pas encore faits), les tickets connus,
        les compteurs du jour : après chaque envoi et quand le passage est arrêté (SIGTERM du timeout de deployer.sh,
        panne), pour que le suivant ne refasse ni ne recompte rien."""
        reste = restantes + [e for s, (_, _, g) in groupes.items() if s not in faites for e in g]
        remplacer(chemin, "".join(x + "\n\n" for x in reste))
        remplacer(notes, json.dumps(ouverts, indent=1))
        remplacer(compteurs_chemin, json.dumps(compteurs))
        return reste

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        for sig, (contexte, detail, groupe) in groupes.items():
            plafonnees += envoyer_groupe(sig, contexte, detail, groupe, ouverts, restantes, reste, faits, compteurs)
            faites.add(sig)
            garder()
    finally:
        restantes = garder()
    envoyees = len(liste) - len(restantes)
    attente = f", {len(restantes)} en attente" if restantes else ""
    print(f"Journal : {envoyees} erreur(s) envoyée(s) sur GitHub{attente}.")
    if faits["tickets"] or faits["commentaires"]:
        dire("Vanguard : journal envoyé sur GitHub",
             f"{faits['tickets']} ticket(s) créé(s), {faits['commentaires']} commentaire(s) (étiquette « {ETIQUETTE} »).")
    if plafonnees:
        dire("Vanguard : envoi du journal plafonné",
             f"{plafonnees} erreur(s) distincte(s) attendent (au plus {PLAFOND_PASSAGE['tickets']} tickets et "
             f"{PLAFOND_PASSAGE['commentaires']} commentaires par passage, {PLAFOND_JOUR['tickets']} et "
             f"{PLAFOND_JOUR['commentaires']} par jour) : {chemin}")


def envoyer_groupe(sig, contexte, detail, groupe, ouverts, restantes, reste, faits, compteurs):
    """Un groupe d'entrées de même signature : un ticket, ou un commentaire au sien. Ce qui ne part pas va dans
    `restantes`. Rend 1 si le plafond l'a retenu."""
    marque = f"vanguard-signature-{sig}"
    etiquettes = [ETIQUETTE] + ([ETIQUETTE_AUTOTEST] if contexte.startswith("[autotest ") else [])
    numero = ouverts.get(sig)
    # Ticket fermé (erreur corrigée) : si elle revient, c'est un nouveau ticket.
    if numero and gh("issue", "view", numero, "--json", "state", "-q", ".state").stdout.strip() != "OPEN":
        numero = None
    if numero is None:
        r = gh("issue", "list", "--label", ETIQUETTE, "--state", "open", "--search", f"{marque} in:body",
               "--json", "number", "-q", ".[0].number")
        if r.returncode != 0:
            restantes.extend(groupe)
            return 0
        numero = r.stdout.strip() or None
        if numero:
            ouverts[sig] = numero
    sorte = "commentaires" if numero else "tickets"
    if reste(sorte) <= 0:
        # Plafond du passage ou du jour : l'erreur attend le passage suivant, et c'est dit plus bas.
        restantes.extend(groupe)
        return 1
    if numero:
        r = gh("issue", "comment", numero, "--body", borne(f"Encore vu :\n\n{corps_groupe(groupe)}"))
    else:
        fin = f"\n\n<!-- {marque} -->"
        args = ["issue", "create", "--title", f"{contexte} {detail}"[:120],
                "--body", borne(corps_groupe(groupe), CORPS_MAX - len(fin.encode("utf-8"))) + fin]
        for t in etiquettes:
            args += ["--label", t]
        r = gh(*args)
        if r.returncode == 0:
            ouverts[sig] = r.stdout.strip().rsplit("/", 1)[-1]
    if r.returncode == 0:
        faits[sorte] += 1
        compteurs[sorte] += 1
    else:
        restantes.extend(groupe)
    return 0


if __name__ == "__main__":
    main()
