#!/bin/bash
# Essai complet de Vanguard sur un vrai Mac (celui de GitHub, voir .github/workflows/macos.yml, option
# « essai_complet »). Chaque commande est lancée sans interaction (réponses fournies), avec un délai maximal ;
# sorties, codes de retour et vérifications vont dans le dossier de résultats, téléchargé ensuite.
#   outils/test-macos/essai.sh <programme vanguard> <dossier de résultats>
# Pas de scan du réseau local : celui de GitHub ne nous appartient pas (seulement 127.0.0.1).
set -u
VANGUARD=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
RES=$2
mkdir -p "$RES"
RES=$(cd "$RES" && pwd)
export VANGUARD_LANG=fr
JOURNAL="$RES/journal.txt"

# Le journal garde le détail (relu par le rapport HTML) ; l'écran montre une ligne par commande ou vérification.
note() { echo "$*" >>"$JOURNAL"; printf '      \033[90m%s\033[0m\n' "$*"; }
titre() { echo "=== $* ===" >>"$JOURNAL"; printf '\n  \033[1;31mTEST DE VANGUARD\033[0m  \033[90m%s\033[0m\n' "$*"; }
bilan() {
  local ok bug
  ok=$(grep -c '^OK' "$JOURNAL")
  bug=$(grep -c '^ÉCHEC' "$JOURNAL")
  echo "=== Fin : $ok vérification(s) OK, $bug échec(s) ===" >>"$JOURNAL"
  printf '\n  ──────────────────────────────────────────────────────────\n'
  if [ "$bug" = 0 ]; then printf '  \033[32m✓ Tout est passé : %s vérification(s) réussie(s).\033[0m\n' "$ok"
  else printf '  \033[31m✗ %s problème(s) ; %s vérification(s) réussie(s).\033[0m\n' "$bug" "$ok"; fi
}
section() { echo "--- $*" >>"$JOURNAL"; printf '\n  \033[1;36m▸ %s\033[0m\n' "$*"; }
ecran_commande() { # ecran_commande <code> <secondes> <arguments…>
  local code=$1 duree=$2
  shift 2
  local texte="vanguard $*"
  [ $# = 0 ] && texte="vanguard (menu)"
  texte=$(echo "$texte" | sed -E 's#[^ ]*/([^/ ]+)#\1#g')
  [ ${#texte} -gt 58 ] && texte="${texte:0:57}…"
  if [ "$code" = 0 ]; then
    printf '      %-60s \033[32m✓\033[0m \033[90m%4s s\033[0m\n' "$texte" "$duree"
  else
    printf '      %-60s \033[31m✗ code %s\033[0m \033[90m%4s s\033[0m\n' "$texte" "$code" "$duree"
  fi
}
# contient <fichier> <texte> : le texte replié à 76 colonnes est cherché mots remis bout à bout, couleurs retirées.
contient() { python3 -c "import re,sys; t=' '.join(re.sub(r'\x1b\[[0-9;]*m', '', open(sys.argv[1],encoding='utf-8').read()).split()); sys.exit(0 if sys.argv[2] in t else 1)" "$1" "$2"; }
# contient_motif <fichier> <expression> : de même, pour une expression régulière de Python.
contient_motif() { python3 -c "import re,sys; t=' '.join(re.sub(r'\x1b\[[0-9;]*m', '', open(sys.argv[1],encoding='utf-8').read()).split()); sys.exit(0 if re.search(sys.argv[2], t) else 1)" "$1" "$2"; }
# macOS n'a pas la commande timeout : perl s'en charge (alarme puis exec).
delai() { perl -e 'alarm shift; exec @ARGV' "$@"; }

# lancer <nom> <secondes> <entrée> <arguments…> : sortie dans <nom>.txt, code et durée dans le journal.
lancer() {
  local nom=$1 secondes=$2 entree=$3
  shift 3
  local debut=$SECONDS
  printf '%b' "$entree" | delai "$secondes" "$VANGUARD" "$@" >"$RES/$nom.txt" 2>&1
  local code=$?
  echo "vanguard $* -> code $code, $((SECONDS - debut)) s$([ $code = 142 ] && echo ' (DÉLAI DÉPASSÉ)') · $nom.txt" >>"$JOURNAL"
  ecran_commande "$code" "$((SECONDS - debut))" "$@"
}

verifier() { # verifier <description> <commande…>
  local d=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "OK      $d" >>"$JOURNAL"
    printf '      \033[32m✓\033[0m %s\n' "$d"
  else
    echo "ÉCHEC   $d" >>"$JOURNAL"
    printf '      \033[31m✗ %s\033[0m\n' "$d"
  fi
}

# mettre_empreinte_essai <copie des empreintes> <empreinte> : l'empreinte ajoutée sur une ligne à part (même si la
# copie ne finit pas par un saut de ligne). La copie d'avant est gardée à côté, heure comprise ; sans copie, elle est
# posée pour l'essai. remettre_empreintes <copie> rend tout comme avant, et le vérifie.
mettre_empreinte_essai() {
  local copie=$1
  EMPREINTES_AVANT=
  DOSSIER_EMPREINTES_POSE=0
  if [ -e "$copie" ]; then
    EMPREINTES_AVANT=$(mktemp "${TMPDIR:-/tmp}/vanguard-empreintes-XXXXXX")
    cp -p "$copie" "$EMPREINTES_AVANT"
    note "empreintes : copie gardée déjà là, complétée pour l'essai"
  else
    [ -d "${copie%/*}" ] || { mkdir -p "${copie%/*}" && DOSSIER_EMPREINTES_POSE=1; }
    note "empreintes : aucune copie gardée (sans clé abuse.ch, rien ne se télécharge), posée pour l'essai"
  fi
  { echo; echo "$2"; } >>"$copie"
}
remettre_empreintes() {
  local copie=$1
  if [ -n "$EMPREINTES_AVANT" ]; then
    cp -p "$EMPREINTES_AVANT" "$copie"
    verifier "empreintes : copie gardée remise comme avant, heure comprise" \
      bash -c 'cmp -s "$1" "$2" && [ ! "$1" -nt "$2" ] && [ ! "$2" -nt "$1" ]' _ "$EMPREINTES_AVANT" "$copie"
    rm -f "$EMPREINTES_AVANT"
  else
    rm -f "$copie"
    [ "$DOSSIER_EMPREINTES_POSE" = 1 ] && rmdir "${copie%/*}" 2>/dev/null
    verifier "empreintes : copie posée pour l'essai retirée" test ! -e "$copie"
  fi
}

titre "Essai complet de Vanguard sur macOS $(sw_vers -productVersion) ($(uname -m))"
lancer version 10 '' --version
lancer aide 10 '' --help

section "Audit"
lancer machine 300 '' audit
lancer machine-json 300 '' audit --json
verifier "audit JSON lisible" python3 -c "import json; json.load(open('$RES/machine-json.txt'))"
# Seule exception : COM-CPT-003 quand sshd est là (Session à distance allumée sur les Mac de GitHub) : son journal
# unifié n'est pas lu, et « non vérifié » est alors la réponse juste, pas un défaut.
verifier "aucune vérification impossible" python3 -c "
import json,sys; a=json.load(open('$RES/machine-json.txt'))
admis=[c for c in a['constats'] if not c['verifie'] and c.get('regle')=='COM-CPT-003' and 'sshd' in c['message']]
bad=[c['categorie']+': '+c['message'] for c in a['constats'] if not c['verifie'] and c not in admis]
print('\n'.join(['admis : '+c['message'] for c in admis]+bad)); sys.exit(1 if bad else 0)"
# Les règles de la 0.80 : XProtect et les profils de configuration, lus et vérifiés sur ce vrai Mac.
for regle in MAC-ANV-001 MAC-PRF-001; do
  verifier "bilan : $regle lue et vérifiée" python3 -c "
import json,sys; a=json.load(open('$RES/machine-json.txt'))
c=[x for x in a['constats'] if x.get('regle')=='$regle']
print(c); sys.exit(0 if c and all(x['verifie'] for x in c) else 1)"
done

section "Diagnostic"
lancer diagnostic 120 '' diagnostic
verifier "diagnostic : section MATÉRIEL" grep -q 'MATÉRIEL' "$RES/diagnostic.txt"
lancer fiche-json 60 '' fiche-ordinateur --json

section "Lectures en Rust (0.82) : les mêmes réponses que les outils d'Apple"
# Depuis la 0.82, Vanguard lit lui-même les plist, sysctl, les noms du Mac, la place libre et les administrateurs, au
# lieu de lancer defaults, plutil, sw_vers, sysctl, scutil, dscl et df. Ces outils servent ici de référence : chaque
# verdict du bilan, de la fiche et du diagnostic doit dire ce qu'ils disent. Le détail va dans comparaisons.txt.
COMPARER="$RES/comparer.py"
cat >"$COMPARER" <<'FIN'
import json, os, plistlib, re, subprocess, sys

cas, res = sys.argv[1], sys.argv[2]
constats = json.load(open(f"{res}/machine-json.txt", encoding="utf-8"))["constats"]


def noter(*texte):
    with open(f"{res}/comparaisons.txt", "a", encoding="utf-8") as f:
        f.write(f"{cas} : " + " | ".join(map(str, texte)) + "\n")


def sortie(*commande):
    r = subprocess.run(commande, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def defaults(domaine, cle):
    return sortie("defaults", "read", domaine, cle)


def de(regle, motif=""):
    return [c for c in constats if c.get("regle") == regle and motif in c["message"]]


def verdict(liste):
    if not liste:
        return "absent"
    return "probleme" if any(c["probleme"] for c in liste) else "ok"


def comparer(attendu, vu, *detail):
    noter(f"attendu {attendu}", f"vu {vu}", *detail)
    sys.exit(0 if attendu == vu else 1)


LOGIN = "/Library/Preferences/com.apple.loginwindow"
if cas == "airdrop":
    mode = defaults("com.apple.sharingd", "DiscoverableMode")
    attendu = "absent" if mode is None else "probleme" if mode.startswith("Everyone") else "ok"
    vus = de("MAC-PAR-001")
    comparer(attendu, verdict(vus), mode, [c["message"] for c in vus])
elif cas == "session-auto":
    compte = defaults(LOGIN, "autoLoginUser")
    comparer(compte is not None, bool(de("MAC-SES-002", "s'ouvre toute seule")), compte)
elif cas == "invite":
    invite = defaults(LOGIN, "GuestEnabled")
    comparer(invite == "1", bool(de("MAC-SES-002", "compte invité est activé")), invite)
elif cas == "maj-auto":
    domaine = "/Library/Preferences/com.apple.SoftwareUpdate"
    coupes = [c for c in ("AutomaticCheckEnabled", "CriticalUpdateInstall", "ConfigDataInstall") if defaults(domaine, c) == "0"]
    vus = de("MAC-MAJ-001")
    comparer("probleme" if coupes else "ok", verdict(vus), coupes, [c["message"] for c in vus])
elif cas == "bibliotheques":
    valeur = defaults("/Library/Preferences/com.apple.security.libraryvalidation", "DisableLibraryValidation")
    vus = de("MAC-SYS-002", "alidation des bibliothèques")
    comparer("probleme" if valeur == "1" else "ok", verdict(vus), valeur)
elif cas == "xprotect":
    bases = [
        "/private/var/protected/xprotect/XProtect.bundle/Contents/Info",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info",
    ]
    dates = []
    for b in bases:
        try:
            dates.append((os.stat(f"{b}.plist").st_mtime, b))
        except OSError:
            pass
    base = max(dates)[1] if dates else None
    version = defaults(base, "CFBundleShortVersionString") if base else None
    vus = de("MAC-ANV-001")
    juste = bool(vus) and all(c["verifie"] for c in vus) and (version is None or f"(version {version})" in vus[0]["message"])
    comparer(True, juste, base, version, [c["message"] for c in vus])
elif cas == "time-machine":
    texte = sortie("defaults", "export", "/Library/Preferences/com.apple.TimeMachine", "-")
    try:
        destinations = plistlib.loads(texte.encode()).get("Destinations", []) if texte else []
    except Exception:
        destinations = []
    non_chiffrees = sum(d.get("LastKnownEncryptionState") == "NotEncrypted" for d in destinations)
    comparer(non_chiffrees > 0, bool(de("MAC-SAV-002")), f"{len(destinations)} destination(s), {non_chiffrees} non chiffrée(s)")
elif cas == "admins":
    texte = sortie("dscl", ".", "-read", "/Groups/admin", "GroupMembership") or ""
    admins = [n for n in texte.split()[1:] if n != "root" and not n.startswith("_")]
    vus = de("MAC-CPT-001")
    message = vus[0]["message"] if vus else ""
    juste = bool(vus) and all(n in message for n in admins) and (len(admins) <= 2 or message.startswith(f"{len(admins)} comptes"))
    comparer(True, juste, admins, message)
elif cas == "persistance":
    agents = []
    for dossier in (os.path.expanduser("~/Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"):
        for nom in sorted(os.listdir(dossier)) if os.path.isdir(dossier) else []:
            if not nom.endswith(".plist"):
                continue
            try:
                with open(os.path.join(dossier, nom), "rb") as f:
                    r = plistlib.load(f)
            except Exception:
                continue
            arguments = [a for a in r.get("ProgramArguments", []) if isinstance(a, str)]
            if isinstance(r.get("Program"), str) or arguments:
                agents.append(nom[: -len(".plist")])
    vus = de("MAC-PRS-001")
    if any(c["probleme"] for c in vus):
        juste = all(c["verifie"] for c in vus)
    elif agents:
        juste = bool(vus) and vus[0]["message"].startswith(f"{len(agents)} programme(s) tiers")
    else:
        juste = bool(vus) and vus[0]["message"].startswith("Aucun programme tiers")
    comparer(True, juste, f"{len(agents)} agent(s) : {', '.join(agents)}", [c["message"] for c in vus])
elif cas == "place-libre":
    point = "/System/Volumes/Data" if os.path.isdir("/System/Volumes/Data") else "/"
    lignes = (sortie("df", "-k", "-P", point) or "").splitlines()
    libre = int(lignes[1].split()[3]) * 1024 if len(lignes) > 1 else 0
    vus = [c for c in constats if c["categorie"] == "Santé" and ("Espace disque" in c["message"] or "presque plein" in c["message"])]
    m = re.search(r"(\d+(?:,\d+)?)\s(To|Go)", vus[0]["message"]) if vus else None
    lu = float(m.group(1).replace(",", ".")) * 1024 ** (4 if m.group(2) == "To" else 3) if m else 0
    juste = libre > 0 and 0.85 < lu / libre < 1.15
    comparer(True, juste, f"df : {libre} octets", f"Vanguard : {lu:.0f} octets", [c["message"] for c in vus])
elif cas == "fiche":
    fiche = json.load(open(f"{res}/fiche-json.txt", encoding="utf-8"))
    version, build = sortie("sw_vers", "-productVersion"), sortie("sw_vers", "-buildVersion")
    memoire = int(sortie("sysctl", "-n", "hw.memsize") or 0)
    juste = version in fiche["systeme"] and build in fiche["systeme"] and fiche["memoire"] == memoire
    comparer(True, juste, version, build, memoire, fiche["systeme"], fiche["memoire"])
elif cas == "diagnostic":
    texte = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", open(f"{res}/diagnostic.txt", encoding="utf-8").read()).split())
    attendus = [
        sortie("sw_vers", "-productVersion"),
        sortie("sw_vers", "-buildVersion"),
        sortie("scutil", "--get", "ComputerName"),
        " ".join((sortie("sysctl", "-n", "machdep.cpu.brand_string") or "").split()),
        "Allumé depuis",
    ]
    manquants = [a for a in attendus if a and a not in texte]
    comparer([], manquants, attendus)
elif cas == "sans-outils":
    cites = [c["message"] for c in constats if not c["verifie"] and re.search(r"\b(defaults|plutil|sw_vers)\b", c["message"])]
    comparer([], cites)
FIN
for cas in airdrop session-auto invite maj-auto bibliotheques xprotect time-machine admins persistance place-libre fiche diagnostic sans-outils; do
  verifier "Rust contre Apple : $cas" python3 -I "$COMPARER" "$cas" "$RES"
done

section "Persistance (0.82) : un dossier d'agents illisible est dit « non vérifié », en le nommant"
# Un dossier d'agents refusé (un intrus devenu root peut le mettre en 000 : launchd le lit toujours) n'est plus parcouru
# comme vide : le bilan le nomme, non vérifié, et ne dit jamais « aucun programme tiers ». Droits remis aussitôt.
AGENTS="$HOME/Library/LaunchAgents"
AGENTS_CREE=0
[ -d "$AGENTS" ] || { mkdir -p "$AGENTS"; AGENTS_CREE=1; }
DROITS_AGENTS=$(stat -f '%Lp' "$AGENTS")
chmod 000 "$AGENTS"
lancer machine-agents-illisibles 300 '' audit --json
chmod "$DROITS_AGENTS" "$AGENTS"
[ "$AGENTS_CREE" = 1 ] && rmdir "$AGENTS"
verifier "persistance : $AGENTS dit illisible, non vérifié" python3 -I -c "
import json, sys
a = json.load(open(sys.argv[1], encoding='utf-8'))
c = [x for x in a['constats'] if x['categorie'] == 'Persistance' and not x['verifie'] and 'illisibles' in x['message'] and sys.argv[2] in x['message']]
print(c); sys.exit(0 if c else 1)" "$RES/machine-agents-illisibles.txt" "$AGENTS"
verifier "persistance : jamais « aucun programme tiers » avec un dossier illisible" python3 -I -c "
import json, sys
a = json.load(open(sys.argv[1], encoding='utf-8'))
sys.exit(1 if any('Aucun programme tiers' in x['message'] for x in a['constats']) else 0)" "$RES/machine-agents-illisibles.txt"
verifier "persistance : droits du dossier d'agents remis" bash -c "[ ! -e '$AGENTS' ] || [ \"\$(stat -f '%Lp' '$AGENTS')\" = '$DROITS_AGENTS' ]"

section "Administrateurs (0.82) : la liste lue, montrée comme avant"
# Une liste vide passe à dscl, puis « impossible » : ici, le compte du runner (administrateur) doit être cité, le
# constat vérifié, et l'écran dire la même chose que le JSON.
verifier "administrateurs : MAC-CPT-001 vérifié, à l'écran comme dans le JSON" python3 -I -c "
import json, re, subprocess, sys
a = json.load(open(sys.argv[1], encoding='utf-8'))
c = [x for x in a['constats'] if x.get('regle') == 'MAC-CPT-001']
ecran = ' '.join(re.sub(r'\x1b\[[0-9;]*m', '', open(sys.argv[2], encoding='utf-8').read()).split())
admin = 'admin' in subprocess.run(['id', '-Gn'], capture_output=True, text=True).stdout.split()
ok = bool(c) and all(x['verifie'] for x in c) and not any('aucune personne' in x['message'] for x in c)
ok = ok and (not admin or any(sys.argv[3] in x['message'] for x in c))
ok = ok and all(' '.join(x['message'].split()) in ecran for x in c)
print(admin, c); sys.exit(0 if ok else 1)" "$RES/machine-json.txt" "$RES/machine.txt" "$USER"

section "Audit du réseau (0.82), sans rien envoyer hors de ce Mac : six domaines, Wi-Fi dit illisible d'ici"
# Le réseau de GitHub ne nous appartient pas : l'audit tourne dans un bac à sable sans réseau (sandbox-exec, le profil
# d'« isoler »), il ne sonde personne. Les lectures locales se font ; ce qui demande le réseau doit être dit non vérifié.
SANS_RESEAU="$RES/sans-reseau.sb"
printf '(version 1)\n(allow default)\n(deny network*)\n' >"$SANS_RESEAU"
ISOLE="$RES/vanguard-sans-reseau.sh"
printf '#!/bin/sh\nexec sandbox-exec -f "%s" "%s" "$@"\n' "$SANS_RESEAU" "$VANGUARD" >"$ISOLE"
chmod +x "$ISOLE"
VANGUARD="$ISOLE" lancer audit-reseau 300 '' audit-reseau
VANGUARD="$ISOLE" lancer audit-reseau-json 300 '' audit-reseau --json
verifier "audit-reseau : code 0 (texte et JSON)" python3 -I -c "
import re, sys
l = [x for x in open(sys.argv[1], encoding='utf-8') if re.match(r'vanguard audit-reseau( --json)? -> code', x)]
sys.exit(0 if len(l) == 2 and all(' -> code 0,' in x for x in l) else 1)" "$JOURNAL"
AUDIT_RESEAU="$RES/audit-reseau.py"
cat >"$AUDIT_RESEAU" <<'FIN'
import json, re, sys

cas, res = sys.argv[1], sys.argv[2]
ecran = [re.sub(r"\x1b\[[0-9;]*m", "", l).rstrip() for l in open(f"{res}/audit-reseau.txt", encoding="utf-8")]
if cas == "colonnes":
    larges = [l for l in ecran if len(l) > 76]
    print(larges)
    sys.exit(1 if larges else 0)
if cas == "faux-verts":
    faux = [l for l in ecran if "✔" in l and "Impossible de vérifier" in l]
    print(faux)
    sys.exit(1 if faux else 0)
a = json.load(open(f"{res}/audit-reseau-json.txt", encoding="utf-8"))
constats = [c for d in a["domaines"] for c in d["constats"]]
if cas == "domaines":
    noms = [d["domaine"] for d in a["domaines"]]
    print(a.get("reseau"), noms, [(d["domaine"], d["score"], d["non_verifies"]) for d in a["domaines"]])
    sys.exit(0 if noms == ["Exposition", "Wi-Fi", "Segmentation", "DNS et TLS", "Appareils", "Postes"] else 1)
if cas == "rien-de-sain":
    faux = [c for c in constats if not c["verifie"] and c["probleme"] is None]
    print(faux)
    sys.exit(1 if faux else 0)
if cas == "wifi":
    mauvais = []
    for regle in ("COM-WIF-001", "COM-WIF-002", "COM-WIF-003"):
        c = [x for x in constats if x.get("regle") == regle]
        if not c or any(x["verifie"] or "ne se lisent pas d'ici" not in x["message"] for x in c):
            mauvais.append((regle, [x["message"] for x in c]))
    print(mauvais)
    sys.exit(1 if mauvais else 0)
FIN
for cas in domaines rien-de-sain wifi colonnes faux-verts; do
  verifier "audit-reseau : $cas" python3 -I "$AUDIT_RESEAU" "$cas" "$RES"
done
note "audit-reseau : $(python3 -I "$AUDIT_RESEAU" domaines "$RES" 2>&1 | head -c 600)"

section "Intégrité (référence, vérification, modification détectée)"
lancer integrite-reference 60 '' integrite
lancer integrite-verification 60 '' integrite
echo "# essai Vanguard $(date)" >>~/.zshrc
lancer integrite-modification 60 '' integrite
verifier "intégrité : ~/.zshrc modifié repéré" grep -q 'zshrc' "$RES/integrite-modification.txt"

section "Ports de cette machine"
lancer local 300 '' appareils 127.0.0.1
lancer local-json 300 '' appareils 127.0.0.1 --json

section "Connexion"
lancer connexion 180 '' test-connexion

section "Menu : chaque groupe ouvert puis refermé, puis q"
lancer menu 60 '4\n\n5\n\n6\n\n7\n\nq\n'
# Une ligne propre à chaque sous-menu : le titre du groupe paraît aussi au menu principal.
for g in "Fiche de l'ordinateur" 'Surveillance toutes les heures' 'Analyse antivirus' 'Ce lien est-il dangereux'; do
  verifier "menu : sous-menu avec « $g »" grep -q "$g" "$RES/menu.txt"
done

section "Mots de passe fuités (pseudo-terminal : saisie sans écho)"
python3 -I "$(dirname "$0")/../test-commun/mot-de-passe-pty.py" "$VANGUARD" >"$RES/motdepasse.txt" 2>&1
verifier "mot de passe : « password » trouvé dans des fuites" grep -qE 'Trouvé [0-9 ]+ fois' "$RES/motdepasse.txt"
verifier "mot de passe : jamais affiché" bash -c "! grep -q 'Mot de passe : password' '$RES/motdepasse.txt'"

section "Réparer (liste), mises à jour (sans rien installer), logiciels, gaming"
lancer reparer 60 '\n' reparer
lancer maj 400 'n\nn\nn\nn\n' mises-a-jour
verifier "maj : jamais « --install --all » (installerait une nouvelle version majeure)" bash -c "! grep -q -- '--install --all' '$RES/maj.txt'"
lancer logiciels-liste 120 '' logiciels --liste
verifier "logiciels : au moins 20 proposés" python3 -c "import re, sys; t = open('$RES/logiciels-liste.txt', encoding='utf-8').read(); sys.exit(len(re.findall(r'(?m)^ +(?:\x1b\[[0-9;]*m)?[✔·]', t)) < 20)"
lancer logiciels 60 '\n' logiciels
lancer nettoyer-liste 120 '' nettoyer --liste
verifier "nettoyer : place à gagner mesurée, rien effacé" grep -qiE 'rien n.a été effacé|nothing was deleted' "$RES/nettoyer-liste.txt"
verifier "logiciels : menu affiché" grep -qE 'Pack de départ|Starter pack' "$RES/logiciels.txt"
lancer gaming 60 '\n' jeux

section "Données : sauvegarde puis restauration"
lancer sauvegarder 60 '' exporter "$RES/sauvegarde.json"
lancer restaurer 60 '' importer "$RES/sauvegarde.json"
verifier "sauvegarde écrite" test -s "$RES/sauvegarde.json"

section "Vérifier ma sauvegarde (0.81) : aucune, puis une fausse sauvegarde rsync relue et une copie abîmée"
DOSSIER_VANGUARD="$HOME/Library/Application Support/vanguard"
NOTES="$DOSSIER_VANGUARD/sauvegarde.json"
mkdir -p "$DOSSIER_VANGUARD"
verifier "verifier-sauvegarde : aucune note de sauvegarde avant l'essai" test ! -e "$NOTES"
lancer verifier-sauvegarde-aucune 60 '' verifier-sauvegarde
verifier "verifier-sauvegarde : « aucune sauvegarde » dit" contient "$RES/verifier-sauvegarde-aucune.txt" 'Aucune sauvegarde mise en place'
verifier "verifier-sauvegarde : rien écrit" test ! -e "$NOTES"
# Une sauvegarde comme celle de rsync : la copie du dossier personnel, heures de modification gardées (cp -p), et
# la note que Vanguard écrit en la mettant en place. Les originaux sont datés d'avant, pour qu'un original réécrit
# ensuite soit « modifié depuis » et une copie réécrite « abîmée ». Depuis la 0.82, l'original se cherche dans le
# dossier sauvegardé du même nom (Documents…) : l'essai se range donc dans Documents, comme rsync le pose.
ORIGINAUX="$HOME/Documents/vanguard-essai-sauvegarde"
DISQUE="$RES/disque-sauvegarde"
mkdir -p "$ORIGINAUX" "$DISQUE/Documents/vanguard-essai-sauvegarde"
for n in a b c; do echo "fichier $n de l'essai" >"$ORIGINAUX/$n.txt"; done
touch -t 202601010000 "$ORIGINAUX"/*.txt
cp -p "$ORIGINAUX"/*.txt "$DISQUE/Documents/vanguard-essai-sauvegarde/"
python3 -c "import json,sys; json.dump({'mise_en_place': {'Systemd': {'date': '2026-01-01', 'destination': sys.argv[1], 'empreinte_timer': '', 'empreinte_service': ''}}}, open(sys.argv[2], 'w'))" "$DISQUE" "$NOTES"
lancer verifier-sauvegarde 60 '' verifier-sauvegarde
verifier "verifier-sauvegarde : 3 fichiers relus, identiques" contient "$RES/verifier-sauvegarde.txt" '3 fichier(s) relu(s) sur le disque de sauvegarde, identiques'
verifier "verifier-sauvegarde : la sauvegarde se relit" contient "$RES/verifier-sauvegarde.txt" 'La sauvegarde se relit'
echo "b réécrit après la sauvegarde" >"$ORIGINAUX/b.txt"
echo "c abîmé sur le disque" >"$DISQUE/Documents/vanguard-essai-sauvegarde/c.txt"
lancer verifier-sauvegarde-abimee 60 '' verifier-sauvegarde
verifier "verifier-sauvegarde : original modifié depuis, pas compté comme abîmé" contient "$RES/verifier-sauvegarde-abimee.txt" '1 fichier(s) modifié(s) depuis la sauvegarde'
verifier "verifier-sauvegarde : copie abîmée nommée" contient "$RES/verifier-sauvegarde-abimee.txt" "c.txt : différent de l'original"
verifier "verifier-sauvegarde : sauvegarde dite abîmée" contient "$RES/verifier-sauvegarde-abimee.txt" 'La sauvegarde est abîmée'
rm -rf "$NOTES" "$ORIGINAUX" "$DISQUE"

section "Tableau de bord de la surveillance (0.81) : page écrite, sans navigateur"
lancer tableau 60 '' tableau-de-bord --sans-ouvrir
verifier "tableau : chemin de la page affiché" grep -q 'Tableau de bord :' "$RES/tableau.txt"
verifier "tableau : page écrite dans le dossier de Vanguard" grep -q 'Surveillance du réseau' "$DOSSIER_VANGUARD/tableau.html"
cp "$DOSSIER_VANGUARD/tableau.html" "$RES/tableau.html" 2>/dev/null

section "Courriel (refus de l'envoi)"
lancer courriel 60 'test@example.com\nn\n' fuite-courriel

section "Surveillance : agent launchd"
lancer surveillance-on 60 '' surveillance on
verifier "agent launchd chargé" launchctl print "gui/$(id -u)/com.vanguard.surveillance"
lancer surveillance-off 60 '' surveillance off
verifier "agent launchd retiré" bash -c "! launchctl print gui/$(id -u)/com.vanguard.surveillance"

section "Bac à sable (sandbox-exec)"
ESSAI_BAC="$RES/bac.sh"
cat >"$ESSAI_BAC" <<'EOF'
#!/bin/sh
ls "$HOME" >/dev/null 2>&1 && echo "LECTURE_MAISON_POSSIBLE" || echo "lecture maison refusée"
echo x >"$HOME/vanguard-bac-intrus" 2>/dev/null && echo "ECRITURE_MAISON_POSSIBLE" || echo "écriture maison refusée"
curl -s -m 5 https://example.com >/dev/null 2>&1 && echo "RESEAU_POSSIBLE" || echo "réseau refusé"
echo "fin du programme isolé"
EOF
chmod +x "$ESSAI_BAC"
lancer isoler 60 '' isoler "$ESSAI_BAC"
verifier "bac : programme lancé" grep -q 'fin du programme isolé' "$RES/isoler.txt"
verifier "bac : dossier personnel illisible" bash -c "! grep -q LECTURE_MAISON_POSSIBLE '$RES/isoler.txt'"
verifier "bac : écriture refusée" bash -c "! grep -q ECRITURE_MAISON_POSSIBLE '$RES/isoler.txt'"
verifier "bac : réseau coupé" bash -c "! grep -q RESEAU_POSSIBLE '$RES/isoler.txt'"

section "Antivirus : installation de ClamAV par Vanguard, puis analyse d'un dossier avec le fichier test EICAR"
ESSAI_AV="$RES/dossier-antivirus"
mkdir -p "$ESSAI_AV"
# Le fichier de test standard des antivirus (inoffensif), écrit en deux morceaux.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' >"$ESSAI_AV/eicar.com"
lancer antivirus 900 'o\nn\nn\nn\n' antivirus "$ESSAI_AV"
verifier "antivirus : EICAR détecté" grep -qi 'eicar' "$RES/antivirus.txt"
verifier "antivirus : message « NULL X509 store » de ClamAV masqué" bash -c "! grep -q 'ERROR: NULL X509' '$RES/antivirus.txt'"
verifier "antivirus : refus de la quarantaine annoncé" grep -q 'Rien n.a été fait' "$RES/antivirus.txt"

section "YARA et empreintes de MalwareBazaar : comptées avec la clé abuse.ch, sinon dites non vérifiées ; une vraie correspondance"
ESSAI_YARA="$RES/dossier-yara"
mkdir -p "$ESSAI_YARA"
echo "fichier d'essai de Vanguard $(date +%s)" >"$ESSAI_YARA/facture.pdf.exe"
lancer yara 600 '' yara "$ESSAI_YARA"
# Depuis la 0.84, les empreintes ne se téléchargent qu'avec la clé abuse.ch, que le Mac de GitHub n'a pas : avec elle,
# l'analyse les compte ; sans elle, elle doit dire qu'elles n'ont pas été vérifiées faute de clé, jamais se taire.
verifier "yara : empreintes comptées, ou dites non vérifiées faute de clé abuse.ch" contient_motif "$RES/yara.txt" \
  'ni aux \d+ empreintes de MalwareBazaar|or the \d+ MalwareBazaar fingerprints|MalwareBazaar non vérifiées : clé abuse\.ch manquante|MalwareBazaar fingerprints not checked: abuse\.ch key missing'
contient "$RES/yara.txt" 'clé abuse.ch manquante' && note "yara : sans clé abuse.ch, aucune empreinte téléchargée"
# L'empreinte du fichier d'essai dans la copie gardée des 48 dernières heures, puis l'analyse hors ligne : il doit être
# reconnu par elle seule. Sans clé, Vanguard ne télécharge rien mais lit cette copie : posée pour l'essai si elle
# manque, puis retirée ; sinon complétée, puis rendue telle quelle, heure comprise (Vanguard la rafraîchit d'après
# cette heure).
EMPREINTES="$DOSSIER_VANGUARD/malwarebazaar/recentes.txt"
mettre_empreinte_essai "$EMPREINTES" "$(shasum -a 256 "$ESSAI_YARA/facture.pdf.exe" | cut -c1-64)"
VANGUARD_HORS_LIGNE=1 lancer yara-empreinte 300 'n\n' yara "$ESSAI_YARA"
remettre_empreintes "$EMPREINTES"
verifier "empreintes : fichier reconnu par son empreinte exacte" grep -q 'empreinte exacte' "$RES/yara-empreinte.txt"
verifier "empreintes : quarantaine refusée, rien fait" grep -q 'Rien n.a été fait' "$RES/yara-empreinte.txt"
verifier "empreintes : fichier laissé en place" test -f "$ESSAI_YARA/facture.pdf.exe"

section "Protection : qui parle à Internet, prise de contrôle, lien, fichier téléchargé"
lancer sortantes 180 '' connexions-sortantes
verifier "sortantes : connexions listées" grep -qE 'connexion\(s\) vers Internet|Aucune connexion' "$RES/sortantes.txt"
lancer distance 120 '' acces-a-distance
verifier "distance : verdict donné" grep -qE 'Aucun logiciel de prise de contrôle|prise de contrôle à distance' "$RES/distance.txt"
lancer lien 60 'n\n' lien 'https://paypal.com.compte-securite.xyz/login'
verifier "lien : faux sous-domaine de PayPal repéré" grep -q 'le vrai : paypal.com' "$RES/lien.txt"
lancer verifier-fichier 300 '\n' verifier-fichier "$ESSAI_AV/eicar.com"
verifier "verifier-fichier : EICAR signalé" grep -qiE 'eicar|danger|malveillant' "$RES/verifier-fichier.txt"
lancer camera-micro 60 '' camera-micro
lancer acces 60 '' bilan-confidentialite
verifier "acces : bilan de confidentialité affiché" grep -qE 'Bilan de confidentialité|Privacy check' "$RES/acces.txt"
lancer quarantaine 60 '' quarantaine

section "Collecter les traces : dossier daté, manifeste vérifié par shasum"
lancer traces 600 '\n' depanner traces
TRACES=$(ls -dt "$HOME/Library/Application Support/vanguard/traces/traces-"* 2>/dev/null | head -1)
note "traces : $TRACES"
verifier "traces : dossier daté écrit" test -d "$TRACES"
verifier "traces : LISEZMOI présent" test -s "$TRACES/LISEZMOI.txt"
verifier "traces : manifeste juste (shasum -c)" bash -c "cd \"$TRACES\" && shasum -a 256 -c MANIFESTE.txt"

section "Règles, mise à jour depuis GitHub, outils du quotidien"
lancer regles 30 '' regles
verifier "règles : au moins 50 déclarées pour macOS" python3 -c "import re,sys; t=open('$RES/regles.txt',encoding='utf-8').read(); m=re.search(r'ce système : (\d+)', t); sys.exit(0 if m and int(m.group(1)) >= 50 else 1)"
lancer se-mettre-a-jour 120 'n\n' se-mettre-a-jour
verifier "mise à jour : GitHub interrogé, rien installé sans accord" grep -qE 'GitHub|Dernière version' "$RES/se-mettre-a-jour.txt"
lancer verifier-moi 30 '' verifier-moi
verifier "verifier-moi : empreinte SHA-256 du programme" grep -qE '[0-9a-f]{64}' "$RES/verifier-moi.txt"
lancer fiche 60 '' fiche-ordinateur
lancer lenteur 120 '' lenteur
lancer demarrage 60 '\n' demarrage
lancer entretien 120 '' entretien
lancer changements 30 '' changements
lancer appris 30 '\n' appris
lancer guide-brew 30 '' guide brew
verifier "guide : page de Homebrew" grep -q 'brew' "$RES/guide-brew.txt"
lancer depanner 30 '' depanner xyz
lancer nat 60 '' nat
lancer listes-noires 30 'n\n' listes-noires
lancer pieges 30 '\n' pieges
lancer secrets 300 '' secrets

section "Clé USB simulée (images disque exFAT) : protection et journal d'erreurs"
CLE_IMG="$RES/cle.dmg"
LOG_IMG="$RES/log.dmg"
hdiutil create -quiet -size 64m -fs ExFAT -volname VANGUARD "$CLE_IMG"
hdiutil create -quiet -size 16m -fs ExFAT -volname VANGUARDLOG "$LOG_IMG"
hdiutil attach -quiet "$CLE_IMG"
hdiutil attach -quiet "$LOG_IMG"
mkdir -p /Volumes/VANGUARD/macOS /Volumes/VANGUARD/donnees
cp "$VANGUARD" /Volumes/VANGUARD/macOS/vanguard
# Empreinte d'un autre ordinateur : ce Mac n'est pas celui du propriétaire, la clé doit être protégée.
echo 0000000000000000000000000000000000000000 >/Volumes/VANGUARD/vanguard.cle
touch /Volumes/VANGUARDLOG/vanguard-journal.cle
# Le jeton d'une clé déployée, le même sur la partition des journaux : sans lui, le journal resterait local.
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' >/Volumes/VANGUARD/vanguard.jeton
cp /Volumes/VANGUARD/vanguard.jeton /Volumes/VANGUARDLOG/vanguard.jeton
note "$(mount | grep VANGUARD)"
(cd / && printf '' | delai 120 /Volumes/VANGUARD/macOS/vanguard appareils 999.1.1.1 >"$RES/cle-protection.txt" 2>&1)
note "$(mount | grep VANGUARD)"
verifier "clé : remontée en lecture seule" bash -c "mount | grep ' on /Volumes/VANGUARD ' | grep -q read-only"
verifier "clé : écriture refusée" bash -c "! touch /Volumes/VANGUARD/essai-ecriture"
verifier "clé : VANGUARDLOG toujours modifiable" touch /Volumes/VANGUARDLOG/essai-ecriture
verifier "journal : erreur notée" grep -q 'cible invalide' /Volumes/VANGUARDLOG/journal-erreurs.txt
verifier "journal : rien de personnel" bash -c "! grep -q \"$USER\" /Volumes/VANGUARDLOG/journal-erreurs.txt"
cp /Volumes/VANGUARDLOG/journal-erreurs.txt "$RES/journal-erreurs-cle.txt" 2>/dev/null
# Le menu doit dire la clé protégée.
(cd / && printf 'q\n' | delai 60 /Volumes/VANGUARD/macOS/vanguard >"$RES/cle-menu.txt" 2>&1)
verifier "menu : « protégée en écriture »" grep -q 'protégée en écriture' "$RES/cle-menu.txt"
hdiutil detach -quiet /Volumes/VANGUARD || hdiutil detach -force -quiet /Volumes/VANGUARD
hdiutil detach -quiet /Volumes/VANGUARDLOG || hdiutil detach -force -quiet /Volumes/VANGUARDLOG
rm -f "$CLE_IMG" "$LOG_IMG"

section "Aucun plantage dans toutes les sorties"
verifier "aucun « panicked » dans les sorties de Vanguard" bash -c "! grep -l 'panicked at' '$RES'/*.txt"
verifier "aucun délai dépassé" bash -c "! grep -q 'DÉLAI DÉPASSÉ' '$JOURNAL'"

bilan
# Rapport HTML au même style que celui du test Windows (dans l'artefact « essai-macos »).
python3 -I "$(dirname "$0")/../test-commun/rapport.py" "$RES"
