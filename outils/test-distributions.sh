#!/usr/bin/env bash
# Le bilan de Vanguard sur de vraies distributions Linux, dans des conteneurs (CI, travail « linux ») : le programme
# statique, tel qu'il part sur la clé, lancé dans Fedora, Debian, Ubuntu et openSUSE, avec le serveur SSH installé pour
# que ses vérifications (sshd, ses algorithmes, PAM) aient de quoi lire. Échec seulement si Vanguard plante ou rend un
# JSON illisible : ce qu'un conteneur ne permet pas de vérifier (systemd, pare-feu) est noté, pas compté comme échec.
#   outils/test-distributions.sh <programme vanguard> <dossier de résultats>
# Demande Docker : la CI de GitHub l'a ; ici, Docker vaut root (jamais pour contourner sudo).
set -uo pipefail
PROGRAMME=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
RES=$2
mkdir -p "$RES"
RES=$(cd "$RES" && pwd)

declare -A INSTALLER=(
  [fedora:latest]="dnf -y -q install openssh-server pam"
  [debian:stable]="apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server"
  [ubuntu:latest]="apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server"
  [opensuse/tumbleweed]="zypper -n -q install openssh-server"
)
echecs=0
for image in fedora:latest debian:stable ubuntu:latest opensuse/tumbleweed; do
  nom=${image//[:\/]/-}
  echo "::group::$image"
  docker run --rm -v "$PROGRAMME:/vanguard:ro" -v "$RES:/res" -e VANGUARD_LANG=fr "$image" bash -c "
    ${INSTALLER[$image]} >/dev/null 2>&1 || echo 'installation de openssh-server impossible'
    cat /etc/os-release | head -2
    timeout 300 /vanguard audit --json >/res/$nom.json 2>/res/$nom.err; echo \$? >/res/$nom.code
  "
  code=$(cat "$RES/$nom.code" 2>/dev/null || echo absent)
  if python3 - "$RES/$nom.json" "$image" "$code" <<'FIN'; then echo "✓ $image"; else echo "✗ $image"; echecs=$((echecs + 1)); fi
import json, sys
fichier, image, code = sys.argv[1:]
try:
    a = json.load(open(fichier, encoding="utf-8"))
except Exception as e:
    print(f"JSON illisible ({image}, code {code}) : {e}")
    sys.exit(1)
constats = a.get("constats", [])
non = [f"{c['categorie']} — {c['message'][:110]}" for c in constats if not c.get("verifie")]
print(f"{image} : {len(constats)} constats, note {a.get('score')}/100, {len(non)} non vérifiés (attendu dans un conteneur)")
for n in non[:12]:
    print("   · " + n)
sys.exit(0 if code == "0" else 1)
FIN
  echo "::endgroup::"
done
echo "Distributions : $((4 - echecs)) sur 4 sans plantage."
exit $((echecs > 0))
