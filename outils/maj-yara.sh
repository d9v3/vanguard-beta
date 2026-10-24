#!/usr/bin/env bash
# Règles YARA de ReversingLabs (licence MIT), rassemblées dans assets/yara/reversinglabs.yara et intégrées au
# programme (src/protection/yara.rs), puis passées au moteur de Vanguard, qui dit celles qu'il ne comprend pas. Familles gardées : rançongiciels, voleurs de mots de passe, chevaux de Troie,
# portes dérobées, téléchargeurs, exploits, rootkits, virus. « certificate » (empreintes de certificats volés) et
# « pua » (logiciels seulement indésirables) restent dehors : beaucoup de bruit pour un ordinateur personnel.
#   outils/maj-yara.sh [commit]     (par défaut : le dernier de la branche develop)
set -euo pipefail
cd "$(dirname "$0")/.."
DEPOT=reversinglabs/reversinglabs-yara-rules
COMMIT=${1:-$(gh api "repos/$DEPOT/commits/develop" -q .sha)}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "https://github.com/$DEPOT/archive/$COMMIT.tar.gz" -o "$TMP/regles.tar.gz"
mkdir "$TMP/x"
tar -xzf "$TMP/regles.tar.gz" -C "$TMP/x"
SOURCE=$(echo "$TMP"/x/*/yara)
mkdir -p assets/yara
{
  echo "// Règles YARA de ReversingLabs : https://github.com/$DEPOT, commit $COMMIT."
  echo "// Licence MIT (assets/yara/LICENSE-reversinglabs.txt). Rassemblées par outils/maj-yara.sh : ne pas modifier."
  for famille in ransomware infostealer trojan backdoor downloader exploit rootkit virus; do
    find "$SOURCE/$famille" -name '*.yar*' | sort | while read -r f; do
      cat "$f"
      echo
    done
  done
} >assets/yara/reversinglabs.yara
cp "$(dirname "$SOURCE")/LICENSE" assets/yara/LICENSE-reversinglabs.txt
echo "$(grep -c -E '^\s*(private\s+)?rule\s' assets/yara/reversinglabs.yara) règles : assets/yara/reversinglabs.yara"
# Le moteur YARA de Vanguard ne lit qu'un sous-ensemble du langage (src/protection/regles_yara.rs) : une construction
# nouvelle de ReversingLabs qu'il ne connaît pas rend sa règle « non vérifiée ». Le test le dit, règle par règle, et
# YARA-X (l'oracle) doit lui aussi accepter le fichier.
if ! cargo test -q --bin vanguard -- --nocapture protection::yara::tests::les_regles_d_origine protection::oracle_yara::corpus >"$TMP/moteur.txt" 2>&1; then
  grep -E 'RÈGLE NON VÉRIFIÉE|refusées par YARA-X|panicked' "$TMP/moteur.txt" || tail -20 "$TMP/moteur.txt"
  echo "✖ Des règles ne sont pas comprises par le moteur de Vanguard (ou par YARA-X) : non vérifiées tant que le moteur"
  echo "  ne les lit pas. Étendre src/protection/regles_yara.rs (et l'oracle), ou garder l'ancienne version des règles."
  exit 1
fi
echo "✔ Toutes les règles sont comprises par le moteur de Vanguard et par YARA-X."
