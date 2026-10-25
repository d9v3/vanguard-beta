#!/usr/bin/env bash
# Tout vérifier en une commande, avant un commit ou une livraison : mise en forme, clippy sur les quatre cibles, tests
# Linux et Windows (sous Wine, avec le lanceur de la clé : outils/essais-lanceur.sh), les tests Linux refaits sans
# Internet, scripts PowerShell, shell et Python, essais des outils de la clé (outils/essais-cle.sh), de la signature
# des versions (outils/essais-signature.sh) et de ce script même sous --seulement (outils/essais-verifier.sh), liens
# internes, carte de couverture ATT&CK à jour (outils/couverture-attack.py), documentation du code sans avertissement
# (cargo doc), textes français et anglais (outils/textes.py), régression de détection (le corpus de
# src/modele/corpus.rs, Linux et Wine), dépendances (cargo deny) et leurs failles connues (cargo audit), banc de
# fuzzing compilé et passé quelques secondes par cible.
# La CI lance ce même script (.github/workflows/ci.yml) : une seule logique, ici.
# Chaque cible de compilation a sa chaîne (clippy, puis ses tests) et les quatre tournent en même temps : cargo garde
# un dossier par cible, elles ne s'attendent presque pas. À la fin, une ligne par étape ; le code de sortie dit si tout
# est vert.
#   outils/verifier.sh               tout
#   outils/verifier.sh --rapide      mise en forme, clippy et tests Linux seulement
#   outils/verifier.sh --sans-wine   tout, sauf les tests Windows
#   outils/verifier.sh --ci          pour la CI de GitHub : tout sauf Wine, et l'essai du veilleur sur le vrai noyau
#                                    peut s'y dire sauté (les runners refusent le connecteur de processus)
#   outils/verifier.sh --seulement dependances,failles-connues   ces étapes-là (la nuit en CI), sans les autres ;
#                                    une étape demandée qui se dit sautée, ou ne tourne pas, y est un échec, et un nom
#                                    inconnu est refusé (code 2)
# Un test qui ne peut pas tourner ici (outil du système absent, root d'un espace de noms…) se dit « sauté »
# (src/essais.rs) : ses sauts sont comptés à côté des tests passés, et leurs raisons montrées.
# Les scripts PowerShell du programme sont aussi analysés et rejoués dans un bac à sable (outils/rejouer-ps.py).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:-}
SEULEMENT=
if [[ $MODE == --seulement ]]; then
  SEULEMENT=",${2:?--seulement étape[,étape]},"
  # Un nom mal écrit, ou une étape renommée sans suivre ci.yml, ne lancerait rien et finirait « Tout est vert » :
  # l'audit de nuit serait vert pour toujours sans rien vérifier. Les noms connus sont ceux du résumé (les appels
  # de ligne, plus bas) : la liste est ce script même, rien n'est recopié.
  CONNUES=$(sed -nE 's/^ *ligne ([a-z-]+) .*/\1/p' "$0")
  for n in ${2//,/ }; do
    grep -qxF -- "$n" <<<"$CONNUES" || { echo "✖ --seulement : étape inconnue : $n" >&2; exit 2; }
  done
fi
WINE=${VANGUARD_WINE:-$HOME/.local/share/Steam/compatibilitytools.d/GE-Proton11-9-x86_64/files/bin/wine}
# pwsh : celui que l'auteur garde à part, sinon celui du système (préinstallé sur les runners Linux de GitHub).
PWSH=${VANGUARD_PWSH:-$HOME/.cache/vanguard-dev/pwsh/pwsh}
[[ -x $PWSH ]] || PWSH=$(command -v pwsh || true)
# Journaux et préfixe Wine hors de /tmp, dont le quota est partagé par les sessions ; retirés à la fin.
mkdir -p "$HOME/.cache/vanguard-dev"
TRAVAIL=$(mktemp -d "$HOME/.cache/vanguard-dev/verifier.XXXX")
trap 'rm -rf "$TRAVAIL"' EXIT
DEBUT=$SECONDS

# Une étape qui ne peut pas tourner ici (outil absent) sort avec ce code et dit pourquoi en première ligne : elle est
# dite « sautée », sans compter comme un échec, sauf avec --seulement (voir ligne). 77, comme les tests d'automake ;
# 1 et 2 sont déjà ceux des échecs.
SAUTEE=77

# Une étape : sa commande, son journal, son état (« ok 41 », « sautee 0 » ou « echec 41 », en secondes). Avec
# --seulement, une étape qui n'est pas demandée ne tourne pas (« non lancé » au résumé, qui ne la montre pas).
etape() {
  local nom=$1 debut=$SECONDS code
  shift
  [[ -z $SEULEMENT || $SEULEMENT == *",$nom,"* ]] || return 0
  "$@" >"$TRAVAIL/$nom.log" 2>&1
  code=$?
  if ((code == 0)); then
    echo "ok $((SECONDS - debut))" >"$TRAVAIL/$nom.etat"
  elif ((code == SAUTEE)); then
    echo "sautee $((SECONDS - debut))" >"$TRAVAIL/$nom.etat"
  else
    echo "echec $((SECONDS - debut))" >"$TRAVAIL/$nom.etat"
    return 1
  fi
}

# Internet joignable : les bases de failles connues (RustSec) sont des dépôts de GitHub. Cinq secondes au plus ;
# VANGUARD_HORS_LIGNE fait comme sans Internet.
internet() { [[ -z ${VANGUARD_HORS_LIGNE:-} ]] && curl -fsI --max-time 5 https://github.com >/dev/null 2>&1; }

# ring (TLS du client HTTPS) et YARA-X (l'oracle des tests, par wasmtime) compilent un peu de C : musl-gcc pour Linux, le gcc de MinGW pour
# Windows, clang pour les cibles Mac, visées sans les outils d'Apple (outils/mac-entetes, ring sans en-têtes du
# système) ; clippy n'assemble jamais le programme.
clippy() {
  case $1 in
    *-apple-darwin)
      local v=${1//-/_}
      env "CC_$v=clang" "CFLAGS_$v=-ffreestanding -nostdlibinc -DRING_CORE_NOSTDLIBINC -I$PWD/outils/mac-entetes" \
        cargo clippy -q --all-targets --target "$1" -- -D warnings ;;
    *) cargo clippy -q --all-targets --target "$1" -- -D warnings ;;
  esac
}

# La régression de détection (src/modele/corpus.rs) : le corpus seul, pour que sa ligne se voie au résumé à côté des
# passes complètes. Chaque cas fabriqué doit faire tirer sa règle, chaque cas propre la laisser muette, et la liste
# fermée tenir. Le code 0 de cargo ne suffit pas (un filtre qui ne trouve aucun test rend 0) : la ligne du corpus de
# ce système est exigée. Sous Wine, dans le préfixe des tests Windows, juste après eux ; sans Wine, sautée et dite.
corpus() {
  local systeme=$1 cible=()
  [[ $systeme == windows ]] && cible=(--target x86_64-pc-windows-gnu)
  shift
  "$@" cargo test -q --bin vanguard "${cible[@]}" modele::corpus:: -- --nocapture >"$TRAVAIL/corpus-$systeme.txt" 2>&1
  local code=$?
  cat "$TRAVAIL/corpus-$systeme.txt"
  ((code == 0)) || return 1
  grep -q "corpus de détection ($systeme) : [0-9]* règles tirent" "$TRAVAIL/corpus-$systeme.txt" ||
    { echo "✖ la ligne du corpus ($systeme) manque : le corpus n'a pas tourné"; return 1; }
}
regression_linux() { corpus linux env; }
regression_windows() {
  [[ -x $WINE ]] || { echo "Wine absent ($WINE ; VANGUARD_WINE pour un autre)"; return "$SAUTEE"; }
  local prefixe resultat
  prefixe=$(mktemp -d "$TRAVAIL/wine-corpus.XXXX")
  corpus windows env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
    WINEPREFIX="$prefixe" WINEDEBUG=-all CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER="$WINE"
  resultat=$?
  WINEPREFIX=$prefixe "${WINE%/*}/wineserver" -k 2>/dev/null
  WINEPREFIX=$prefixe "${WINE%/*}/wineserver" -w 2>/dev/null
  return "$resultat"
}

# Les cas du corpus qui tirent sur un système, et le reste du compte, lus dans le journal de son étape.
cas_qui_tirent() {
  sed -nE 's/^.*corpus de détection \([a-z]+\) : ([0-9]+) règles tirent.*/\1/p' "$TRAVAIL/$1.log" 2>/dev/null | head -n1
}

# Les compilateurs C qu'il faut ici, dits d'emblée plutôt qu'au milieu d'une compilation.
for outil in musl-gcc x86_64-w64-mingw32-gcc clang; do
  command -v "$outil" >/dev/null || echo "⚠ $outil manque (Arch : musl, mingw-w64-gcc, clang) : la compilation de ring et de YARA-X (tests) échouera."
done

# Les tests sautés (src/essais.rs) d'une étape : un fichier par étape, qu'ils remplissent d'une ligne chacun.
sautes() { echo "$TRAVAIL/sautes-$1.txt"; }

# Les tests Linux : le veilleur sur le vrai noyau est exigé (VANGUARD_EXIGER_VEILLEUR : son échec fait échouer le
# test au lieu de le dire sauté), sauf en CI, où les runners n'ouvrent pas le connecteur de processus.
tests_linux() {
  if [[ $MODE == --ci ]]; then
    VANGUARD_TESTS_SAUTES=$(sautes tests-linux) cargo test -q
  else
    VANGUARD_TESTS_SAUTES=$(sautes tests-linux) VANGUARD_EXIGER_VEILLEUR=1 cargo test -q
  fi
}

tests_wine() {
  local prefixe resultat
  [[ -x $WINE ]] || { echo "Wine absent ($WINE ; VANGUARD_WINE pour un autre)"; return "$SAUTEE"; }
  prefixe=$(mktemp -d "$TRAVAIL/wine.XXXX")
  # Sans le bus système, Wine ne demande pas à udisks les disques montés : sinon le préfixe en fait des lecteurs
  # (la vraie clé VANGUARD branchée devient E:) et les tests qui parcourent D: à Z: la lisent.
  local -x DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent
  # Le fichier des sauts sous son nom pour Windows : Wine montre la racine de Linux comme le lecteur Z:.
  local f
  f=$(sautes tests-windows)
  WINEPREFIX=$prefixe WINEDEBUG=-all CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=$WINE \
    VANGUARD_TESTS_SAUTES="Z:${f//\//\\}" cargo test -q --target x86_64-pc-windows-gnu
  resultat=$?
  # Le lanceur de la clé dans le même préfixe, déjà prêt (son faux powershell.exe y remplace celui de Wine).
  local lanceur
  VANGUARD_PREFIXE_LANCEUR=$prefixe VANGUARD_WINE=$WINE bash outils/essais-lanceur.sh
  lanceur=$?
  ((lanceur == SAUTEE)) && echo "⚠ essais du lanceur de la clé sautés (voir la ligne plus haut)"
  ((lanceur == 0 || lanceur == SAUTEE)) || resultat=1
  # Le serveur de Wine survit quelques secondes aux tests et écrit encore dans le préfixe : arrêté avant le ménage.
  WINEPREFIX=$prefixe "${WINE%/*}/wineserver" -k 2>/dev/null
  WINEPREFIX=$prefixe "${WINE%/*}/wineserver" -w 2>/dev/null
  return "$resultat"
}

# Chaque script analysé, puis une faute que l'analyse laisse passer : PowerShell ne distingue pas les majuscules des
# variables, si bien qu'un `$langues = @(...)` écrit au niveau du script range le tableau dans le paramètre
# `[string]$Langues`, converti en « fr en » (vu dans la VM : tous les essais de console fondus en un seul). Un nom
# de paramètre réaffecté sous une autre casse est refusé, comme un tableau rangé dans un paramètre [string] ou [int] ;
# le reste à même casse (`$Exe = (Resolve-Path ...).Path`) : voulu.
scripts_powershell() {
  local erreurs=0 f verif
  [[ -n $PWSH ]] || { echo "pwsh absent (VANGUARD_PWSH pour le donner)"; return "$SAUTEE"; }
  verif=$(
    cat <<'EOF'
$ErrorActionPreference = 'Stop'
$f = $env:VG_PS_FICHIER; $nom = $env:VG_PS_NOM; $e = $null; $t = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$t, [ref]$e)
if ($e.Count) { $e | ForEach-Object { "$nom : " + $_.Message }; exit 1 }
if (-not $ast.ParamBlock) { exit 0 }
$params = @{}
foreach ($p in $ast.ParamBlock.Parameters) { $params[$p.Name.VariablePath.UserPath.ToLowerInvariant()] = $p }
$fautes = foreach ($a in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -or $x -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
    $v = if ($a -is [System.Management.Automation.Language.ForEachStatementAst]) { $a.Variable } else { $a.Left }
    while ($v -is [System.Management.Automation.Language.AttributedExpressionAst]) { $v = $v.Child }
    if ($v -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
    $chemin = $v.VariablePath
    if (-not ($chemin.IsUnqualified -or $chemin.IsScript)) { continue }
    $n = $chemin.UserPath -replace '^script:', ''
    $p = $params[$n.ToLowerInvariant()]
    if (-not $p) { continue }
    $pourquoi = 'PowerShell ne distingue pas les majuscules : à renommer'
    if ($n -ceq $p.Name.VariablePath.UserPath) {
        # Même casse : voulu, sauf un tableau rangé dans un paramètre d'un seul texte ou nombre (aplati pareil).
        $droite = if ($a -is [System.Management.Automation.Language.AssignmentStatementAst] -and $a.Right -is [System.Management.Automation.Language.CommandExpressionAst]) { $a.Right.Expression } else { $null }
        $type = $p.StaticType
        $tableau = $droite -is [System.Management.Automation.Language.ArrayExpressionAst] -or $droite -is [System.Management.Automation.Language.ArrayLiteralAst]
        $recoitTableau = $type -eq [object] -or ($type -ne [string] -and [Collections.IEnumerable].IsAssignableFrom($type))
        if (-not $tableau -or $recoitTableau) { continue }
        $pourquoi = 'un tableau y serait aplati : une autre variable'
    }
    # Dans une fonction, une affectation sans portée crée une variable à elle : le paramètre du script n'y est pas touché.
    $dansFonction = $false
    for ($q = $a.Parent; $q; $q = $q.Parent) { if ($q -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $dansFonction = $true; break } }
    if ($dansFonction -and -not $chemin.IsScript) { continue }
    '{0}:{1} : ${2} est le paramètre [{3}]${4} ({5})' -f $nom, $v.Extent.StartLineNumber, $n, $p.StaticType.Name, $p.Name.VariablePath.UserPath, $pourquoi
}
if ($fautes) { $fautes; exit 1 }
EOF
  )
  for f in outils/test-windows/*.ps1 extensions/exemples/*/*.ps1; do
    VG_PS_FICHIER=$PWD/$f VG_PS_NOM=$f "$PWSH" -NoProfile -NonInteractive -Command "$verif" || erreurs=$((erreurs + 1))
  done
  ((erreurs == 0))
}

# Toute la suite Linux refaite sans Internet : dans un espace réseau vide (unshare -rn, sans root ; la boucle locale
# seule, remontée), VANGUARD_HORS_LIGNE posé pour les essais qui le demandent. Chaque outil doit s'y arrêter de
# lui-même et dire pourquoi. Sans espaces de noms d'utilisateur (noyau qui les refuse), l'étape n'est pas lancée.
hors_ligne() {
  unshare -rn true 2>/dev/null || { echo "espaces de noms d'utilisateur indisponibles"; return 2; }
  VANGUARD_TESTS_SAUTES=$(sautes tests-hors-ligne) \
    unshare -rn sh -c 'ip link set lo up && VANGUARD_HORS_LIGNE=1 exec cargo test -q --offline'
}

rejeu_powershell() {
  [[ -n $PWSH ]] || { echo "pwsh absent (VANGUARD_PWSH pour le donner)"; return "$SAUTEE"; }
  python3 outils/rejouer-ps.py --pwsh "$PWSH"
}

# Le banc de fuzzing (fuzz/) compilé, puis chaque cible passée quelques secondes (VANGUARD_FUZZ_SECONDES, 5 par
# défaut) : une cible que la moindre modification de src/ a cassée se voit à la vérification suivante, pas au
# prochain lancement à la main ; la CI y passe cinq minutes par cible chaque nuit. Sautée sans cargo-fuzz ou sans la
# chaîne nightly (outils/fuzz.sh le dit).
fuzzing() { bash outils/fuzz.sh tout "${VANGUARD_FUZZ_SECONDES:-5}"; }

# La bibliothèque des extensions (extensions/sdk) et l'exemple en Rust : des crates à part, hors de l'espace de travail
# de Vanguard ; leurs propres clippy, tests et compilation, dans un dossier de compilation à eux.
extensions() {
  local cible=${CARGO_TARGET_DIR:-$PWD/target}/extensions m
  for m in extensions/sdk/Cargo.toml extensions/exemples/rust-exemple/Cargo.toml; do
    CARGO_TARGET_DIR=$cible cargo fmt --check --manifest-path "$m" &&
      CARGO_TARGET_DIR=$cible cargo clippy -q --all-targets --manifest-path "$m" -- -D warnings || return 1
  done
  CARGO_TARGET_DIR=$cible cargo test -q --manifest-path extensions/sdk/Cargo.toml &&
    CARGO_TARGET_DIR=$cible cargo build -q --manifest-path extensions/exemples/rust-exemple/Cargo.toml
}

scripts_shell() { find outils extensions -name '*.sh' -print0 | xargs -0 -n1 bash -n; }

# Analysés sans être compilés sur disque : py_compile laisserait des __pycache__ dans outils/.
scripts_python() {
  find outils -name '*.py' -print0 |
    xargs -0 python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]'
}

# Les dépendances selon deny.toml : failles connues (base RustSec), licences, provenance, doublons. Sans Internet, la
# base du dernier téléchargement sert telle quelle ; sans aucune, seules les failles ne sont pas vérifiées, et c'est
# dit. Sans cargo-deny, l'étape est sautée.
dependances() {
  command -v cargo-deny >/dev/null || { echo "cargo-deny absent (cargo install --locked cargo-deny)"; return "$SAUTEE"; }
  local options=(--locked) verifications=() sortie code
  if ! internet; then
    options+=(--offline)
    if compgen -G "${CARGO_HOME:-$HOME/.cargo}/advisory-dbs/advisory-db-*" >/dev/null; then
      echo "sans Internet : base RustSec du dernier téléchargement"
    else
      echo "sans Internet ni base RustSec : failles connues non vérifiées"
      verifications=(bans licenses sources)
    fi
  fi
  sortie=$(cargo deny "${options[@]}" check --hide-inclusion-graph "${verifications[@]}" 2>&1)
  code=$?
  # La bibliothèque des extensions et l'exemple en Rust, crates à part avec leur Cargo.lock : leurs propres règles
  # (extensions/deny.toml), sans les failles admises pour YARA-X.
  local m
  for m in extensions/sdk/Cargo.toml extensions/exemples/rust-exemple/Cargo.toml; do
    sortie+=$'\n'"$m :"$'\n'$(cargo deny "${options[@]}" --manifest-path "$m" --config extensions/deny.toml check \
      --hide-inclusion-graph "${verifications[@]}" 2>&1) || code=1
  done
  # Le banc de fuzzing, crate à part aussi (fuzz/deny.toml) : ses dépendances ne vont jamais dans Vanguard.
  sortie+=$'\n'"fuzz/Cargo.toml :"$'\n'$(cargo deny "${options[@]}" --manifest-path fuzz/Cargo.toml \
    --config fuzz/deny.toml check --hide-inclusion-graph "${verifications[@]}" 2>&1) || code=1
  printf '%s\n' "$sortie"
  # En échec, le résumé ne montre que la fin du journal, où sont les doublons : chaque erreur y est rappelée, avec la
  # bibliothèque visée (dossier de son Cargo.toml pour une licence, ligne de Cargo.lock pour une faille).
  ((code == 0)) || awk '
    /^error\[/ { if (t != "") print t; t = $0; n = 0; next }
    t != "" && ++n <= 5 && match($0, /[^\/]+\/Cargo\.toml:/) { print t " : " substr($0, RSTART, RLENGTH - 12); t = ""; next }
    t != "" && n <= 5 && match($0, /[0-9]+ │ [^ ]+ [^ ]+ registry/) {
      split(substr($0, RSTART, RLENGTH), m, " "); print t " : " m[3] " " m[4]; t = ""
    }
    END { if (t != "") print t }' <<<"$sortie"
  return "$code"
}

# Les failles connues des dépendances selon cargo audit : un second avis, indépendant de cargo deny (sa propre copie
# de la base RustSec, sa propre lecture de Cargo.lock), jugé par outils/failles-programmes.sh comme il juge les
# programmes compilés : abandon, code défaillant et avis « notice » refusés, seules exceptions celles de deny.toml,
# que .cargo/audit.toml doit recopier. Une seule copie de ce jugement, que la CI lance aussi. Sautée sans
# cargo-audit, et sans Internet : une base qui n'est plus à jour dirait vert à tort.
failles_connues() { bash outils/failles-programmes.sh --depot; }

# Les textes affichés comparés à master (outils/textes.py) : un texte perdu ou nouveau se voit avant le commit, un
# tutoiement fait échouer. Sur master, le vouvoiement seul ; sans master (clone partiel de la CI), la comparaison
# est sautée, pas le vouvoiement.
textes() {
  [[ $(git rev-parse HEAD) == $(git rev-parse master 2>/dev/null) ]] && { python3 outils/textes.py --vouvoiement; return; }
  python3 outils/textes.py
}

# La documentation du code (cargo doc) sans aucun avertissement : un `<pid>` pris pour une balise HTML ou un
# `[Install]` pris pour un lien se voit ici plutôt que dans une page cassée.
documentation() { RUSTDOCFLAGS="-D warnings" cargo doc -q --no-deps; }

if [[ -z $SEULEMENT ]] && ! etape mise-en-forme cargo fmt --check; then
  echo "✖ mise en forme : lancer cargo fmt"
  sed -n '1,20p' "$TRAVAIL/mise-en-forme.log"
  exit 1
fi

# Pas d'exigence du veilleur dans la passe sans Internet, où le connecteur de processus n'existe pas.
{
  etape clippy-linux clippy x86_64-unknown-linux-musl && etape tests-linux tests_linux &&
    etape regression-detection regression_linux &&
    if [[ $MODE != --rapide ]]; then etape tests-hors-ligne hors_ligne; fi
} &
if [[ $MODE != --rapide ]]; then
  if [[ $MODE == --sans-wine || $MODE == --ci ]]; then
    etape clippy-windows clippy x86_64-pc-windows-gnu &
  else
    {
      etape clippy-windows clippy x86_64-pc-windows-gnu && etape tests-windows tests_wine &&
        etape regression-detection-windows regression_windows
    } &
  fi
  etape clippy-macos-arm clippy aarch64-apple-darwin &
  etape clippy-macos-intel clippy x86_64-apple-darwin &
  etape powershell scripts_powershell &
  etape rejeu-powershell rejeu_powershell &
  etape shell scripts_shell &
  etape essais-cle bash outils/essais-cle.sh &
  etape signature bash outils/essais-signature.sh &
  etape essais-verifier bash outils/essais-verifier.sh &
  etape masque bash outils/verifier-masque.sh &
  etape extensions extensions &
  etape python scripts_python &
  etape liens python3 outils/liens.py --hors-ligne &
  etape carte-attack python3 outils/couverture-attack.py --verifier &
  etape documentation documentation &
  etape textes textes &
  etape dependances dependances &
  etape failles-connues failles_connues &
  etape fuzzing fuzzing &
fi
wait

# Les tests laissent chacun un dossier jetable (socle::dossier_local sous cfg(test)) : ceux dont le processus est fini
# partent.
for d in /tmp/vanguard-tests-*; do
  [[ -d $d ]] && ! kill -0 "${d##*-}" 2>/dev/null && rm -rf "$d"
done

# Nombre de tests passés, lu dans « test result: ok. 313 passed », et des sautés parmi eux : « 1544 » ou « 1544,
# 12 sautés ».
passes() {
  local n s
  n=$(grep -o 'ok\. [0-9]* passed' "$TRAVAIL/$1.log" 2>/dev/null | awk '{s += $2} END {print s + 0}')
  s=$(cat "$(sautes "$1")" 2>/dev/null | wc -l)
  if ((s > 0)); then echo "$n, $s sautés"; else echo "$n"; fi
}

# Les raisons des tests sautés d'une étape, les plus fréquentes d'abord : ce que cette passe n'a pas vérifié.
raisons_des_sautes() {
  local f
  f=$(sautes "$1")
  [[ -s $f ]] || return 0
  cut -f2 "$f" | sort | uniq -c | sort -rn | head -n 8 | sed -E 's/^ *([0-9]+) /      \1 × /'
  (($(cut -f2 "$f" | sort -u | wc -l) <= 8)) || echo "      … (liste complète : VANGUARD_TESTS_SAUTES=fichier cargo test)"
}

ECHECS=0
# Le résumé est aussi gardé dans un fichier : la page des fonctions (outils/page-fonctions.py) y lit les nombres de
# tests de la dernière vérification, au déploiement.
RESUME=$HOME/.cache/vanguard-dev/verifier-dernier.txt
# Avec --seulement, le résumé de la dernière vérification complète reste celui que la page des fonctions lit.
[[ -n $SEULEMENT ]] && RESUME=/dev/null
mkdir -p "$HOME/.cache/vanguard-dev" && : >"$RESUME"
ligne() {
  local nom=$1 libelle=$2 etat duree
  [[ -z $SEULEMENT || $SEULEMENT == *",$nom,"* ]] || return 0
  # Une étape demandée nommément (--seulement : l'audit de nuit de la CI) qui n'a pas tourné, ou qui s'est dite
  # sautée, n'a rien vérifié : ce n'est pas un vert. Sans --seulement, un saut a ses raisons (outil absent ici,
  # clone partiel de la CI) et reste dit sans échouer.
  if [[ ! -f $TRAVAIL/$nom.etat ]]; then
    printf '  · %-34s non lancé\n' "$libelle" | tee -a "$RESUME"
    [[ -z $SEULEMENT ]] || ECHECS=$((ECHECS + 1))
    return
  fi
  read -r etat duree <"$TRAVAIL/$nom.etat"
  if [[ $etat == ok ]]; then
    printf '  ✔ %-34s %4s s\n' "$libelle" "$duree" | tee -a "$RESUME"
  elif [[ $etat == sautee && -z $SEULEMENT ]]; then
    printf '  · %-34s sautée : %s\n' "$libelle" "$(head -n1 "$TRAVAIL/$nom.log")" | tee -a "$RESUME"
  elif [[ $etat == sautee ]]; then
    ECHECS=$((ECHECS + 1))
    printf '  ✖ %-34s sautée, rien vérifié : %s\n' "$libelle" "$(head -n1 "$TRAVAIL/$nom.log")" | tee -a "$RESUME"
  else
    ECHECS=$((ECHECS + 1))
    printf '  ✖ %-34s %4s s\n' "$libelle" "$duree" | tee -a "$RESUME"
    tail -n 25 "$TRAVAIL/$nom.log" | sed 's/^/      /'
  fi
}

# Ce que cargo deny laisse passer sans le taire : les failles admises dans deny.toml (leur raison commence par le nom
# de la bibliothèque), les doublons, la base de failles hors ligne, et tout autre avertissement (version retirée de
# crates.io, cible inconnue…) : l'étape reste verte, et son journal part à la fin, il ne se lirait nulle part ailleurs.
remarques_dependances() {
  local journal=$TRAVAIL/dependances.log admises doublons
  [[ -f $journal && $(head -c6 "$TRAVAIL/dependances.etat" 2>/dev/null) != sautee ]] || return 0
  grep -m1 '^sans Internet' "$journal" | sed 's/^/      /'
  admises=$(grep -oE '\{ id = "RUSTSEC-[0-9]{4}-[0-9]{4}", reason = "[^,]+' deny.toml |
    sed -E 's/.*"(RUSTSEC-[0-9-]+)", reason = "(.*)/\1 (\2)/' | paste -sd, | sed 's/,/, /g')
  [[ -n $admises ]] && echo "      failles admises (deny.toml) : $admises"
  doublons=$(grep -c '^warning\[duplicate\]' "$journal")
  ((doublons == 0)) || echo "      $doublons bibliothèques en plusieurs versions (doublons)"
  grep -E '^warning(\[[a-z-]+\])?:' "$journal" | grep -v '^warning\[duplicate\]' | sort | uniq -c |
    sed -E 's/^ *([0-9]+) /      \1 × /'
  return 0
}

echo
ligne mise-en-forme "mise en forme"
ligne clippy-linux "clippy Linux"
ligne tests-linux "tests Linux ($(passes tests-linux))"
raisons_des_sautes tests-linux
ligne regression-detection "régression de détection Linux ($(cas_qui_tirent regression-detection) règles)"
[[ -f $TRAVAIL/regression-detection.log ]] && grep -m1 -oE '[0-9]+ exemptées, [0-9]+ en attente de S3b, [0-9]+ de S3c' "$TRAVAIL/regression-detection.log" | sed 's/^/      /'
if [[ $MODE != --rapide ]]; then
  ligne tests-hors-ligne "tests Linux sans Internet ($(passes tests-hors-ligne))"
  raisons_des_sautes tests-hors-ligne
  ligne clippy-windows "clippy Windows"
  if [[ $MODE != --sans-wine && $MODE != --ci ]]; then
    ligne tests-windows "tests Windows sous Wine ($(passes tests-windows))"
    raisons_des_sautes tests-windows
    ligne regression-detection-windows "régression de détection Windows ($(cas_qui_tirent regression-detection-windows) règles)"
  elif [[ -z $SEULEMENT ]]; then
    printf '  · %-34s non lancé (%s) : le vrai Windows de la CI fait tourner son cargo test\n' "régression de détection Windows" "$MODE" | tee -a "$RESUME"
  fi
  ligne clippy-macos-arm "clippy macOS Apple Silicon"
  ligne clippy-macos-intel "clippy macOS Intel"
  ligne powershell "scripts PowerShell"
  ligne rejeu-powershell "PowerShell du programme rejoué"
  ligne shell "scripts shell"
  ligne essais-cle "essais des outils de la clé"
  ligne signature "signature des versions"
  ligne essais-verifier "essais de verifier.sh (--seulement)"
  ligne masque "mots d'attaque masqués"
  ligne extensions "extensions (sdk, exemple Rust)"
  ligne python "scripts Python"
  ligne liens "liens internes"
  ligne carte-attack "carte ATT&CK à jour (COUVERTURE-ATTACK.md)"
  ligne documentation "documentation du code (cargo doc)"
  ligne textes "textes FR/EN"
  [[ -f $TRAVAIL/textes.log ]] && grep -E '^(perdues|nouvelles) : \[[^]]' "$TRAVAIL/textes.log" | cut -c1-200 | sed 's/^/      /'
  ligne dependances "dépendances (cargo deny)"
  remarques_dependances
  ligne failles-connues "failles connues (cargo audit)"
  ligne fuzzing "banc de fuzzing ($(awk '/^  ✔/ { n++ } END { print n + 0 }' "$TRAVAIL/fuzzing.log" 2>/dev/null) cibles)"
fi
DUREE=$((SECONDS - DEBUT))
if ((ECHECS)); then
  echo "$ECHECS étape(s) en échec, en $((DUREE / 60)) min $((DUREE % 60)) s."
  exit 1
fi
echo "Tout est vert, en $((DUREE / 60)) min $((DUREE % 60)) s."
