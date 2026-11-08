#!/usr/bin/env bash
# Publie la version de Cargo.toml sur GitHub (page « Releases ») : les deux programmes, Linux et Windows, sous des noms
# fixes que le README relie (…/releases/latest/download/<nom>), leurs empreintes SHA-256 et leurs nomenclatures (SBOM,
# attestées par GitHub : travail « nomenclatures » de .github/workflows/ci.yml, relancé pour ce commit s'il manque).
# À lancer après outils/deployer.sh, quand la version est compilée et poussée. Les notes reprennent toutes les versions
# déployées depuis la page précédente : une version intermédiaire (VANGUARD_INTERMEDIAIRE) n'a pas la sienne.
#   outils/publier-version.sh           publier la version de Cargo.toml
#   outils/publier-version.sh --notes   montrer les notes qu'elle aurait, sans rien publier
#   outils/publier-version.sh --premier la toute première version du dépôt des versions (l'historique y commence)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
# Le nom du programme, avec sa majuscule (« Vanguard ») : titre de la page de la version.
NOM=$(sed -n 's/^name = "\(.*\)"/\1/p' Cargo.toml | head -1)
NOM=${NOM^}
TAG="v$VERSION"
COMMIT=$(git rev-parse HEAD)
LINUX=target/x86_64-unknown-linux-musl/release/vanguard
WINDOWS=target/x86_64-pc-windows-gnu/release/vanguard.exe

# Les commits « … (vX.Y.Z) » depuis la dernière page publiée, le plus récent en tête, un seul par version (le plus
# récent : un commit de version ajouté après coup remplace le titre d'avant) ; sans page d'avant (ou si elle manque
# ici), celui de cette version seulement.
versions() {
  local precedente
  precedente=$(gh release view --json tagName -q .tagName 2>/dev/null || true)
  if [[ -n $precedente && $precedente != "$TAG" ]] && git rev-parse -q --verify "$precedente^{commit}" >/dev/null; then
    git log --format='%H %s' "$precedente..HEAD"
  else
    git log --format='%H %s' --grep="(v$VERSION)" -1
  fi | grep -E ' \(v[0-9]+\.[0-9]+\.[0-9]+\)$' | awk '{ v = $NF } !vu[v]++' || true
}

# Les passe-droits pris pour cette version (VANGUARD_PUBLIER_SANS_EMPREINTES_CI, VANGUARD_PUBLIER_SANS_VM) : dits en
# tête des notes de la page, et gardés dans l'historique signé (outils/signer-versions.sh --passe-droit), pas
# seulement au terminal (relecture du lot correctifs-c6).
PASSE_DROITS=()
passe_droits_notes() {
  local p
  for p in "${PASSE_DROITS[@]+"${PASSE_DROITS[@]}"}"; do
    case $p in
      sans-empreintes-ci)
        printf '%s\n' "⚠ **Passe-droit** : programmes Linux et Windows publiés sans être confrontés à la compilation \
reproductible de la CI (VANGUARD_PUBLIER_SANS_EMPREINTES_CI)." "⚠ **Override**: Linux and Windows programs published \
without being matched against the CI's reproducible build (VANGUARD_PUBLIER_SANS_EMPREINTES_CI)." ""
        ;;
      sans-vm)
        printf '%s\n' "⚠ **Passe-droit** : programme Windows publié sans passe de la VM d'essais sur ce .exe \
(VANGUARD_PUBLIER_SANS_VM)." "⚠ **Override**: Windows program published without a pass of the test VM on this .exe \
(VANGUARD_PUBLIER_SANS_VM)." ""
        ;;
    esac
  done
}

# La compilation reproductible de la CI retenue, quand elle a tourné sur un commit d'après celui de la version
# (CI_APRES, descendant_hors_compilation) : dit en tête des notes, avec ce commit, pour qui veut la retrouver, et
# gardé en entier (CI_APRES_COMPLET) dans le bloc de la version de l'historique signé (signer-versions.sh --ci-apres).
CI_APRES=
CI_APRES_COMPLET=
ci_apres_notes() {
  [[ -n $CI_APRES ]] || return 0
  printf '%s\n' "ℹ Programmes Linux et Windows identiques à ceux de la compilation reproductible de la CI, faite sur \
le commit $CI_APRES : il suit celui de la version et ne change que des captures d'écran, l'image de partage ou la page \
des fonctions, rien de ce qui est compilé." "ℹ Linux and Windows programs identical to those of the CI's reproducible \
build, run on commit $CI_APRES: it follows the version's commit and only changes screenshots, the social preview image \
or the features page, nothing that is compiled." ""
}

# Ce qui change, version par version : le titre de son commit, ses puces dessous (sans les lignes de co-auteur). Une
# seule version : son titre en gras, comme avant ; plusieurs : un titre « X.Y.Z : … » chacune. Puis comment
# télécharger. Les passe-droits pris d'abord, puis la provenance de la CI quand elle est dite.
notes() {
  local lignes nombre sha sujet puces
  passe_droits_notes
  ci_apres_notes
  lignes=$(versions)
  nombre=$(grep -c . <<<"$lignes" || true)
  [[ $nombre -gt 0 ]] || printf '**%s %s**\n\n' "$NOM" "$VERSION"
  while read -r sha sujet; do
    [[ -n $sha ]] || continue
    puces=$(git log -1 --format=%b "$sha" | grep -viE '^(co-authored-by|signed-off-by|claude-session):' || true)
    puces=$(sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' <<<"$puces")
    if [[ $nombre -gt 1 ]]; then
      printf '### %s : %s\n\n' "$(sed -E 's/.* \(v([0-9.]+)\)$/\1/' <<<"$sujet")" "${sujet% (v*)}"
    else
      printf '**%s**\n\n' "${sujet% (v*)}"
    fi
    [[ -z $puces ]] || printf '%s\n\n' "$puces"
  done <<<"$lignes"
  printf '%s\n' "$TELECHARGER"
}

TELECHARGER="Un programme par système, à télécharger :
- **Windows** : \`vanguard-windows-x86_64.exe\`, double-clic. Il n'est pas signé : SmartScreen peut avertir
  (« Informations complémentaires » puis « Exécuter quand même »).
- **Linux** : \`vanguard-linux-x86_64\` (toutes les distributions), \`chmod +x\` puis lancer dans un terminal.

Empreintes SHA-256 : \`SHA256SUMS.txt\` (\`sha256sum -c SHA256SUMS.txt\`).

Sur la page de d9v3/vanguard-beta, les nomenclatures logicielles (SBOM CycloneDX : toutes les dépendances compilées,
versions et licences) : \`vanguard-<système>.cdx.json\`, une par programme ; elles décrivent leur code, pas le
fichier publié. Ces nomenclatures sont attestées par GitHub, qui les a produites, à vérifier avec la GitHub CLI
connectée (\`gh auth login\`), le nom du fichier changé pour l'autre système :

\`gh attestation verify vanguard-linux-x86_64.cdx.json -R d9v3/vanguard-beta --signer-workflow d9v3/vanguard-beta/.github/workflows/ci.yml --source-ref refs/heads/master\`

Les programmes Windows et Linux, compilés par l'auteur, ne sont pas attestés : la mise à jour intégrée de Vanguard
les vérifie par la signature Ed25519 de l'auteur (dépôt d9v3/vanguard-update). \`SHA256SUMS.txt\` contrôle le
téléchargement, pas l'origine.

Ce qu'ont apporté les versions d'avant : \`CHANGELOG.md\` dans le dépôt.

---

Download the program for your system: \`vanguard-windows-x86_64.exe\` (Windows, unsigned: SmartScreen may warn, “More
info” then “Run anyway”), \`vanguard-linux-x86_64\` (any distribution: \`chmod +x\`, then run it in a terminal).
SHA-256 checksums: \`SHA256SUMS.txt\` (they check the download, not the origin). On the d9v3/vanguard-beta page,
software bills of materials (CycloneDX SBOM): \`vanguard-<system>.cdx.json\`, one per program; they describe its
code, not the published file. The SBOMs are attested by GitHub, which built them; check with the GitHub CLI logged in
(\`gh auth login\`), changing the file name for the other system: \`gh attestation verify vanguard-linux-x86_64.cdx.json -R d9v3/vanguard-beta --signer-workflow d9v3/vanguard-beta/.github/workflows/ci.yml --source-ref refs/heads/master\`. The Windows and Linux programs, built by the author, are not attested: Vanguard's built-in
update checks them with the author's Ed25519 signature (d9v3/vanguard-update repository). What earlier versions brought: \`CHANGELOG.en.md\` in the repository."

# Jamais déduit d'un dépôt des versions vide : vidé par qui tient le compte GitHub (et le point sûr effacé), il ferait
# repartir l'historique de zéro (campagne d'attaque n° 4). Tapé par l'auteur, une seule fois.
PREMIERE=
[[ ${1:-} == --premier ]] && PREMIERE=1
if [[ ${1:-} == --notes ]]; then
  git fetch -q --tags origin 2>/dev/null || true
  notes
  exit 0
fi

# Les programmes publiés doivent être, octet pour octet, ceux que outils/compiler-version.sh a compilés d'un arbre
# propre (son repère, target/.compilation : commit, arbre propre, empreintes) ; ce commit-là, ou un d'avant dont le
# programme est le même (seuls des captures, la page des fonctions, la documentation ont changé depuis :
# .github/hors-code.txt), et HEAD celui de GitHub : la page de la version y renvoie, et GitHub fait les nomenclatures
# de la tête de master. L'étiquette se pose sur le commit compilé : qui la recompile retrouve sa date gravée.
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo "Des changements ne sont pas committés : rien de publié."
  exit 1
fi
REPERE=target/.compilation
repere() { sed -n "s/^$1 //p" "$REPERE" 2>/dev/null | head -1; }
HORS_CODE=$(grep -v '^#' .github/hors-code.txt | head -n 1)
# Le commit compilé sur la sortie si les programmes sont bien les siens ; sinon la raison, et code 1. Lue telle quelle
# par outils/essais-signature.sh.
verifier_compilation() {
  local compile sorte fichier gravee
  compile=$(repere commit)
  [[ -f $LINUX && -f $WINDOWS && -n $compile ]] ||
    { echo "Pas de programmes compilés par outils/compiler-version.sh ($REPERE) : lancer d'abord outils/deployer.sh."; return 1; }
  [[ $(repere propre) == oui ]] ||
    { echo "Programmes compilés d'un arbre aux changements non commités ($REPERE) : rien de publié (outils/deployer.sh)."; return 1; }
  for sorte in linux-x86_64 windows-x86_64; do
    fichier=$LINUX
    [[ $sorte == linux-x86_64 ]] || fichier=$WINDOWS
    [[ $(repere "$sorte") == "$(sha256sum "$fichier" | cut -d' ' -f1)" ]] || {
      echo "$fichier n'est plus celui de sa compilation (empreinte ≠ $REPERE : compilation ordinaire, autre worktree) :"
      echo "rien de publié. Relancer outils/deployer.sh."
      return 1
    }
  done
  if [[ $compile != "$COMMIT" ]] && ! { git merge-base --is-ancestor "$compile" "$COMMIT" 2>/dev/null &&
    [[ -n $HORS_CODE ]] && ! git diff --name-only "$compile" "$COMMIT" | grep -vqE "$HORS_CODE"; }; then
    echo "Les programmes compilés viennent de ${compile:0:12}, et le code a changé depuis : lancer d'abord outils/deployer.sh."
    return 1
  fi
  # La date gravée avec la version (VANGUARD-VERSION:x.y.z+N, build.rs) est celle du code du commit compilé
  # (outils/date-du-code.sh), celle que portent aussi les nomenclatures de GitHub.
  gravee=$(grep -aoE 'VANGUARD-VERSION:[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+;' "$LINUX" | head -1 | sed 's/.*+//; s/;$//')
  [[ $gravee == "$(bash outils/date-du-code.sh "$compile")" ]] ||
    { echo "Date gravée dans le programme (${gravee:-absente}) ≠ celle du commit compilé : rien de publié."; return 1; }
  echo "$compile"
}
COMPILE=$(verifier_compilation) || { echo "$COMPILE"; exit 1; }
git fetch -q --tags origin
if [[ $(git rev-parse origin/master) != "$COMMIT" ]]; then
  echo "Ce commit n'est pas la tête de master sur GitHub : lancer d'abord outils/deployer.sh."
  exit 1
fi
if gh release view "$TAG" >/dev/null 2>&1; then
  echo "La version $TAG est déjà publiée."
  exit 0
fi
# Aucun lien mort, avant d'attendre GitHub : les téléchargements du README (…/releases/latest/download/<nom>) visent
# les fichiers de cette version, qui sera la dernière (outils/liens.py).
python3 outils/liens.py --version vanguard-windows-x86_64.exe vanguard-linux-x86_64 SHA256SUMS.txt \
  $(bash outils/sbom.sh --noms) ||
  { echo "Liens : rien de publié."; exit 1; }

DOSSIER=$(mktemp -d)
trap 'rm -rf "$DOSSIER"' EXIT
# Les nomenclatures (SBOM) d'ici, avant d'attendre GitHub : un cargo-cyclonedx absent ou d'une autre version
# s'arrête maintenant, pas après dix minutes. Comparées plus bas à celles du passage attesté de ci.yml.
bash outils/sbom.sh "$DOSSIER/sbom" >/dev/null || { echo "Nomenclatures (SBOM) : rien de publié."; exit 1; }
cp "$LINUX" "$DOSSIER/vanguard-linux-x86_64"
cp "$WINDOWS" "$DOSSIER/vanguard-windows-x86_64.exe"
# Les copies qui partent, relues : celles-là, et pas un fichier remplacé entre la vérification et la copie.
[[ $(sha256sum "$DOSSIER/vanguard-linux-x86_64" | cut -d' ' -f1) == "$(repere linux-x86_64)" &&
  $(sha256sum "$DOSSIER/vanguard-windows-x86_64.exe" | cut -d' ' -f1) == "$(repere windows-x86_64)" ]] ||
  { echo "Copie des programmes différente de leur compilation : rien de publié."; exit 1; }
# Les failles connues, revérifiées sur les fichiers mêmes qui partent (outils/failles-programmes.sh, comme dans
# deployer.sh) : depuis, une compilation ordinaire a pu remplacer ceux de target/ par d'autres, sans leur liste, sans
# toucher .commit-compile, et une faille paraître. Avant d'attendre GitHub.
outils/failles-programmes.sh "$DOSSIER/vanguard-linux-x86_64" "$DOSSIER/vanguard-windows-x86_64.exe" ||
  { echo "Programmes : rien de publié."; exit 1; }
# Les protections des fichiers mêmes qui partent, lues dans leurs en-têtes sans les lancer (vanguard deploiement
# verifier-binaire, src/deploiement/binaire.rs) : PIE statique, marque RELRO et pile non exécutable pour Linux ; DLL
# depuis System32, manifeste, ASLR, DEP et relocalisations pour Windows. Lues par la copie Linux qui part, dont
# l'empreinte vient d'être relue. Chacun avec le système qu'il doit être (--attendu) : un fichier échangé ou d'une
# autre architecture est refusé. Lue telle quelle par outils/essais-signature.sh.
verifier_binaires() { # système fichiers…
  "$DOSSIER/vanguard-linux-x86_64" deploiement verifier-binaire --attendu "$@"
}
{ verifier_binaires linux "$DOSSIER/vanguard-linux-x86_64" &&
  verifier_binaires windows "$DOSSIER/vanguard-windows-x86_64.exe"; } ||
  { echo "Protections des programmes : rien de publié."; exit 1; }

# Une exécution de GitHub attendue au plus tant de secondes : un runner qui ne vient jamais (file d'attente bloquée)
# tiendrait publier-version.sh ouvert pour toujours. Rend le code de gh run watch (--exit-status), 124 quand le délai
# est passé, et le dit. Lue telle quelle par outils/essais-signature.sh.
attendre_execution() { # exécution, secondes au plus
  local code=0
  # -k : un gh qui ignore TERM est tué 10 s plus tard ; timeout rend alors 137 (KILL), le même délai passé.
  timeout -k 10 "$2" gh run watch "$1" --exit-status >/dev/null 2>&1 || code=$?
  ((code != 137)) || code=124
  ((code != 124)) || echo "⚠ Exécution $1 de GitHub pas finie après $(($2 / 60)) minutes : attente abandonnée."
  return "$code"
}

# Ce qui n'entre pas dans les programmes compilés, une liste fermée, plus étroite que .github/hors-code.txt (qui
# compte aussi outils/, donc la recette de compilation) : les captures d'écran et l'image de partage du README, que
# deployer.sh committe après la version (« Captures d'écran : vX.Y.Z »), et la page des fonctions (« Page des
# fonctions : vX.Y.Z »). Ni src/, ni build.rs, ni Cargo.toml ne citent ces chemins (relu par
# outils/essais-signature.sh) ; build.rs ne lit que des fichiers nommés (assets/oui.tsv, assets/yara/…,
# assets/vanguard.ico…), pas des dossiers ; et outils/date-du-code.sh les saute (hors-code.txt les contient) : la
# date gravée reste celle du code. Tout autre fichier, même hors du programme (.md, outils/, ci.yml), n'y est pas.
HORS_COMPILATION='^(assets/captures/[A-Za-z0-9][A-Za-z0-9._-]*\.png|assets/captures/VERSION|assets/partage\.png|docs/index\.html)$'
# Une entrée de « git diff-tree --raw » permise dans la liste : un fichier ordinaire (100644, 100755) ajouté, changé
# ou qui l'est devenu, ou un effacement (000000) ; un lien symbolique (120000) ou un sous-module (160000) nommé comme
# une capture n'est pas ce que deployer.sh committe (relecture adverse du lot publier-version, T1).
ENTREE_HORS_COMPILATION='^:[0-7]{6} ((100644|100755) [0-9a-f]{40} [0-9a-f]{40} [AMT]|000000 [0-9a-f]{40} 0{40} D)$'
# Le 2e commit vient après le 1er, en ligne droite jusqu'à la tête de master (COMMIT), et chaque commit entre les deux
# ne touche que HORS_COMPILATION, en fichiers ordinaires : les deux compilent le même code. Appelée dans les deux sens :
# (commit compilé, commit de la CI) quand la CI a tourné après, (commit de la CI, commit compilé) quand elle a tourné
# avant. Code 0 seulement alors ; une fusion, un commit hors de la ligne, un fichier hors de la liste (un
# renommage compte pour ses deux chemins), un lien ou un sous-module, une réponse de git illisible : 1. Lue telle
# quelle par outils/essais-signature.sh.
descendant_hors_compilation() { # commit d'avant, commit d'après
  local de=$1 vers=$2 fusions premiers tous c champs i
  [[ $de =~ ^[0-9a-f]{40}$ && $vers =~ ^[0-9a-f]{40}$ && $de != "$vers" ]] || return 1
  git merge-base --is-ancestor "$de" "$vers" 2>/dev/null || return 1
  git merge-base --is-ancestor "$vers" "$COMMIT" 2>/dev/null || return 1
  fusions=$(git rev-list --merges "$de..$vers" 2>/dev/null) || return 1
  [[ -z $fusions ]] || return 1
  premiers=$(git rev-list --first-parent "$de..$vers" 2>/dev/null) || return 1
  tous=$(git rev-list "$de..$vers" 2>/dev/null) || return 1
  [[ -n $tous && $premiers == "$tous" ]] || return 1
  for c in $tous; do
    [[ $c =~ ^[0-9a-f]{40}$ ]] || return 1
    # Avec -z, chaque entrée fait deux éléments : « :modes shas état », puis le chemin. Un élément vide en dernier :
    # git a fini sans erreur (un chemin n'est jamais vide).
    mapfile -d '' champs < <(git diff-tree --no-commit-id --raw -r --no-renames -z "$c" 2>/dev/null && printf '\0')
    [[ ${#champs[@]} -gt 0 && -z ${champs[-1]} ]] || return 1
    unset 'champs[-1]'
    (( ${#champs[@]} % 2 == 0 )) || return 1
    for ((i = 0; i < ${#champs[@]}; i += 2)); do
      [[ ${champs[i]} =~ $ENTREE_HORS_COMPILATION && ${champs[i + 1]} =~ $HORS_COMPILATION ]] || return 1
    done
  done
}

# Les outils de la chaîne C (outils/chaine-c.sh) qui diffèrent entre le repère d'ici (lignes « outil ») et le journal
# de la CI (OUTILS-VANGUARD) : montrés quand les empreintes diffèrent, pour dire d'où vient l'écart ; rien n'en
# dépend. Seuls les noms et valeurs de la forme qu'écrit chaine-c.sh sont repris du journal. Lue telle quelle par
# outils/essais-signature.sh.
outils_differents() { # journal de la CI
  local nom valeur ici ecarts=()
  while IFS='=' read -r nom valeur; do
    ici=$(sed -n "s/^outil $nom=//p" "${REPERE:-}" 2>/dev/null | head -n 1)
    [[ $ici == "$valeur" ]] || ecarts+=("  $nom : « ${ici:-pas relevé ici} » ici, « $valeur » dans la CI")
  done < <(tr -d '\r' <<<"$1" | grep -oE 'OUTILS-VANGUARD [a-z0-9-]{1,30}=[A-Za-z0-9 ._:+()/,~-]{1,120}$' |
    cut -d' ' -f2- | awk -F= '!vu[$1]++')
  if ((${#ecarts[@]})); then
    echo "Outils de compilation qui diffèrent (outils/chaine-c.sh ; CONTRIBUTING.md, « Compilation reproductible ») :"
    printf '%s\n' "${ecarts[@]}"
  fi
  return 0
}

# Les programmes Linux et Windows qui partent doivent être ceux que la CI a compilés du même code : son travail
# « reproductible » (.github/workflows/ci.yml) les compile deux fois par la même recette et écrit leurs empreintes
# dans son journal (EMPREINTE-VANGUARD-LINUX, -WINDOWS). Sans cette comparaison, un programme altéré sur cet ordinateur
# (chaîne Rust, éditeur de liens, fichier de config de cargo) serait signé et publié avec une CI verte à côté
# (campagne d'attaque n° 6, F1). Seulement une exécution de master (push, nuit ou à la main), du commit compilé, ou
# d'un commit d'avant ou d'après dont rien de ce qui est compilé n'a changé : en ligne droite, sans fusion, chaque
# commit entre les deux ne touchant que la liste fermée HORS_COMPILATION (descendant_hors_compilation, dans un sens
# ou dans l'autre ; après : les captures et la page des fonctions que deployer.sh committe après la version, et sur
# lesquels la CI tourne). Pas .github/hors-code.txt, trop large ici : il laisse passer outils/ (dont la recette de la
# compilation, outils/compiler-version.sh et outils/chaine-zig.sh), .cargo/audit.toml, tout .md, et un écart à
# travers une fusion (relecture du lot publier-version, recommandation acceptée). Code 0 : mêmes empreintes ; 1 :
# différentes (la raison) ; 2 : aucune exécution de la CI n'en a pour ce code. Lue telle quelle par
# outils/essais-signature.sh.
empreintes_de_la_ci() {
  local id sha apres travail journal linux windows ici_linux ici_windows
  ici_linux=$(sha256sum "$DOSSIER/vanguard-linux-x86_64" | cut -d' ' -f1)
  ici_windows=$(sha256sum "$DOSSIER/vanguard-windows-x86_64.exe" | cut -d' ' -f1)
  while read -r id sha; do
    [[ $id =~ ^[0-9]+$ ]] || continue
    apres=
    if [[ $sha != "$COMPILE" ]]; then
      if descendant_hors_compilation "$sha" "$COMPILE"; then
        apres=", avant ${COMPILE:0:12} sans rien de compilé changé"
      elif descendant_hors_compilation "$COMPILE" "$sha"; then
        apres=", après ${COMPILE:0:12} sans rien de compilé changé"
      else
        continue
      fi
    fi
    travail=$(gh run view "$id" --json jobs \
      -q '.jobs[] | select(.name == "reproductible" and .conclusion == "success") | .databaseId' | head -n 1)
    [[ $travail =~ ^[0-9]+$ ]] || continue
    journal=$(gh run view "$id" --job "$travail" --log 2>/dev/null) || continue
    linux=$(grep -oE 'EMPREINTE-VANGUARD-LINUX [0-9a-f]{64}' <<<"$journal" | tail -n 1 | cut -d' ' -f2 || true)
    windows=$(grep -oE 'EMPREINTE-VANGUARD-WINDOWS [0-9a-f]{64}' <<<"$journal" | tail -n 1 | cut -d' ' -f2 || true)
    [[ -n $linux && -n $windows ]] || continue
    if [[ $linux != "$ici_linux" || $windows != "$ici_windows" ]]; then
      [[ $linux == "$ici_linux" ]] ||
        echo "Linux : ${ici_linux:0:16}… ici, ${linux:0:16}… dans la CI (exécution $id, ${sha:0:12})."
      [[ $windows == "$ici_windows" ]] ||
        echo "Windows : ${ici_windows:0:16}… ici, ${windows:0:16}… dans la CI (exécution $id, ${sha:0:12})."
      outils_differents "$journal"
      return 1
    fi
    echo "exécution $id, ${sha:0:12}$apres"
    return 0
  done < <(gh run list --workflow ci.yml --branch master --limit 30 --json databaseId,headSha,headBranch,event \
    -q '.[] | select(.headBranch == "master" and (.event == "push" or .event == "schedule"
      or .event == "workflow_dispatch")) | "\(.databaseId) \(.headSha)"')
  return 2
}
# La CI de ce commit tourne encore (poussé à l'instant par deployer.sh) : sa compilation reproductible est attendue.
# VANGUARD_PUBLIER_SANS_EMPREINTES_CI=1 publie quand même (outils de compilation d'ici différents de ceux de la CI,
# CONTRIBUTING.md, « Compilation reproductible »), et le dit.
CODE_CI=0
EMPREINTES_CI=$(empreintes_de_la_ci) || CODE_CI=$?
if ((CODE_CI == 2)); then
  EN_COURS=$(gh run list --workflow ci.yml --branch master --commit "$COMMIT" --limit 5 --json databaseId,status \
    -q '[.[] | select(.status != "completed")][0].databaseId // ""')
  if [[ $EN_COURS =~ ^[0-9]+$ ]]; then
    echo "Attente de la CI de ce commit (exécution $EN_COURS, compilation reproductible : jusqu'à 40 minutes)…"
    # Son code ne compte pas : un autre travail en échec n'empêche pas de lire les empreintes, relues ensuite.
    # Deux heures : son plus long travail en a 75 minutes au plus (ci.yml), plus l'attente d'un runner.
    attendre_execution "$EN_COURS" 7200 || true
    CODE_CI=0
    EMPREINTES_CI=$(empreintes_de_la_ci) || CODE_CI=$?
  fi
fi
if ((CODE_CI == 0)); then
  echo "✔ Programmes Linux et Windows identiques à ceux de la compilation reproductible de la CI ($EMPREINTES_CI)."
  if [[ $EMPREINTES_CI == *", après "* ]]; then
    CI_APRES=$(sed -nE 's/^exécution [0-9]+, ([0-9a-f]{12}), après .*/\1/p' <<<"$EMPREINTES_CI")
    [[ -n $CI_APRES ]] || { echo "Provenance de la CI illisible ($EMPREINTES_CI) : rien de publié."; exit 1; }
    # Le commit entier, pour l'historique signé : le seul de la ligne entre la version et la tête qui commence ainsi,
    # et qui passe encore descendant_hors_compilation ; sinon, rien de publié.
    CI_APRES_COMPLET=$(git rev-list "$COMPILE..$COMMIT" 2>/dev/null | grep -xE "${CI_APRES}[0-9a-f]{28}" || true)
    [[ $CI_APRES_COMPLET =~ ^[0-9a-f]{40}$ ]] && descendant_hors_compilation "$COMPILE" "$CI_APRES_COMPLET" ||
      { echo "Commit de la CI $CI_APRES introuvable ou ambigu dans la ligne de master : rien de publié."; exit 1; }
  fi
elif [[ -n ${VANGUARD_PUBLIER_SANS_EMPREINTES_CI:-} ]]; then
  [[ -z $EMPREINTES_CI ]] || echo "$EMPREINTES_CI"
  echo "⚠ Programmes Linux et Windows publiés sans être ceux de la CI (VANGUARD_PUBLIER_SANS_EMPREINTES_CI) : dit dans les notes et l'historique signé."
  PASSE_DROITS+=(sans-empreintes-ci)
else
  if ((CODE_CI == 1)); then
    echo "$EMPREINTES_CI"
    echo "Programmes Linux ou Windows différents de ceux de la compilation reproductible de la CI : rien de publié."
  else
    echo "Aucune compilation reproductible réussie de la CI (ci.yml, master) pour ce code : rien de publié."
  fi
  echo "  (VANGUARD_PUBLIER_SANS_EMPREINTES_CI=1 outils/publier-version.sh pour publier quand même, et le dire.)"
  exit 1
fi

# Une exécution dont les nomenclatures valent d'être publiées : « attester » réussi, et ses essais avec, « linux »
# réussi et « windows » réussi ou sauté (ci.yml le saute quand le code Windows n'a pas changé). Sans ça, un commit dont
# les essais Linux échouaient aurait ses nomenclatures attestées quand même : « attester » ne dépend que d'elles.
attestee_et_essayee() {
  [[ $(gh run view "$1" --json jobs -q '[.jobs[] | select(
      (.name == "attester" and .conclusion == "success") or (.name == "linux" and .conclusion == "success")
      or (.name == "windows" and (.conclusion == "success" or .conclusion == "skipped")))
    | .name] | unique | length') == 3 ]]
}

# Les nomenclatures (SBOM) attestées de ce code : celles du travail « nomenclatures » de ci.yml pour ce commit, ou pour
# un commit d'avant dont le programme est le même (seuls des captures, la documentation ou les outils ont changé
# depuis : .github/hors-code.txt, la liste que lit aussi ci.yml). Seulement une exécution de master (headBranch relu),
# lancée par un envoi, la nuit ou à la main : celle d'une autre branche, ou d'une demande de fusion, tourne avec le
# ci.yml qu'elle apporte, et un compte GitHub pris ferait ainsi publier des nomenclatures faites ailleurs. Sur master,
# le travail tourne sans cache (ci.yml). Son code d'ensemble ne compte pas (la nuit, un fuzzing en échec n'y change
# rien) : comptent « attester » et les essais (attestee_et_essayee), et l'artefact « nomenclatures » encore là.
avec_nomenclatures() {
  local id sha
  while read -r id sha; do
    [[ -n $id ]] || continue
    if [[ $sha != "$COMMIT" ]]; then
      git merge-base --is-ancestor "$sha" "$COMMIT" 2>/dev/null || continue
      # Un fichier du programme a changé depuis : ces nomenclatures-là ne valent pas pour ce commit.
      [[ -n $HORS_CODE ]] || continue
      git diff --name-only "$sha" "$COMMIT" | grep -vqE "$HORS_CODE" && continue
      # Ce qui fait les nomenclatures est « hors code » : changé depuis, celles d'ici ne seraient plus les siennes.
      git diff --quiet "$sha" "$COMMIT" -- outils/sbom.sh outils/date-du-code.sh .github/hors-code.txt || continue
    fi
    # Seulement un passage dont le travail « attester » a réussi (celui d'une attestation en échec ne se publierait
    # pas, plus bas) et dont les essais n'ont pas échoué : on en relance plutôt un neuf.
    attestee_et_essayee "$id" || continue
    if [[ -n $(gh api "repos/{owner}/{repo}/actions/runs/$id/artifacts" \
      -q '.artifacts[] | select(.name == "nomenclatures" and (.expired | not)) | .name') ]]; then
      echo "$id"
      return
    fi
  done < <(gh run list --workflow ci.yml --branch master --limit 20 \
    --json databaseId,headSha,headBranch,event \
    -q '.[] | select(.headBranch == "master" and (.event == "push" or .event == "schedule"
      or .event == "workflow_dispatch")) | "\(.databaseId) \(.headSha)"')
}
RUN=$(avec_nomenclatures)
if [[ -z $RUN ]]; then
  # La CI de ce commit tourne encore (attendue plus haut pour sa compilation reproductible, mais un passage relancé à
  # la main peut suivre) : attendue, puis relue.
  EN_COURS=$(gh run list --workflow ci.yml --branch master --commit "$COMMIT" --limit 5 --json databaseId,status \
    -q '[.[] | select(.status != "completed")][0].databaseId // ""')
  if [[ $EN_COURS =~ ^[0-9]+$ ]]; then
    echo "Attente de la CI de ce commit (exécution $EN_COURS) pour ses nomenclatures attestées…"
    attendre_execution "$EN_COURS" 7200 || true
    RUN=$(avec_nomenclatures)
  fi
fi
if [[ -z $RUN ]]; then
  echo "Nomenclatures attestées de ce commit : CI relancée sur master (quelques minutes)…"
  # Les exécutions déjà là pour ce commit (son envoi, par exemple) ne sont pas celle qu'on attend.
  AVANT=$(gh run list --workflow ci.yml --commit "$COMMIT" --limit 20 --json databaseId -q '.[].databaseId')
  gh workflow run ci.yml --ref master
  for _ in {1..30}; do
    RUN=$(gh run list --workflow ci.yml --branch master --commit "$COMMIT" --event workflow_dispatch --limit 1 \
      --json databaseId \
      -q '.[0].databaseId // ""')
    [[ -n $RUN ]] && ! grep -qx -- "$RUN" <<<"$AVANT" && break
    RUN=""
    sleep 5
  done
  [[ -n $RUN ]] || { echo "La CI relancée n'a pas démarré : rien de publié."; exit 1; }
  # Son code ne compte pas : seuls « attester », « linux » et « windows » comptent, relus plus bas. Deux heures : son plus
  # long travail en a 75 minutes au plus (ci.yml), plus l'attente d'un runner.
  CODE_RUN=0
  attendre_execution "$RUN" 7200 || CODE_RUN=$?
  if ((CODE_RUN == 124)); then
    echo "La CI relancée n'a pas fini à temps : rien de publié."
    exit 1
  fi
  attestee_et_essayee "$RUN" ||
    { echo "CI relancée ($RUN) : nomenclatures pas attestées ou essais Linux/Windows en échec : rien de publié."; exit 1; }
fi
gh run download "$RUN" -n nomenclatures -D "$DOSSIER/ci" >/dev/null
# Relu sur l'exécution même dont on publie les nomenclatures, quelle que soit la façon dont elle a été trouvée.
SHA_RUN=$(gh run view "$RUN" --json headSha -q .headSha)
BRANCHE_RUN=$(gh run view "$RUN" --json headBranch,event -q '"\(.headBranch) \(.event)"')
case $BRANCHE_RUN in
  "master push" | "master schedule" | "master workflow_dispatch") ;;
  *)
    echo "Nomenclatures faites sur « $BRANCHE_RUN », pas sur master par un envoi, la nuit ou à la main : rien de publié."
    exit 1
    ;;
esac
if [[ $(tr -d '[:space:]' <"$DOSSIER/ci/commit.txt") != "$SHA_RUN" ]]; then
  echo "Nomenclatures : commit.txt n'est pas le commit de leur passage ($SHA_RUN) : rien de publié."
  exit 1
fi

# Les nomenclatures faites ici (outils/sbom.sh), octet pour octet celles du passage : son travail « attester »
# (.github/workflows/ci.yml) les a attestées, et c'est ce que la page publie. Puis chaque attestation vérifiée
# (Sigstore, registre public Rekor) : signée par ci.yml de ce dépôt, sur master, au commit de ce passage, sur un runner
# de GitHub. Exigée depuis la 0.89 : rien ne se publie sans. Linux et Windows ne sont pas attestés : compilés ici, pas
# par GitHub ; la mise à jour intégrée les vérifie par la signature Ed25519 de l'auteur (outils/signer-versions.sh),
# comme le disent les notes.
DEPOT_CODE=d9v3/vanguard-beta
RELANCE="relancer la CI (gh workflow run ci.yml --ref master), puis outils/publier-version.sh"
[[ -d $DOSSIER/ci/sbom ]] ||
  { echo "Le passage $RUN n'a pas de nomenclatures : rien de publié ; $RELANCE."; exit 1; }
for f in "$DOSSIER/sbom/"*.cdx.json; do
  cmp -s "$f" "$DOSSIER/ci/sbom/${f##*/}" ||
    { echo "Nomenclature ${f##*/} différente de celle du passage $RUN : rien de publié ; $RELANCE."; exit 1; }
done
[[ $(ls "$DOSSIER/ci/sbom/" | wc -l) == "$(ls "$DOSSIER/sbom/" | wc -l)" ]] ||
  { echo "Le passage $RUN n'a pas les mêmes nomenclatures qu'ici : rien de publié."; exit 1; }
for f in "$DOSSIER/sbom/"*.cdx.json; do
  gh attestation verify "$f" -R "$DEPOT_CODE" --signer-workflow "$DEPOT_CODE/.github/workflows/ci.yml" \
    --source-ref refs/heads/master --source-digest "$SHA_RUN" --deny-self-hosted-runners >/dev/null ||
    { echo "Attestation de ${f##*/} absente ou invalide (passage $RUN) : rien de publié."; exit 1; }
done
echo "✔ Nomenclatures attestées par GitHub (ci.yml, master, ${SHA_RUN:0:12})."

# Le programme Windows publié doit être celui qu'une passe réussie de la VM a fait tourner, octet pour octet : la CI
# teste la cible MSVC sur Windows, Wine a ses faux verts, et seule la VM essaie ce .exe-là sur un vrai Windows. Une
# porte de qualité, pas de sécurité. Sa preuve : le verdict OK, signé par le surveillant de la file d'essais (HMAC du
# secret de la file), d'un travail signé qui a fait tourner ce .exe (outils/vm-tester.sh --verdict) ; deployer.sh
# vient de l'y déposer. Tant que la file n'est pas réinstallée (pas de secret ici : code 3), la ligne de
# resultats/historique.txt qu'écrit test.ps1 en sert encore, et c'est dit : n'importe quel programme qui écrit dans
# le partage pourrait l'écrire (campagne d'attaque n° 3). Attendue VANGUARD_ATTENTE_VM minutes (40 par défaut). Une
# passe en échec, ou aucune : rien de publié. VANGUARD_PUBLIER_SANS_VM=1 publie quand même (VM en panne), et le dit.
VM_HISTORIQUE=$HOME/Windows/VANGUARD-TEST/resultats/historique.txt
EXE_PUBLIE=$(sha256sum "$DOSSIER/vanguard-windows-x86_64.exe" | cut -d' ' -f1)
# Les lignes de l'historique finissent par \r\n (écrites sous Windows).
passe_de_la_vm() {
  local code=0 ligne
  ligne=$(bash outils/vm-tester.sh --verdict "$EXE_PUBLIE" 2>/dev/null) || code=$?
  if ((code == 0)); then
    echo "OK, tout est passé (verdict signé de la file d'essais : $ligne)"
  elif ((code == 3)); then
    ligne=$(tr -d '\r' <"$VM_HISTORIQUE" 2>/dev/null | grep -E " sha256 $EXE_PUBLIE\$" | tail -n 1)
    [[ -z $ligne ]] || echo "$ligne [NON AUTHENTIFIÉ : historique.txt, file d'essais pas réinstallée]"
  fi
}
if [[ -n ${VANGUARD_PUBLIER_SANS_VM:-} ]]; then
  echo "⚠ Programme Windows publié sans passe de la VM sur ce .exe (VANGUARD_PUBLIER_SANS_VM) : dit dans les notes et l'historique signé."
  PASSE_DROITS+=(sans-vm)
else
  fin=$((SECONDS + 60 * ${VANGUARD_ATTENTE_VM:-40}))
  [[ -n $(passe_de_la_vm) ]] || echo "Programme Windows : attente de sa passe dans la VM (${VANGUARD_ATTENTE_VM:-40} min au plus)…"
  while [[ -z $(passe_de_la_vm) ]] && ((SECONDS < fin)); do
    sleep 20
  done
  PASSE=$(passe_de_la_vm)
  [[ -n $PASSE ]] || PASSE="aucune passe de la VM ne l'a essayé"
  if [[ $PASSE != *"OK, tout est passé"* ]]; then
    echo "Programme Windows ($EXE_PUBLIE) : $PASSE : rien de publié."
    echo "  (VANGUARD_PUBLIER_SANS_VM=1 outils/publier-version.sh pour publier sans elle.)"
    exit 1
  fi
  [[ $PASSE != *"NON AUTHENTIFIÉ"* ]] || echo "⚠ Porte de la VM non authentifiée : réinstaller la file d'essais (outils/vm-tester.sh --installer)."
  echo "✔ Programme Windows essayé tel quel dans la VM : ${PASSE%% ->*}"
fi
(cd "$DOSSIER" && sha256sum vanguard-windows-x86_64.exe vanguard-linux-x86_64 >SHA256SUMS.txt)
cp "$DOSSIER/sbom/"*.cdx.json "$DOSSIER/"

NOTES=$(notes)

# Rien de personnel dans la page de la version ni dans les programmes : chemins du dossier personnel, nom dans les
# métadonnées du .exe… (outils/confidentialite.py).
printf '%s\n' "$NOTES" | python3 outils/confidentialite.py --texte || { echo "Notes de la version : rien de publié."; exit 1; }
printf '%s\n' "$NOTES" | python3 outils/liens.py --texte || { echo "Liens des notes : rien de publié."; exit 1; }
python3 outils/confidentialite.py --binaire "$DOSSIER/vanguard-windows-x86_64.exe" "$DOSSIER/vanguard-linux-x86_64" \
  "$DOSSIER/"*.cdx.json || { echo "Programmes : rien de publié."; exit 1; }
# Les mêmes programmes, avec leur manifeste signé (outils/signer-versions.sh), dans le dépôt public des versions : la
# mise à jour depuis GitHub les y prend (src/mise_a_jour/github.rs), le code restant privé. Seule la dernière y reste.
# Signés AVANT la création de toute page : un contrôle de signer-versions.sh qui refuse (forme d'un programme,
# version, historique d'avant douteux, point sûr) n'arrête plus rien après coup, une page publique déjà en ligne et
# une relance qui disait « déjà publiée ».
DEPOT_VERSIONS=d9v3/vanguard-update
SIGNEE=""
if ! gh repo view "$DEPOT_VERSIONS" >/dev/null 2>&1; then
  echo "Dépôt public des versions absent ($DEPOT_VERSIONS, outils/depot-versions.sh) : mise à jour depuis GitHub non publiée."
else
  mkdir -p "$DOSSIER/avant"
  # L'historique signé de la version d'avant (ou, la première fois, son manifeste signé) : signer-versions.sh le
  # revérifie (et le compare au point sûr, le dernier historique publié d'ici), y ajoute cette version et le signe ;
  # publié avec elle, il permet de vérifier une copie qui n'est pas la dernière, une fois les pages d'avant retirées.
  # Un téléchargement raté (réseau, limite de l'API, jeton expiré) n'est permis qu'avec --premier tapé, et si le dépôt
  # n'a encore aucune version : sinon l'historique repartirait de zéro, et la boucle plus bas effacerait les pages
  # d'avant. API muette : sortie vide, pas « 0 », donc rien de publié.
  PREMIER=()
  if ! gh release download -R "$DEPOT_VERSIONS" -D "$DOSSIER/avant" -p 'historique.txt*' -p 'derniere.txt*' \
    >/dev/null 2>&1; then
    if [[ $(gh api "repos/$DEPOT_VERSIONS/releases?per_page=1" --jq length 2>/dev/null) == 0 ]]; then
      [[ -n $PREMIERE ]] && PREMIER=(--premier) || echo "⚠ Dépôt des versions vide : s'il n'a jamais rien eu, \
outils/publier-version.sh --premier ; sinon, il a été vidé, et l'historique ne repart pas de zéro."
    fi
  fi
  # Les passe-droits pris plus haut, et la CI faite après la version, gardés dans le bloc de cette version de
  # l'historique signé.
  PASSES=()
  for p in "${PASSE_DROITS[@]+"${PASSE_DROITS[@]}"}"; do
    PASSES+=(--passe-droit "$p")
  done
  [[ -z $CI_APRES_COMPLET ]] || PASSES+=(--ci-apres "$CI_APRES_COMPLET")
  outils/signer-versions.sh "${PREMIER[@]}" "${PASSES[@]}" "$DOSSIER" ||
    { echo "✖ Signature refusée (voir ci-dessus) : rien de publié, ni page ni mise à jour."; exit 1; }
  SIGNEE=1
fi

# Seule la dernière version garde son étiquette dans le dépôt du code (les vieilles ont été retirées le 7 nov. 2026,
# sauf avec-macos) : celle de la version qui précède est retirée, elle seule, une fois la nouvelle page en ligne et
# relue. Toutes ces conditions, sinon rien n'est retiré et c'est dit :
#  - PRECEDENTE, la page « dernière » relevée juste avant la création de celle-ci, a la forme vX.Y.Z, est plus petite
#    que cette version, et c'est la plus haute des étiquettes vX.Y.Z du dépôt sous elle : jamais avec-macos, jamais
#    une étiquette plus vieille ou plus récente ;
#  - la page de TAG est en ligne, ni brouillon ni préversion, ses fichiers exactement ceux de DOSSIER (mêmes noms,
#    mêmes empreintes SHA-256 relevées par GitHub), et son étiquette, légère, vise le commit compilé ;
#  - la page de PRECEDENTE n'est plus là (retirée juste avant) ;
#  - l'étiquette de PRECEDENTE est légère (celle que pose gh release create) et vise un commit d'avant le commit compilé.
# Une API muette ou illisible vaut refus. Le retrait est noté avant d'être demandé (date, étiquette, commit, version
# qui la remplace) dans ETIQUETTES_RETIREES, hors du dépôt : de quoi la reposer au besoin
# (git push origin <commit>:refs/tags/<étiquette>). Lue telle quelle par outils/essais-signature.sh.
ETIQUETTES_RETIREES=${VANGUARD_ETIQUETTES_RETIREES:-${XDG_STATE_HOME:-$HOME/.local/state}/vanguard-dev/etiquettes-retirees.txt}
etiquettes_du_depot() { # une ligne « refs/tags/<nom> <type> <commit> » par étiquette ; code ≠ 0 si l'API ne répond pas
  gh api --paginate "repos/$DEPOT_CODE/git/matching-refs/tags/" -q '.[] | "\(.ref) \(.object.type) \(.object.sha)"'
}
retirer_etiquette_precedente() {
  local garde page fichiers attendus refs nouvelle avant plus_haute pages lignes _ type sha f
  garde="Étiquette de la version d'avant (${PRECEDENTE:-aucune page relevée}) gardée"
  if ! [[ $PRECEDENTE =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $PRECEDENTE != avec-macos && $PRECEDENTE != "$TAG" ]]; then
    echo "$garde : pas une étiquette de version d'avant."
    return 1
  fi
  if [[ $(printf '%s\n' "${PRECEDENTE#v}" "$VERSION" | sort -V | head -n 1) != "${PRECEDENTE#v}" ]]; then
    echo "$garde : plus récente que $TAG."
    return 1
  fi
  page=$(gh release view "$TAG" -R "$DEPOT_CODE" --json tagName,isDraft,isPrerelease \
    -q '"\(.tagName) \(.isDraft) \(.isPrerelease)"' 2>/dev/null) || page=
  if [[ $page != "$TAG false false" ]]; then
    echo "$garde : la page de $TAG n'est pas en ligne telle quelle (${page:-illisible})."
    return 1
  fi
  attendus=$(for f in "$DOSSIER/vanguard-windows-x86_64.exe" "$DOSSIER/vanguard-linux-x86_64" \
    "$DOSSIER/SHA256SUMS.txt" "$DOSSIER/"*.cdx.json; do
    printf '%s sha256:%s\n' "${f##*/}" "$(sha256sum "$f" | cut -d' ' -f1)"
  done | LC_ALL=C sort)
  fichiers=$(gh release view "$TAG" -R "$DEPOT_CODE" --json assets -q '.assets[] | "\(.name) \(.digest)"' \
    2>/dev/null | LC_ALL=C sort) || fichiers=
  if [[ -z $fichiers || $fichiers != "$attendus" ]]; then
    echo "$garde : les fichiers de la page de $TAG ne sont pas ceux publiés d'ici (noms ou empreintes)."
    return 1
  fi
  refs=$(etiquettes_du_depot 2>/dev/null) || refs=
  nouvelle=$(awk -v r="refs/tags/$TAG" '$1 == r' <<<"$refs")
  if [[ $nouvelle != "refs/tags/$TAG commit $COMPILE" ]]; then
    echo "$garde : l'étiquette $TAG ne vise pas le commit compilé (${nouvelle:-absente ou illisible})."
    return 1
  fi
  plus_haute=$(awk '{ print $1 }' <<<"$refs" | sed -n 's|^refs/tags/v\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\)$|\1|p' |
    sort -uV | awk -v v="$VERSION" '$0 == v { print p; exit } { p = $0 }')
  if [[ v$plus_haute != "$PRECEDENTE" ]]; then
    echo "$garde : la version d'avant dans le dépôt est ${plus_haute:-introuvable}, pas $PRECEDENTE."
    return 1
  fi
  pages=$(gh release list -R "$DEPOT_CODE" --limit 500 --json tagName -q '.[].tagName' 2>/dev/null) || pages=
  if ! grep -qxF -- "$TAG" <<<"$pages"; then
    echo "$garde : liste des pages illisible."
    return 1
  fi
  if grep -qxF -- "$PRECEDENTE" <<<"$pages"; then
    echo "$garde : sa page est encore en ligne."
    return 1
  fi
  avant=$(awk -v r="refs/tags/$PRECEDENTE" '$1 == r' <<<"$refs")
  lignes=$(grep -c . <<<"$avant" || true)
  read -r _ type sha <<<"$avant"
  if [[ $lignes != 1 || $type != commit || ! $sha =~ ^[0-9a-f]{40}$ || $sha == "$COMPILE" ]] ||
    ! git merge-base --is-ancestor "$sha" "$COMPILE" 2>/dev/null; then
    echo "$garde : elle n'est pas une étiquette légère sur un commit d'avant celui-ci (${avant:-absente})."
    return 1
  fi
  if ! { mkdir -p "$(dirname "$ETIQUETTES_RETIREES")" &&
    printf '%s %s %s remplacee-par %s\n' "$(date -u +%FT%TZ)" "$PRECEDENTE" "$sha" "$TAG" >>"$ETIQUETTES_RETIREES"; }; then
    echo "$garde : impossible de noter son retrait ($ETIQUETTES_RETIREES)."
    return 1
  fi
  if ! gh api -X DELETE "repos/$DEPOT_CODE/git/refs/tags/$PRECEDENTE" >/dev/null 2>&1; then
    echo "⚠ Étiquette $PRECEDENTE : GitHub a refusé son retrait, elle reste (noté quand même dans $ETIQUETTES_RETIREES)."
    return 1
  fi
  refs=$(etiquettes_du_depot 2>/dev/null) || refs=
  if [[ -z $refs ]] || awk -v r="refs/tags/$PRECEDENTE" '$1 == r { t = 1 } END { exit !t }' <<<"$refs"; then
    echo "⚠ Étiquette $PRECEDENTE : retrait demandé, mais pas confirmé par GitHub."
    return 1
  fi
  echo "Étiquette $PRECEDENTE retirée de $DEPOT_CODE (commit ${sha:0:12} ; noté dans $ETIQUETTES_RETIREES)."
}
# La page « dernière » d'avant, relevée avant que celle-ci la remplace.
PRECEDENTE=$(gh release view -R "$DEPOT_CODE" --json tagName -q .tagName 2>/dev/null || true)
gh release create "$TAG" --target "$COMPILE" --title "$NOM $VERSION" --notes "$NOTES" \
  "$DOSSIER/vanguard-windows-x86_64.exe" "$DOSSIER/vanguard-linux-x86_64" "$DOSSIER/SHA256SUMS.txt" \
  "$DOSSIER/"*.cdx.json
echo "Version $TAG publiée : $(gh release view "$TAG" --json url -q .url)"
PUBLIEE_SIGNEE=""
if [[ -n $SIGNEE ]] && gh release create "$TAG" -R "$DEPOT_VERSIONS" --title "$NOM $VERSION" --notes "$NOTES" \
  "$DOSSIER/vanguard-windows-x86_64.exe" "$DOSSIER/vanguard-linux-x86_64" \
  "$DOSSIER/SHA256SUMS.txt" "$DOSSIER/derniere.txt" "$DOSSIER/derniere.txt.sig" \
  "$DOSSIER/historique.txt" "$DOSSIER/historique.txt.sig"; then
  echo "Version $TAG signée dans $DEPOT_VERSIONS : les Vanguard sans clé la proposeront."
  PUBLIEE_SIGNEE=1
  # Le point sûr (outils/signer-versions.sh) : le dernier historique en ligne, signé, gardé ici hors du dépôt des
  # versions ; la signature suivante s'y comparera.
  POINT_SUR=${VANGUARD_HISTORIQUE_PUBLIE:-${XDG_STATE_HOME:-$HOME/.local/state}/vanguard-dev/historique-publie.txt}
  mkdir -p "$(dirname "$POINT_SUR")" && cp "$DOSSIER/historique.txt" "$POINT_SUR.nouveau" &&
    cp "$DOSSIER/historique.txt.sig" "$POINT_SUR.sig.nouveau" && mv -f "$POINT_SUR.sig.nouveau" "$POINT_SUR.sig" &&
    mv -f "$POINT_SUR.nouveau" "$POINT_SUR" || echo "⚠ Point sûr de l'historique pas gardé ($POINT_SUR)."
  for ancienne in $(gh release list -R "$DEPOT_VERSIONS" --limit 500 --json tagName -q '.[].tagName' | grep -vxF "$TAG"); do
    gh release delete "$ancienne" -R "$DEPOT_VERSIONS" --yes --cleanup-tag >/dev/null
  done
elif [[ -n $SIGNEE ]]; then
  echo "✖ Version non publiée dans $DEPOT_VERSIONS : relancer gh release create à la main (DOSSIER gardé : $DOSSIER)."
  trap - EXIT
fi
# Seule la dernière version a sa page : CHANGELOG.md garde ce que chacune a apporté. Les pages d'avant sont retirées
# sans leur étiquette (sans --cleanup-tag) ; puis l'étiquette de la seule version qui précède, une fois tout relu
# (retirer_etiquette_precedente) ; une plus vieille, ou une autre, reste. Rien de cela tant que la mise à jour signée
# n'est pas en ligne : la page d'avant reste celle qu'on peut vérifier.
if [[ -z $SIGNEE || -n $PUBLIEE_SIGNEE ]]; then
  for ancienne in $(gh release list --limit 500 --json tagName -q '.[].tagName' | grep -vxF "$TAG"); do
    gh release delete "$ancienne" --yes >/dev/null && echo "Page de $ancienne retirée."
  done
  retirer_etiquette_precedente || true
fi
command -v notify-send >/dev/null &&
  notify-send -a Vanguard -i vanguard "$NOM $VERSION publiée sur GitHub" "Page de la version : les deux programmes, leurs empreintes et leurs nomenclatures." || true
