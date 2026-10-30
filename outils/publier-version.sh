#!/usr/bin/env bash
# Publie la version de Cargo.toml sur GitHub (page « Releases ») : les trois programmes, sous des noms fixes que le
# README relie (…/releases/latest/download/<nom>), leurs empreintes SHA-256 et leurs nomenclatures (SBOM, attestées
# avec le programme macOS). À lancer après outils/deployer.sh, quand la version est compilée et poussée. La version macOS vient d'un Mac de GitHub (.github/workflows/macos.yml) :
# compilée pour ce commit si elle manque, en quelques minutes. Les notes reprennent toutes les versions déployées depuis
# la page précédente : une version intermédiaire (VANGUARD_INTERMEDIAIRE) n'a pas la sienne.
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

# Ce qui change, version par version : le titre de son commit, ses puces dessous (sans les lignes de co-auteur). Une
# seule version : son titre en gras, comme avant ; plusieurs : un titre « X.Y.Z : … » chacune. Puis comment
# télécharger.
notes() {
  local lignes nombre sha sujet puces
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
- **macOS** (Apple Silicon et Intel) : \`vanguard-macos\`, puis \`xattr -d com.apple.quarantine vanguard-macos\` et
  lancer dans le Terminal.

Empreintes SHA-256 : \`SHA256SUMS.txt\` (\`sha256sum -c SHA256SUMS.txt\`).

Sur la page de d9v3/vanguard-beta, les nomenclatures logicielles (SBOM CycloneDX : toutes les dépendances compilées,
versions et licences) : \`vanguard-<système>.cdx.json\`, une par programme, deux pour le Mac universel ; celles de
Linux et Windows décrivent leur code, pas le fichier publié. Le programme macOS et ces nomenclatures sont attestés par
GitHub, qui les a produits, à vérifier avec la GitHub CLI connectée (\`gh auth login\`), le nom du fichier changé
pour une nomenclature :

\`gh attestation verify vanguard-macos -R d9v3/vanguard-beta --signer-workflow d9v3/vanguard-beta/.github/workflows/macos.yml --source-ref refs/heads/master\`

Les programmes Windows et Linux, compilés par l'auteur, ne sont pas attestés : la mise à jour intégrée de Vanguard
les vérifie par la signature Ed25519 de l'auteur (dépôt d9v3/vanguard-update). \`SHA256SUMS.txt\` contrôle le
téléchargement, pas l'origine.

Ce qu'ont apporté les versions d'avant : \`CHANGELOG.md\` dans le dépôt.

---

Download the program for your system: \`vanguard-windows-x86_64.exe\` (Windows, unsigned: SmartScreen may warn, “More
info” then “Run anyway”), \`vanguard-linux-x86_64\` (any distribution: \`chmod +x\`, then run it in a terminal),
\`vanguard-macos\` (Apple Silicon and Intel: \`xattr -d com.apple.quarantine vanguard-macos\`, then run it in Terminal).
SHA-256 checksums: \`SHA256SUMS.txt\` (they check the download, not the origin). On the d9v3/vanguard-beta page,
software bills of materials (CycloneDX SBOM): \`vanguard-<system>.cdx.json\`, one per program, two for the universal
Mac one; the Linux and Windows ones describe their code, not the published file. The macOS program and the SBOMs are
attested by GitHub, which built them; check with the GitHub CLI logged in (\`gh auth login\`), changing the file name
for an SBOM: \`gh attestation verify vanguard-macos -R d9v3/vanguard-beta --signer-workflow d9v3/vanguard-beta/.github/workflows/macos.yml --source-ref refs/heads/master\`. The Windows and Linux programs, built by the author, are not attested: Vanguard's built-in
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
# .github/hors-code.txt), et HEAD celui de GitHub : la page de la version y renvoie, et le Mac de GitHub compile la
# tête de master. L'étiquette se pose sur le commit compilé : qui la recompile retrouve sa date gravée.
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
  # (outils/date-du-code.sh), celle que le Mac de GitHub grave aussi.
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
# Aucun lien mort, avant d'attendre le Mac : les téléchargements du README (…/releases/latest/download/<nom>) visent
# les fichiers de cette version, qui sera la dernière (outils/liens.py).
python3 outils/liens.py --version vanguard-windows-x86_64.exe vanguard-linux-x86_64 vanguard-macos SHA256SUMS.txt ||
  { echo "Liens : rien de publié."; exit 1; }

DOSSIER=$(mktemp -d)
trap 'rm -rf "$DOSSIER"' EXIT
# Les nomenclatures (SBOM) d'ici, avant d'attendre le Mac : un cargo-cyclonedx absent ou d'une autre version
# s'arrête maintenant, pas après dix minutes. Comparées plus bas à celles du passage Mac.
bash outils/sbom.sh "$DOSSIER/sbom" >/dev/null || { echo "Nomenclatures (SBOM) : rien de publié."; exit 1; }
cp "$LINUX" "$DOSSIER/vanguard-linux-x86_64"
cp "$WINDOWS" "$DOSSIER/vanguard-windows-x86_64.exe"
# Les copies qui partent, relues : celles-là, et pas un fichier remplacé entre la vérification et la copie.
[[ $(sha256sum "$DOSSIER/vanguard-linux-x86_64" | cut -d' ' -f1) == "$(repere linux-x86_64)" &&
  $(sha256sum "$DOSSIER/vanguard-windows-x86_64.exe" | cut -d' ' -f1) == "$(repere windows-x86_64)" ]] ||
  { echo "Copie des programmes différente de leur compilation : rien de publié."; exit 1; }
# Les failles connues, revérifiées sur les fichiers mêmes qui partent (outils/failles-programmes.sh, comme dans
# deployer.sh) : depuis, une compilation ordinaire a pu remplacer ceux de target/ par d'autres, sans leur liste, sans
# toucher .commit-compile, et une faille paraître. Avant d'attendre le Mac ; la version macOS l'est une fois récupérée.
outils/failles-programmes.sh "$DOSSIER/vanguard-linux-x86_64" "$DOSSIER/vanguard-windows-x86_64.exe" ||
  { echo "Programmes : rien de publié."; exit 1; }

# Une compilation macOS qui a vraiment produit le programme de ce code : celle de ce commit, ou celle d'un commit
# d'avant dont le programme est le même (seuls des captures, la documentation ou les outils ont changé depuis :
# .github/hors-code.txt, la liste que lisent aussi les workflows). Une exécution de nuit sautée (code inchangé)
# réussit aussi, sans rien produire : son artefact manque, elle est passée.
# Seulement une exécution de master (headBranch relu), lancée par la nuit ou à la main : celle d'une autre branche
# tourne avec le macos.yml de cette branche et le cache qu'elle a pu préparer, et un compte GitHub pris ferait ainsi
# signer par la clé de l'auteur un programme compilé ailleurs. master compile sans cache (macos.yml). Le passage
# de la branche sur le Mac, avant la fusion, reste un essai : il ne sert plus à la page.
avec_programme() {
  local id sha
  while read -r id sha; do
    [[ -n $id ]] || continue
    if [[ $sha != "$COMMIT" ]]; then
      git merge-base --is-ancestor "$sha" "$COMMIT" 2>/dev/null || continue
      # Un fichier du programme a changé depuis : cette compilation-là ne vaut pas pour ce commit.
      [[ -n $HORS_CODE ]] || continue
      git diff --name-only "$sha" "$COMMIT" | grep -vqE "$HORS_CODE" && continue
      # Ce qui fait les nomenclatures est « hors code » : changé depuis, celles d'ici ne seraient plus les siennes.
      git diff --quiet "$sha" "$COMMIT" -- outils/sbom.sh outils/date-du-code.sh .github/hors-code.txt || continue
    fi
    # Seulement un passage dont le travail « attester » a réussi : celui d'avant ce travail, ou d'une attestation
    # en échec, ne se publierait pas (plus bas) ; on en compile plutôt un neuf.
    [[ -n $(gh run view "$id" --json jobs \
      -q '.jobs[] | select(.name == "attester" and .conclusion == "success") | .name') ]] || continue
    if [[ -n $(gh api "repos/{owner}/{repo}/actions/runs/$id/artifacts" \
      -q '.artifacts[] | select(.name == "vanguard-macos" and (.expired | not)) | .name') ]]; then
      echo "$id"
      return
    fi
  done < <(gh run list --workflow macos.yml --branch master --status success --limit 20 \
    --json databaseId,headSha,headBranch,event \
    -q '.[] | select(.headBranch == "master" and (.event == "schedule" or .event == "workflow_dispatch"))
      | "\(.databaseId) \(.headSha)"')
}
RUN=$(avec_programme)
if [[ -z $RUN ]]; then
  echo "Compilation macOS de ce commit sur un Mac de GitHub (quelques minutes)…"
  # Les exécutions déjà là pour ce commit (une nuit sautée, par exemple) ne sont pas celle qu'on attend.
  AVANT=$(gh run list --workflow macos.yml --commit "$COMMIT" --limit 20 --json databaseId -q '.[].databaseId')
  gh workflow run macos.yml --ref master
  for _ in {1..30}; do
    RUN=$(gh run list --workflow macos.yml --branch master --commit "$COMMIT" --event workflow_dispatch --limit 1 \
      --json databaseId \
      -q '.[0].databaseId // ""')
    [[ -n $RUN ]] && ! grep -qx -- "$RUN" <<<"$AVANT" && break
    RUN=""
    sleep 5
  done
  [[ -n $RUN ]] || { echo "La compilation macOS n'a pas démarré : rien de publié."; exit 1; }
  gh run watch "$RUN" --exit-status >/dev/null || { echo "La compilation macOS a échoué : rien de publié."; exit 1; }
fi
gh run download "$RUN" -n vanguard-macos -D "$DOSSIER/mac" >/dev/null
cp "$DOSSIER/mac/vanguard" "$DOSSIER/vanguard-macos"
# Le programme Mac sort d'un runner de GitHub et la clé de l'auteur va le signer : contrôlé ici d'abord, par ce qui
# ne vient pas de l'artefact lui-même. Il doit être la compilation du commit de ce passage (commit.txt), et porter
# l'empreinte que ce passage a écrite dans son journal (.github/workflows/macos.yml) ; signer-versions.sh vérifie
# ensuite sa forme (Mach-O universel, Apple Silicon et Intel) et sa version gravée, celle des deux autres programmes.
# Ni l'un ni l'autre ne prouve que le runner n'a pas été piégé : seul un Mac de l'auteur le pourrait.
SHA_RUN=$(gh run view "$RUN" --json headSha -q .headSha)
# Relu sur l'exécution même qu'on va signer, quelle que soit la façon dont elle a été trouvée.
BRANCHE_RUN=$(gh run view "$RUN" --json headBranch,event -q '"\(.headBranch) \(.event)"')
if [[ $BRANCHE_RUN != "master schedule" && $BRANCHE_RUN != "master workflow_dispatch" ]]; then
  echo "Version macOS : compilée sur « $BRANCHE_RUN », pas sur master par la nuit ou à la main : rien de publié."
  exit 1
fi
if [[ $(tr -d '[:space:]' <"$DOSSIER/mac/commit.txt") != "$SHA_RUN" ]]; then
  echo "Version macOS : commit.txt n'est pas le commit de sa compilation ($SHA_RUN) : rien de publié."
  exit 1
fi
ANNONCEE=$(gh run view "$RUN" --log 2>/dev/null | grep -oE 'EMPREINTE-VANGUARD-MACOS [0-9a-f]{64}' | tail -1 |
  cut -d' ' -f2 || true)
if [[ -z $ANNONCEE || $ANNONCEE != "$(sha256sum "$DOSSIER/vanguard-macos" | cut -d' ' -f1)" ]]; then
  echo "Version macOS : son empreinte n'est pas celle du journal de sa compilation (${ANNONCEE:-absente}) : rien de publié."
  exit 1
fi
outils/failles-programmes.sh "$DOSSIER/vanguard-macos" || { echo "Version macOS : rien de publié."; exit 1; }

# Les nomenclatures (SBOM) faites ici (outils/sbom.sh), octet pour octet celles du passage Mac : son travail
# « attester » (.github/workflows/macos.yml) les a attestées avec le programme Mac, et c'est ce que la page publie.
# Puis chaque attestation vérifiée (Sigstore, registre public Rekor) : signée par macos.yml de ce dépôt, sur master, au
# commit de ce passage, sur un runner de GitHub. Exigée depuis la 0.89 : un passage d'avant ce travail n'en a pas, et
# rien ne se publie sans. Linux et Windows ne sont pas attestés : compilés ici, pas par GitHub ; la mise à jour
# intégrée les vérifie par la signature Ed25519 de l'auteur (outils/signer-versions.sh), comme le disent les notes.
DEPOT_CODE=d9v3/vanguard-beta
RELANCE="relancer le Mac (gh workflow run macos.yml --ref master), puis outils/publier-version.sh"
[[ -d $DOSSIER/mac/sbom ]] ||
  { echo "Le passage Mac ($RUN) n'a pas de nomenclatures : rien de publié ; $RELANCE."; exit 1; }
for f in "$DOSSIER/sbom/"*.cdx.json; do
  cmp -s "$f" "$DOSSIER/mac/sbom/${f##*/}" ||
    { echo "Nomenclature ${f##*/} différente de celle du passage Mac ($RUN) : rien de publié ; $RELANCE."; exit 1; }
done
[[ $(ls "$DOSSIER/mac/sbom/" | wc -l) == "$(ls "$DOSSIER/sbom/" | wc -l)" ]] ||
  { echo "Le passage Mac ($RUN) n'a pas les mêmes nomenclatures qu'ici : rien de publié."; exit 1; }
for f in "$DOSSIER/vanguard-macos" "$DOSSIER/sbom/"*.cdx.json; do
  gh attestation verify "$f" -R "$DEPOT_CODE" --signer-workflow "$DEPOT_CODE/.github/workflows/macos.yml" \
    --source-ref refs/heads/master --source-digest "$SHA_RUN" --deny-self-hosted-runners >/dev/null ||
    { echo "Attestation de ${f##*/} absente ou invalide (passage Mac $RUN) : rien de publié."; exit 1; }
done
echo "✔ Programme macOS et nomenclatures attestés par GitHub (macos.yml, master, ${SHA_RUN:0:12})."

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
  echo "⚠ Programme Windows publié sans passe de la VM sur ce .exe (VANGUARD_PUBLIER_SANS_VM)."
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
(cd "$DOSSIER" && sha256sum vanguard-windows-x86_64.exe vanguard-linux-x86_64 vanguard-macos >SHA256SUMS.txt)
cp "$DOSSIER/sbom/"*.cdx.json "$DOSSIER/"

NOTES=$(notes)

# Rien de personnel dans la page de la version ni dans les programmes : chemins du dossier personnel, nom dans les
# métadonnées du .exe… (outils/confidentialite.py).
printf '%s\n' "$NOTES" | python3 outils/confidentialite.py --texte || { echo "Notes de la version : rien de publié."; exit 1; }
printf '%s\n' "$NOTES" | python3 outils/liens.py --texte || { echo "Liens des notes : rien de publié."; exit 1; }
python3 outils/confidentialite.py --binaire "$DOSSIER/vanguard-windows-x86_64.exe" "$DOSSIER/vanguard-linux-x86_64" \
  "$DOSSIER/vanguard-macos" "$DOSSIER/"*.cdx.json || { echo "Programmes : rien de publié."; exit 1; }
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
  outils/signer-versions.sh "${PREMIER[@]}" "$DOSSIER" ||
    { echo "✖ Signature refusée (voir ci-dessus) : rien de publié, ni page ni mise à jour."; exit 1; }
  SIGNEE=1
fi
gh release create "$TAG" --target "$COMPILE" --title "$NOM $VERSION" --notes "$NOTES" \
  "$DOSSIER/vanguard-windows-x86_64.exe" "$DOSSIER/vanguard-linux-x86_64" "$DOSSIER/vanguard-macos" "$DOSSIER/SHA256SUMS.txt" \
  "$DOSSIER/"*.cdx.json
echo "Version $TAG publiée : $(gh release view "$TAG" --json url -q .url)"
PUBLIEE_SIGNEE=""
if [[ -n $SIGNEE ]] && gh release create "$TAG" -R "$DEPOT_VERSIONS" --title "$NOM $VERSION" --notes "$NOTES" \
  "$DOSSIER/vanguard-windows-x86_64.exe" "$DOSSIER/vanguard-linux-x86_64" "$DOSSIER/vanguard-macos" \
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
# Seule la dernière version a sa page : CHANGELOG.md garde ce que chacune a apporté. Les pages d'avant sont retirées,
# leurs étiquettes restent dans le dépôt (sans --cleanup-tag), pour recompiler une ancienne version au besoin. Pas
# tant que la mise à jour signée n'est pas en ligne : la page d'avant reste celle qu'on peut vérifier.
if [[ -z $SIGNEE || -n $PUBLIEE_SIGNEE ]]; then
  for ancienne in $(gh release list --limit 500 --json tagName -q '.[].tagName' | grep -vxF "$TAG"); do
    gh release delete "$ancienne" --yes >/dev/null && echo "Page de $ancienne retirée (son étiquette reste)."
  done
fi
command -v notify-send >/dev/null &&
  notify-send -a Vanguard -i vanguard "$NOM $VERSION publiée sur GitHub" "Page de la version : les trois programmes, leurs empreintes et leurs nomenclatures." || true

# La version macOS publiée est gardée comme une compilation récupérée (outils/deployer.sh ne la redemande pas) et
# copiée sur la clé si elle est branchée : sinon la clé garderait celle d'avant jusqu'au déploiement suivant.
rm -rf target/macos && mkdir -p target/macos && cp -R "$DOSSIER/mac/". target/macos/
# Seulement la clé de cet ordinateur (jeton connu, outils/cle-commun.sh), et seulement si elle est encore sa référence :
# comparée avant la copie, comme dans deployer.sh, pour que la réécriture du manifeste ne reprenne rien d'autre.
# shellcheck source=outils/cle-commun.sh
source outils/cle-commun.sh
CLE=$(cle_connue "./$LINUX" 2>/dev/null || true)
if [[ -n $CLE && -d $CLE/macOS ]]; then
  if ! ./"$LINUX" deploiement comparer-cle "$CLE" >/dev/null 2>&1; then
    echo "Clé VANGUARD différente de sa référence : la version macOS n'y est pas copiée (outils/deployer.sh le dit)."
  elif cp -f target/macos/vanguard "$CLE/macOS/vanguard" && sync; then
    echo "Version macOS $VERSION copiée sur la clé."
    # Le manifeste de la clé, écrit par deployer.sh avant cette copie, la reprend : sinon le bilan suivant dirait le
    # programme macOS remplacé.
    ./"$LINUX" manifeste --ecrire "$CLE" || echo "Manifeste de la clé non réécrit : relancer outils/deployer.sh."
  fi
fi
