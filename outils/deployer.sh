#!/usr/bin/env bash
# Compile Vanguard (Linux statique + Windows), l'installe localement et met à jour la clé USB VANGUARD si elle est branchée.
#   outils/deployer.sh                 compiler puis déployer
#   outils/deployer.sh --branchement   au branchement de la clé : récupérer la dernière version de GitHub, la
#                                      compiler si elle est nouvelle, puis copier
#   outils/deployer.sh --sans-compiler copier les dernières versions compilées (après chaque compilation)
#   outils/deployer.sh --local         comme sans option, mais rien ne part sur GitHub (ni le code, ni les tickets
#                                      du journal) ; le service de copie qui suit la compilation le respecte aussi
#   outils/deployer.sh --publier       comme sans option (gardée pour les anciens appels : chaque publication a
#                                      désormais sa page)
#   outils/deployer.sh --accepter-cle [DOSSIER]
#                                      comme --sans-compiler, sur une clé que l'auteur accepte telle qu'elle est :
#                                      une clé neuve (outils/preparer-cle.sh, cle-secours.sh --ecrire), un volume au
#                                      jeton inconnu (DOSSIER, son point de montage), ou la clé connue dont l'écart
#                                      avec sa référence a été regardé ; sa référence (manifeste) la reprend telle quelle
# La clé n'est jamais que celle de cet ordinateur (jeton connu, outils/cle-commun.sh), et rien n'y est écrit quand
# elle a changé depuis son dernier déploiement (comparée à sa référence AVANT toute écriture) : ce qui y a été planté
# en voyage n'entre jamais en silence dans la référence. Notification, puis --accepter-cle si c'est voulu.
# VANGUARD_INTERMEDIAIRE=1 : une version d'une série livrée d'affilée. Pas de page (la dernière de la série reprend
# leurs notes) ni de dépôt dans la VM Windows (son test automatique passerait sur chacune) : le Mac de GitHub et la VM
# ne voient que la dernière.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

LINUX=target/x86_64-unknown-linux-musl/release/vanguard
WINDOWS=target/x86_64-pc-windows-gnu/release/vanguard.exe
# Le repère de la compilation (outils/compiler-version.sh) : le commit compilé, l'arbre propre ou non, l'empreinte
# des deux programmes. Rien ne part (clé, VM, GitHub) dont les octets ne sont pas ceux qu'il a relevés.
REPERE_COMPILATION=target/.compilation
commit_compile() { sed -n 's/^commit //p' "$REPERE_COMPILATION" 2>/dev/null | head -1; }
# Le code a-t-il changé depuis le commit compilé ? Les commits qui ne touchent que ce que le programme n'intègre pas
# (captures, page des fonctions, documentation : .github/hors-code.txt) n'obligent pas à recompiler : le programme
# de ce commit-là est le même, et sa date gravée reste celle du commit compilé (celui que la page de la version
# étiquette, outils/publier-version.sh).
code_change_depuis() { # commit compilé
  local hors
  [[ -n $1 && -f $LINUX ]] || return 0
  [[ $1 != "$(git rev-parse HEAD)" ]] || return 1
  git merge-base --is-ancestor "$1" HEAD 2>/dev/null || return 0
  hors=$(grep -v '^#' .github/hors-code.txt 2>/dev/null | head -n 1)
  [[ -n $hors ]] || return 0
  git diff --name-only "$1" HEAD | grep -vqE "$hors"
}
MODE=${1:-}
if [[ $MODE == --publier ]]; then
  MODE=""
fi
ACCEPTER="" ACCEPTER_CLE=""
if [[ $MODE == --accepter-cle ]]; then
  ACCEPTER=1 ACCEPTER_CLE=${2:-} MODE=--sans-compiler
fi
# shellcheck source=outils/cle-commun.sh
source outils/cle-commun.sh
# « Seulement sur cet ordinateur » : rien n'est envoyé sur GitHub. Le repère dure 2 h, assez pour le service de copie
# que la compilation déclenche (--sans-compiler, qui sinon pousserait) ; un déploiement normal l'efface.
REPERE_LOCAL="${XDG_RUNTIME_DIR:-/tmp}/vanguard-deployer-local"
if [[ $MODE == --local ]]; then
  MODE=""
  touch "$REPERE_LOCAL"
elif [[ -z $MODE ]]; then
  rm -f "$REPERE_LOCAL"
fi
LOCAL=""
[[ -n $(find "$REPERE_LOCAL" -mmin -120 2>/dev/null) ]] && LOCAL=1

# Une alerte que personne ne lirait au branchement (vanguard-cle.service) sans notification.
avertir_cle() { # titre texte
  command -v notify-send >/dev/null && notify-send -a Vanguard -i vanguard -u critical -- "$1" "$2" || true
}

# Durée de chaque étape, dite à la fin : on voit où part le temps d'un déploiement.
DUREES=""
duree() { DUREES+="${DUREES:+ · }$1 $((SECONDS - $2)) s"; }
dire_durees() { [[ -z $DUREES ]] || echo "Durées : $DUREES (en tout $SECONDS s)."; }
# Copié seulement s'il a changé : une clé USB écrit lentement, et chaque écriture l'use un peu.
copier() { cmp -s "$1" "$2" 2>/dev/null || cp -f "$1" "$2"; }

# Erreurs du journal de Vanguard (plantages, PowerShell en échec…) : celles de cet ordinateur et celles que la clé
# rapporte des autres sont gardées dans retours/, puis envoyées en tickets GitHub avec gh (un ticket par erreur, les
# répétitions en commentaire ; outils/journal-vers-github.py). Sans Internet, elles attendent le déploiement suivant.
RETOURS="${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/retours"
rapatrier_journal() { # $1 : journal à vider, $2 : d'où il vient
  [[ -s $1 && -f $1 && ! -L $1 ]] || return 0
  mkdir -p "$RETOURS"
  local nb cote
  # Au-delà de la borne de src/journal.rs (4 Mio), ce n'est pas un journal que Vanguard a écrit (celui de la clé
  # s'écrit sur n'importe quel ordinateur) : son début mis de côté pour être regardé, rien n'en part sur GitHub.
  if (($(stat -c %s "$1") > 4 * 1024 * 1024)); then
    cote="$RETOURS/journal-demesure-$(date +%Y%m%d-%H%M%S).txt"
    head -c $((4 * 1024 * 1024)) "$1" >"$cote"
    : >"$1"
    echo "Journal $2 démesuré (plus de 4 Mio) : mis de côté ($cote), rien n'en est envoyé."
    command -v notify-send >/dev/null &&
      notify-send -a Vanguard -i vanguard "Vanguard : journal $2 démesuré, rien envoyé" "$cote" || true
    return 0
  fi
  nb=$(grep -c '^== ' "$1" || true)
  cat "$1" >>"$RETOURS/journal-erreurs.txt"
  cat "$1" >>"$RETOURS/a-envoyer-github.txt"
  : >"$1"
  echo "Journal $2 : $nb erreur(s) rapatriée(s) dans $RETOURS/journal-erreurs.txt"
  command -v notify-send >/dev/null &&
    notify-send -a Vanguard -i vanguard "Vanguard : $nb erreur(s) rapportée(s) ($2)" "$RETOURS/journal-erreurs.txt" || true
}
envoyer_journal() {
  [[ -z $LOCAL && -s $RETOURS/a-envoyer-github.txt ]] && command -v gh >/dev/null || return 0
  timeout 300 python3 outils/journal-vers-github.py "$RETOURS/a-envoyer-github.txt" ||
    echo "Journal : envoi sur GitHub impossible, il repartira au prochain déploiement."
}

# Programmes refusés par outils/failles-programmes.sh : rien ne part, ni sur la clé, ni dans la VM, ni sur GitHub.
# Une faille peut paraître n'importe quand, sans changement de code, et au branchement de la clé (vanguard-cle.service)
# personne ne lit cette sortie : une notification le dit, une seule pour les mêmes programmes en cinq minutes (le
# service de copie qui suit une compilation repasse aussitôt). Les journaux d'erreurs, eux, rentrent quand même : ils
# n'envoient aucun programme.
refuser() {
  local cle journal="" repere="${XDG_RUNTIME_DIR:-/tmp}/vanguard-refus.empreinte" empreinte
  echo "Déploiement arrêté : seuls les journaux d'erreurs sont rapatriés."
  rapatrier_journal "${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/journal-erreurs.txt" "de cet ordinateur"
  # La partition des journaux de la clé de cet ordinateur seulement, et seulement si la clé n'a pas changé : vider le
  # journal est une écriture.
  cle=$(cle_connue "./$LINUX" 2>/dev/null || true)
  if [[ -n $cle ]] && ./"$LINUX" deploiement comparer-cle "$cle" >/dev/null 2>&1; then
    journal=$(journal_de_la_cle "$cle" 2>/dev/null || true)
  fi
  [[ -z $journal ]] || rapatrier_journal "$journal/journal-erreurs.txt" "de la clé"
  envoyer_journal
  empreinte=$({ cat "$LINUX" "$WINDOWS" 2>/dev/null || true; } | sha256sum)
  if [[ -z $(find "$repere" -mmin -5 2>/dev/null) || $(cat "$repere" 2>/dev/null) != "$empreinte" ]]; then
    command -v notify-send >/dev/null && notify-send -a Vanguard -i vanguard "Vanguard : programmes refusés" \
      "Faille connue ou liste absente : rien n'est copié ni envoyé. Le détail : outils/failles-programmes.sh" || true
    echo "$empreinte" >"$repere"
  fi
  exit 1
}

compiler() {
  # Un programme qui part sur GitHub doit être celui de son commit : rien de compilé d'un arbre où le code a changé
  # sans être commité (une autre session, un essai en cours), qui partirait signé puis disparaîtrait. Seul un
  # déploiement local (--local) le permet, et son repère le dit (outils/publier-version.sh refuse alors de publier).
  if [[ -z $LOCAL && -n $(git status --porcelain -- src build.rs assets Cargo.toml Cargo.lock .cargo \
    rust-toolchain.toml) ]]; then
    echo "✖ Compilation refusée : le code a des changements non commités (git status) ; un programme publié est"
    echo "  celui de son commit. Les committer, ou outils/deployer.sh --local pour cet ordinateur seulement."
    avertir_cle "Vanguard : rien compilé ni copié" "Le code a des changements non commités : la clé n'est pas mise \
à jour (outils/deployer.sh le dit)."
    exit 1
  fi
  # Chaque programme porte la liste de ses dépendances, versions comprises (cargo auditable, section .dep-v0), que
  # cargo audit bin relit plus bas, et chez quiconque l'a téléchargé. Sans ces outils, rien n'est compilé : jamais de
  # programme publié sans sa liste. cargo-auditable dans la version de la CI (.github/workflows/ci.yml) : une autre
  # écrirait une autre liste, donc un autre programme, que la compilation reproductible ne retrouverait pas.
  # cargo-audit, lui, est vérifié par outils/failles-programmes.sh (--outil : avant la compilation, pas après).
  local auditable installes
  auditable=$(sed -n 's/.*cargo-auditable@\([0-9][0-9.]*\).*/\1/p' .github/workflows/ci.yml | head -1)
  installes=$(cargo install --list 2>/dev/null || true)
  if [[ -z $auditable ]]; then
    echo "✖ Compilation refusée : version de cargo-auditable introuvable dans .github/workflows/ci.yml."
    exit 1
  fi
  if ! grep -qxF "cargo-auditable v$auditable:" <<<"$installes"; then
    echo "✖ Compilation refusée : il faut cargo-auditable $auditable, celui de la CI (.github/workflows/ci.yml) : un"
    echo "  programme publié porte la liste de ses dépendances, la même qu'en CI."
    echo "  cargo install cargo-auditable --locked --version $auditable"
    exit 1
  fi
  outils/failles-programmes.sh --outil || exit 1
  # Liste des fabricants de plus d'un mois : on la rafraîchit avant de compiler (elle est intégrée au programme), et
  # elle part dans son propre commit. Sans Internet, on garde l'ancienne.
  if [[ -n $(find assets/oui.tsv -mtime +30) ]] && outils/maj-fabricants.sh; then
    if ! git diff --quiet -- assets/oui.tsv; then
      git commit -q -m "Fabricants : liste du $(date +%F)" -- assets/oui.tsv && echo "Liste des fabricants mise à jour."
    else
      touch assets/oui.tsv
    fi
  fi
  # Les deux programmes d'un seul cargo, qui les mène de front : l'optimisation finale (LTO, une seule unité de code)
  # n'occupe qu'un cœur chacune. Deux cargo lancés ensemble, eux, s'attendaient l'un l'autre (« Blocking waiting for
  # file lock on build directory ») : 97 s au lieu de 52 (mesuré le 19 oct. 2026). Par la recette que la CI refait
  # (outils/compiler-version.sh : chaîne épinglée, Cargo.lock tel quel, chemins de la compilation retirés).
  local debut=$SECONDS
  outils/compiler-version.sh
  duree compilation "$debut"
}

# Un seul déploiement à la fois : le service déclenché par la compilation attend la fin du lancement manuel.
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/vanguard-deployer.lock"
if [[ $MODE == --sans-compiler ]]; then
  # Le service part dès que le binaire Linux est écrit, alors que Windows compile encore :
  # attendre que cargo ait fini (3 s sans cargo, 15 min au plus) pour ne copier qu'une fois.
  for ((calme = 0, tours = 0; calme < 3 && tours < 900; tours++)); do
    if pgrep -x cargo >/dev/null; then calme=0; else calme=$((calme + 1)); fi
    sleep 1
  done
fi
flock 9
# Le dossier de compilation est partagé avec les worktrees : une compilation faite dans une branche en cours
# déclenche aussi ce service. Elle ne part ni sur la clé, ni sur cet ordinateur, ni sur GitHub ; le fichier de
# dépendances que cargo écrit à côté du programme dit d'où elle vient (.git/worktrees/<nom>/HEAD).
if [[ $MODE == --sans-compiler ]] && grep -qs "/\.git/worktrees/" "$LINUX.d" "${WINDOWS%.exe}.d"; then
  echo "Compilation venue d'une branche en cours (worktree) : rien n'est copié ni envoyé."
  # Une clé à adopter (preparer-cle.sh, cle-secours.sh --ecrire) ne reste pas sans programme en silence.
  [[ -z $ACCEPTER ]] || { echo "✖ --accepter-cle : relancer outils/deployer.sh (il recompile), puis --accepter-cle."; exit 1; }
  exit 0
fi

VENU_DE_GITHUB=""
if [[ $MODE == --branchement ]]; then
  # Dernière version de GitHub (code modifié depuis un autre ordinateur, puis poussé). Récupérée seulement sans
  # risque : aucun changement local en cours, et un historique qui ne fait qu'avancer. Sans Internet : on continue.
  if timeout 30 git fetch -q origin 2>/dev/null; then
    DISTANT=$(git rev-parse '@{upstream}' 2>/dev/null || true)
    if [[ -n $DISTANT && $DISTANT != $(git rev-parse HEAD) ]]; then
      if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
        echo "GitHub a une version plus récente, mais des changements locaux sont en cours : rien de récupéré."
      elif git merge-base --is-ancestor HEAD "$DISTANT"; then
        git merge -q --ff-only "$DISTANT" && VENU_DE_GITHUB=1 && echo "Dernière version récupérée de GitHub."
      else
        echo "GitHub et ce PC ont chacun des commits que l'autre n'a pas : rien de récupéré (à fusionner à la main)."
      fi
    fi
  else
    echo "GitHub injoignable : copie de la version locale."
  fi
  if code_change_depuis "$(commit_compile)"; then
    compiler
  fi
elif [[ $MODE != --sans-compiler ]]; then
  compiler
fi
# Une DLL posée à côté de vanguard.exe ne doit jamais être chargée : le programme Windows qui n'en porte pas la
# garde (chargement.rs), ou pas son manifeste (UTF-8, asInvoker), ne part nulle part. Vérifié après la compilation,
# sur le programme qui va être copié, par le programme Linux (src/pe.rs, src/deploiement.rs) ; sans repli : un .exe
# non vérifié n'est jamais compté sain.
if [[ -f $WINDOWS ]]; then
  ./"$LINUX" deploiement verifier-pe "$WINDOWS" || {
    echo "✖ vanguard.exe non vérifié (DLL depuis System32, manifeste) : rien ne part. Un programme Linux d'avant « deploiement » ne sait pas le vérifier : recompiler."
    exit 1
  }
fi
# Les octets qui vont partir sont-ils ceux que outils/compiler-version.sh a relevés à la compilation ? Le dossier de
# compilation est partagé avec les worktrees, et une compilation ordinaire (cargo build) y remplace les programmes sans
# toucher le repère : ceux-là ne partent nulle part.
octets_compiles() {
  local sorte fichier attendu
  for sorte in linux-x86_64 windows-x86_64; do
    fichier=$LINUX
    [[ $sorte == linux-x86_64 ]] || fichier=$WINDOWS
    [[ -f $fichier ]] || continue
    attendu=$(sed -n "s/^$sorte //p" "$REPERE_COMPILATION" 2>/dev/null | head -1)
    [[ -n $attendu && $attendu == "$(sha256sum "$fichier" | cut -d' ' -f1)" ]] || return 1
  done
}
if ! octets_compiles; then
  if [[ $MODE == --sans-compiler && -z $ACCEPTER ]]; then
    echo "Programmes de target/ pas ceux de outils/compiler-version.sh (compilation ordinaire, autre dossier) : rien"
    echo "n'est copié."
    exit 0
  fi
  echo "✖ Programmes remplacés depuis leur compilation (empreintes ≠ $REPERE_COMPILATION) : rien ne part. Relancer"
  echo "  outils/deployer.sh (il recompile)."
  avertir_cle "Vanguard : rien copié ni envoyé" "Les programmes de target/ ne sont plus ceux de leur compilation : \
relancer outils/deployer.sh."
  exit 1
fi
# Aucun mot d'attaque que Vanguard cherche en clair dans les programmes qui partent : Defender a supprimé une
# version pour la seule présence de « sekurlsa:: » (outils/verifier-masque.sh, sur les programmes livrés tels quels).
MASQUES=("$LINUX")
[[ -f $WINDOWS ]] && MASQUES+=("$WINDOWS")
bash outils/verifier-masque.sh "${MASQUES[@]}" || { echo "✖ mot d'attaque en clair dans le programme : rien ne part."; exit 1; }
# Les failles connues de leurs dépendances, lues dans la liste que chaque programme porte (outils/failles-programmes.sh,
# avis traités comme par cargo deny) : une seule, et rien ne part, ni sur la clé, ni dans la VM, ni sur GitHub
# (refuser, plus haut).
PROGRAMMES=("$LINUX")
[[ -f $WINDOWS ]] && PROGRAMMES+=("$WINDOWS")
outils/failles-programmes.sh "${PROGRAMMES[@]}" || refuser
# Page de la version sur GitHub (Releases) : chaque publication a la sienne, 0.x.0 comme 0.x.y. Il n'y en a qu'une par
# jour : le lien « dernière version » du README mène toujours à celle du jour, et le Mac de GitHub ne compile qu'une
# fois par jour. Une version intermédiaire (VANGUARD_INTERMEDIAIRE) va sur la clé et sur GitHub (le code) sans page :
# la suivante la reprend (outils/publier-version.sh).
# Captures d'écran du README (assets/captures/) : refaites pour chaque page publiée, puisque le menu montre le numéro
# de la version téléchargée. Vanguard y tourne sur une copie des données, sans rien toucher de vrai, et ce qui
# identifierait la maison est masqué (outils/captures.py). Elles partent dans leur propre commit, comme la liste des
# fabricants. En cas d'échec, le README garde celles d'avant.
A_PUBLIER=""
if [[ -z $MODE ]]; then
  VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
  if [[ -z $LOCAL && -z ${VANGUARD_INTERMEDIAIRE:-} ]] &&
    ! timeout 30 gh release view "v$VERSION" >/dev/null 2>&1; then
    A_PUBLIER=1
  fi
  T_CAPTURES=$SECONDS
  if [[ -n $A_PUBLIER && $(cat assets/captures/VERSION 2>/dev/null) != "$VERSION" ]]; then
    if command -v uv >/dev/null && timeout 900 uv run -q --no-project --with pyte python outils/captures.py "$LINUX"; then
      git add assets/captures assets/partage.png
      # Les captures ne sont pas dans le programme (.github/hors-code.txt) : celui qui vient d'être compilé reste
      # celui du commit compilé, que outils/publier-version.sh étiquette et publie.
      git commit -q -m "Captures d'écran : v$VERSION" -- assets/captures assets/partage.png &&
        echo "Captures d'écran refaites (v$VERSION)."
    else
      echo "Captures d'écran non refaites : le README garde celles d'avant."
    fi
    duree captures "$T_CAPTURES"
  fi
  # La page des fonctions (docs/index.html, servie par GitHub Pages) : refaite pour chaque version publiée à partir
  # du code, du programme compilé et de la dernière vérification, puis committée à part. En cas d'échec, GitHub
  # Pages garde celle d'avant.
  if [[ -n $A_PUBLIER ]]; then
    if python3 outils/page-fonctions.py --complet --programme "$LINUX" --sortie docs/index.html >/dev/null; then
      git add docs/index.html
      if git diff --quiet --cached -- docs/index.html; then
        echo "Page des fonctions déjà à jour."
      elif git commit -q -m "Page des fonctions : v$VERSION" -- docs/index.html; then
        echo "Page des fonctions refaite (v$VERSION) : docs/index.html."
      fi
    else
      echo "Page des fonctions non refaite : GitHub Pages garde celle d'avant."
    fi
  fi
fi
install -Dm755 "$LINUX" "$HOME/.cargo/bin/vanguard"
# Sauvegarde hors de la maison : les commits partent vers le dépôt GitHub (sans bloquer s'il n'y a pas d'Internet),
# seulement si rien de personnel n'y paraît : code, messages, auteur (outils/confidentialite.py), et si aucun lien
# n'est mort : documentation, programme, scripts, licences (outils/liens.py).
T_ENVOI=$SECONDS
if [[ -n $LOCAL ]]; then
  echo "Rien n'est envoyé sur GitHub (déploiement local)."
elif git remote get-url origin >/dev/null 2>&1; then
  if ! python3 outils/confidentialite.py --envoi; then
    echo "Rien n'est envoyé sur GitHub : un détail personnel paraît dans les commits (voir ci-dessus)."
  # Une page de version suit : les liens de téléchargement du README se vérifient contre ses fichiers, pas contre la
  # dernière version en ligne (absente sur un dépôt neuf, d'une version en retard sinon).
  elif ! python3 outils/liens.py ${A_PUBLIER:+--version vanguard-windows-x86_64.exe vanguard-linux-x86_64 vanguard-macos SHA256SUMS.txt}; then
    echo "Rien n'est envoyé sur GitHub : un lien est mort (voir ci-dessus)."
  # La sortie est gardée : un refus de GitHub (règles de master, historique qui a divergé) n'est pas une panne
  # d'Internet, et le redire au prochain déploiement n'y changerait rien.
  elif ENVOI=$(timeout 30 git push -q origin HEAD 2>&1); then
    echo "Code envoyé sur GitHub."
    # La page du dépôt suit le dépôt : description et version, lien, sujets (outils/github.py, .github/depot.json).
    python3 outils/github.py || echo "Page du dépôt sur GitHub pas mise à jour (voir ci-dessus)."
    # La page de la version, s'il en faut une (A_PUBLIER, plus haut), vient à la fin du déploiement.
    if [[ -n $A_PUBLIER ]]; then
      PUBLIER=1
    elif [[ -z $MODE ]] && ! timeout 30 gh release view "v$VERSION" >/dev/null 2>&1; then
      echo "Version v$VERSION sans page sur GitHub (version intermédiaire) : la prochaine page la reprendra."
    fi
  elif grep -q "rejected" <<<"$ENVOI"; then
    echo "GitHub refuse l'envoi de master :"
    grep -E "rejected|^remote: - " <<<"$ENVOI" | sed 's/^/  /'
  else
    echo "GitHub injoignable : le code partira au prochain déploiement."
  fi
fi
[[ -n $LOCAL ]] || duree "envoi GitHub" "$T_ENVOI"
# Icône du lanceur (Vanguard.desktop : Icon=vanguard) : le bouclier ouvert sur un trou noir (outils/icone.py), une
# image par taille de 16 à 512 px, pour que la barre et le lanceur n'aient pas à réduire eux-mêmes la plus grande.
ICONES="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
for png in assets/icones/vanguard-*.png; do
  t=${png##*-}
  t=${t%.png}
  install -Dm644 "$png" "$ICONES/${t}x$t/apps/vanguard.png"
done
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$ICONES" || true

# Sans clé branchée, Vanguard écrit son journal dans son dossier de cet ordinateur (fonctions du journal : en tête).
rapatrier_journal "${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/journal-erreurs.txt" "de cet ordinateur"
envoyer_journal

# Dossier partagé avec la machine virtuelle Windows (\\host.lan\Data\VANGUARD-TEST dans Windows) : à chaque
# déploiement, le programme et les scripts de test y sont remplacés par les derniers ; les résultats restent. Dans la
# VM, TESTER-VANGUARD.bat ouvre le menu des tests (son choix 6 teste seul chaque nouvelle version, en arrière-plan).
VM="$HOME/Windows/VANGUARD-TEST"
# Un test qui tourne dans la VM garde son programme : le remplacer en pleine passe mélangerait deux versions. Le témoin
# est celui du menu des tests, périmé au bout de 3 h comme là-bas.
EN_COURS="$VM/resultats/.test-en-cours.txt"
# La version qui aura sa page : aussi un essai signé de la file (test.ps1 en administrateur), dont le verdict signé
# par le surveillant est la porte de outils/publier-version.sh. Déposé même pendant une passe du menu : le surveillant
# attend sa fin. Seulement la file réinstallée (secret ici).
if [[ -z ${VANGUARD_INTERMEDIAIRE:-} && -n $A_PUBLIER && -f $WINDOWS && -d $HOME/Windows ]]; then
  if [[ -s ${XDG_CONFIG_HOME:-$HOME/.config}/vanguard/file-essais/secret ]]; then
    bash outils/vm-tester.sh --exe "$WINDOWS" --sans-console --sans-attendre ||
      echo "VM Windows : essai de la file pas déposé (voir ci-dessus) : sans son verdict signé, pas de page."
  else
    echo "VM Windows : file d'essais pas réinstallée (pas de secret) : la page se fiera à historique.txt, non authentifié."
  fi
fi
if [[ -n ${VANGUARD_INTERMEDIAIRE:-} ]]; then
  echo "VM Windows : version intermédiaire d'une série, rien n'y est déposé (la dernière le sera)."
elif [[ -n $(find "$EN_COURS" -mmin -180 2>/dev/null) ]]; then
  echo "VM Windows : un test y tourne (depuis $(date -r "$EN_COURS" +%H:%M)) : rien n'y est déposé cette fois."
elif [[ -d $HOME/Windows && -f $WINDOWS ]]; then
  mkdir -p "$VM/programme" "$VM/resultats" "$VM/a-lancer"
  cp -f "$WINDOWS" "$VM/programme/vanguard.exe"
  # Le lanceur de la clé aussi : test.ps1 l'essaie dans un dossier sans programme (Vanguard bloqué par Defender).
  cp -f outils/test-windows/test.ps1 outils/test-windows/menu.ps1 "outils/cle/Lancer Vanguard.bat" "$VM/programme/"
  cp -f outils/test-windows/TESTER-VANGUARD.bat outils/test-windows/LISEZMOI.txt "$VM/"
  # La version déposée et l'empreinte du programme : le menu les montre, le test automatique part quand elles changent.
  printf '%s\r\n%s\r\n' "$(./"$LINUX" --version)" "$(sha256sum "$WINDOWS" | cut -c1-16)" >"$VM/programme/version.txt"
  if [[ -s $VM/resultats/historique.txt ]]; then
    echo "VM Windows : version déposée. Dernière passe : $(tail -n 1 "$VM/resultats/historique.txt" | sed 's/ *->.*//')"
  else
    echo "VM Windows : version déposée dans $VM."
  fi
fi

# Nouvelle version envoyée : sa page sur GitHub (Releases), en dernier, car la version macOS se compile sur un Mac de
# GitHub (quelques minutes d'attente) ; la clé et la VM sont alors déjà à jour.
publier_la_version() {
  [[ -n ${PUBLIER:-} ]] || return 0
  echo "Nouvelle version v$VERSION : sa page sur GitHub…"
  local debut=$SECONDS
  if outils/publier-version.sh; then
    # La description du dépôt montre la dernière version publiée : elle change maintenant.
    python3 outils/github.py || echo "Page du dépôt sur GitHub pas mise à jour (voir ci-dessus)."
  else
    echo "Page de la version pas publiée (voir ci-dessus) : relancer outils/publier-version.sh."
  fi
  duree "page de la version" "$debut"
}

# La clé de cet ordinateur : le volume au témoin vanguard.cle dont le jeton est connu ici (outils/cle-commun.sh). Un
# volume étiqueté VANGUARD au jeton inconnu ne reçoit rien. --accepter-cle DOSSIER : celui que l'auteur désigne.
CODE_CLE=0
if [[ -n $ACCEPTER_CLE ]]; then
  # Normalisé (barre finale de la complétion, « .. ») : sinon son identifiant de volume ne se lit pas, et la
  # référence part sous un autre nom que celui du branchement suivant.
  CLE=$(realpath -s -- "$ACCEPTER_CLE")
  if [[ ! -d $CLE || ! -f $CLE/vanguard.cle || -L $CLE/vanguard.cle ]]; then
    echo "✖ $CLE ne porte pas le témoin vanguard.cle d'une clé VANGUARD : rien n'y est écrit."
    exit 1
  fi
else
  CLE=$(cle_connue "./$LINUX") || CODE_CLE=$?
fi
if [[ -z $CLE ]]; then
  if ((CODE_CLE == 3)); then
    echo "Volume au témoin VANGUARD, au jeton inconnu de cet ordinateur : rien n'y est écrit (ni programme, ni code"
    echo "source). S'il est à vous : outils/deployer.sh --accepter-cle <son dossier>."
    avertir_cle "Volume VANGUARD inconnu : rien n'y est écrit" "Ce n'est pas une clé déployée ici (jeton absent ou \
inconnu). Si elle est à vous : outils/deployer.sh --accepter-cle <son dossier>."
  elif ((CODE_CLE != 0)); then
    echo "✖ Clé VANGUARD pas cherchée (le programme ne sait pas la reconnaître : recompiler) : rien n'y est écrit."
  else
    echo "Clé VANGUARD non branchée : elle sera mise à jour au prochain branchement."
  fi
  publier_la_version
  dire_durees
  # Une clé demandée (--accepter-cle) mais pas trouvée, ou pas cherchée : un échec ; un volume inconnu, non.
  if [[ -n $ACCEPTER ]] || ((CODE_CLE != 0 && CODE_CLE != 3)); then exit 1; fi
  exit 0
fi
T_CLE=$SECONDS

# La clé comparée à sa référence AVANT toute écriture (src/protection/manifeste.rs) : un raccourci, une image, un
# ventoy.json ou une archive tldr posés pendant le voyage y sont vus, et rien n'est écrit (ni programme, ni journal
# vidé, ni manifeste), jusqu'à l'accord de l'auteur (--accepter-cle). Sans cela, la référence réécrite après la copie
# les reprenait, et le bilan disait « la clé n'a pas changé » (campagne d'attaque n° 3).
# Un déploiement arrêté en route (clé retirée, rsync ou copie en échec) laisse son repère, au jeton de la clé : le
# suivant ne compte pas ce que le déploiement pose lui-même et a pu laisser à moitié écrit (il le réécrit), tout le
# reste si. Retiré une fois la référence réécrite.
REPRISE=${XDG_STATE_HOME:-$HOME/.local/state}/vanguard/deploiement-en-cours-$(jeton_du_volume "$CLE")
REPRENDRE=()
[[ -f $REPRISE && $REPRISE != */deploiement-en-cours- ]] && REPRENDRE=(--reprise)
if [[ -z $ACCEPTER ]] && ! ECART=$(./"$LINUX" deploiement comparer-cle "$CLE" "${REPRENDRE[@]}" 2>&1); then
  echo "✖ La clé VANGUARD ($CLE) a changé depuis son dernier déploiement : rien n'y est écrit."
  sed 's/^/  /' <<<"$ECART"
  echo "  Regarder ces fichiers (un raccourci ou une image plantés sont un piège). S'ils sont voulus :"
  echo "  outils/deployer.sh --accepter-cle (la clé est réécrite et sa référence la reprend telle quelle)."
  avertir_cle "Clé VANGUARD changée : rien n'y est écrit" "$(head -c 300 <<<"$ECART")
À regarder avant tout usage ; si c'est voulu : outils/deployer.sh --accepter-cle"
  publier_la_version
  dire_durees
  exit 1
fi

# Témoins de la clé, écrits par le programme (src/deploiement.rs) : le jeton d'identité (src/protection/cles_connues.rs),
# 32 caractères hexadécimaux tirés une fois et gardés ensuite (seulement pour une clé acceptée : une clé connue a
# déjà le sien) ; cet ordinateur le note (vanguard manifeste --ecrire, plus bas). La partition des journaux reçoit le
# même jeton. Puis l'empreinte de cet ordinateur (SHA-1 de /etc/machine-id) dans vanguard.cle : partout ailleurs,
# Vanguard remonte la clé en lecture seule sous Linux (src/protection/cle.rs). Avant la copie vers la partition des
# journaux et avant le manifeste.
./"$LINUX" deploiement temoins "$CLE" || { echo "✖ Témoins de la clé non écrits : clé pas mise à jour."; exit 1; }
# Le jeton est là maintenant (tiré pour une clé acceptée) : le repère d'un déploiement en cours, à son nom.
REPRISE=${XDG_STATE_HOME:-$HOME/.local/state}/vanguard/deploiement-en-cours-$(jeton_du_volume "$CLE")
mkdir -p "${REPRISE%/*}" && : >"$REPRISE"

# Partition VANGUARDLOG (la seule modifiable sur les autres ordinateurs) : celle du même disque, au jeton de la clé
# (outils/cle-commun.sh) ; elle se monte en même temps que VANGUARD, parfois une seconde après. Son journal d'erreurs
# est rapatrié ici puis vidé, pour améliorer Vanguard.
JOURNAL=""
for _ in {1..10}; do
  JOURNAL=$(journal_de_la_cle "$CLE") || break
  [[ -n $JOURNAL ]] && break
  sleep 1
done
if [[ -n $JOURNAL ]]; then
  touch "$JOURNAL/vanguard-journal.cle"
  cp -f "$CLE/vanguard.jeton" "$JOURNAL/vanguard.jeton"
  rapatrier_journal "$JOURNAL/journal-erreurs.txt" "de la clé"
  envoyer_journal
fi

mkdir -p "$CLE"/{Linux,Windows,donnees,source}
copier "$LINUX" "$CLE/Linux/vanguard"
[[ -f $WINDOWS ]] && copier "$WINDOWS" "$CLE/Windows/vanguard.exe"
# Version macOS : compilée sur un Mac de GitHub (.github/workflows/macos.yml, chaque nuit si le code a changé),
# récupérée ici quand une compilation plus récente a réussi. Sans Internet ou sans gh : on garde la dernière.
MAC=target/macos
if [[ -z $LOCAL ]] && command -v gh >/dev/null; then
  # La dernière compilation réussie qui a vraiment produit le programme : une exécution de nuit sautée (code
  # inchangé) réussit aussi, sans rien produire. Comme pour la page de la version (outils/publier-version.sh) :
  # seulement une exécution de master, lancée par la nuit ou à la main (celle d'une autre branche tourne avec son
  # macos.yml et le cache qu'elle a pu préparer), d'un commit déjà dans celui-ci ; puis son commit.txt et l'empreinte
  # que son journal annonce, relus sur ce qui est téléchargé (campagne d'attaque n° 3).
  RUN=""
  for execution in $(timeout 20 gh run list --workflow macos.yml --branch master --status success --limit 20 \
    --json databaseId,headSha,headBranch,event \
    -q '.[] | select(.headBranch == "master" and (.event == "schedule" or .event == "workflow_dispatch"))
      | "\(.databaseId):\(.headSha)"' 2>/dev/null || true); do
    git merge-base --is-ancestor "${execution#*:}" HEAD 2>/dev/null || continue
    if [[ -n $(timeout 20 gh api "repos/{owner}/{repo}/actions/runs/${execution%%:*}/artifacts" \
      -q '.artifacts[] | select(.name == "vanguard-macos" and (.expired | not)) | .name' 2>/dev/null) ]]; then
      RUN="${execution%%:*} ${execution#*:}"
      break
    fi
  done
  # Jamais une compilation plus ancienne que celle déjà là (celle de la dernière page, copiée par
  # publier-version.sh).
  ACTUEL=$(cat "$MAC/commit.txt" 2>/dev/null || true)
  if [[ -n $RUN && ${RUN#* } != "$ACTUEL" ]] &&
    ! { [[ -n $ACTUEL ]] && git merge-base --is-ancestor "${RUN#* }" "$ACTUEL" 2>/dev/null; }; then
    rm -rf "$MAC.nouveau"
    if timeout 120 gh run download "${RUN%% *}" -n vanguard-macos -D "$MAC.nouveau" >/dev/null 2>&1; then
      ANNONCEE=$(timeout 60 gh run view "${RUN%% *}" --log 2>/dev/null | grep -oE 'EMPREINTE-VANGUARD-MACOS [0-9a-f]{64}' |
        tail -1 | cut -d' ' -f2 || true)
      if [[ $(tr -d '[:space:]' <"$MAC.nouveau/commit.txt" 2>/dev/null) != "${RUN#* }" || -z $ANNONCEE ||
        $ANNONCEE != "$(sha256sum "$MAC.nouveau/vanguard" 2>/dev/null | cut -d' ' -f1)" ]]; then
        echo "Version macOS de GitHub écartée : commit.txt ou empreinte différents de son exécution (${RUN%% *})."
        rm -rf "$MAC.nouveau"
      else
        rm -rf "$MAC" && mv "$MAC.nouveau" "$MAC" && echo "Version macOS récupérée de GitHub (commit ${RUN#* })."
      fi
    fi
  fi
fi
# La version macOS passe la même vérification que les deux autres (outils/failles-programmes.sh, moitié par moitié) :
# un artefact compilé avant cargo auditable, donc sans sa liste, ou une faille parue depuis, et la clé garde la sienne.
if [[ -f $MAC/vanguard ]] && ! outils/failles-programmes.sh "$MAC/vanguard"; then
  echo "Version macOS pas copiée sur la clé (voir ci-dessus) : elle y reste telle qu'elle était."
elif [[ -f $MAC/vanguard ]]; then
  mkdir -p "$CLE/macOS"
  copier "$MAC/vanguard" "$CLE/macOS/vanguard"
  cp -f "outils/cle/Lancer Vanguard.command" "$CLE/"
  # Le Mac de GitHub ne compile pas chaque version (la nuit si le code a changé, et pour chaque page publiée) : la
  # version macOS de la clé peut retarder sur les deux autres, et c'est dit.
  VERSION_MAC=$(git show "$(cat "$MAC/commit.txt" 2>/dev/null):Cargo.toml" 2>/dev/null |
    sed -n 's/^version = "\(.*\)"/\1/p' | head -1)
  VERSION_ICI=$(./"$LINUX" --version | awk '{print $2}')
  if [[ -n $VERSION_MAC && $VERSION_MAC != "$VERSION_ICI" ]]; then
    echo "Clé : macOS en $VERSION_MAC (dernière compilation sur un Mac de GitHub), Linux et Windows en $VERSION_ICI."
  fi
fi
# macOS écrit dès le branchement (index Spotlight, journal des changements, corbeille) : ces témoins l'en
# dispensent, la clé reste propre même avant que Vanguard la protège.
touch "$CLE/.metadata_never_index" "$CLE/.Trashes"
mkdir -p "$CLE/.fseventsd" && touch "$CLE/.fseventsd/no_log"
cp -f outils/LISEZMOI.txt "$CLE/LISEZMOI.txt"
cp -f outils/README.txt "$CLE/README.txt"
# Mode d'emploi de chaque version, à côté de son programme : double-clic, terminal, PowerShell, invite de commandes.
for systeme in Linux Windows macOS; do
  if [[ -d $CLE/$systeme ]]; then
    cp -f "outils/cle/$systeme/LISEZMOI.txt" "outils/cle/$systeme/README.txt" "$CLE/$systeme/"
  fi
done
# Avis de licence des bibliothèques incluses dans les binaires (MIT, Apache… demandent de les joindre).
python3 outils/licences-tierces.py >/dev/null
cp -f LICENSE "$CLE/LICENSE.txt"
cp -f LICENCES-TIERCES.txt "$CLE/LICENCES-TIERCES.txt"
# Icône et nom du lecteur dans l'Explorateur, lanceurs à la racine. (Windows ne lance plus rien tout seul depuis une
# clé USB, depuis Windows 7 ; GNOME, lui, propose de lancer autorun.sh.)
cp -f assets/vanguard.ico "$CLE/vanguard.ico"
cp -f outils/cle/autorun.inf outils/cle/autorun.sh "outils/cle/Lancer Vanguard.bat" "$CLE/"
# Code source complet (avec l'historique git) pour continuer le développement depuis n'importe quel ordinateur.
# exFAT ne garde ni droits ni liens : -rt suffit, --modify-window tolère sa précision de 2 s. Les copies de travail
# des sessions Claude (.claude/worktrees, avec leurs propres compilations) restent sur l'ordinateur.
# Code 24 : des fichiers ont disparu pendant la copie (une autre session committe) ; le reste est copié, pas une panne.
rsync -rt --delete --modify-window=2 --exclude /target/ --exclude /.claude/worktrees/ ./ "$CLE/source/" ||
  { code=$?; ((code == 24)) || exit "$code"; }
# Exemples de tldr-pages sur la clé (src/guide/tldr/cle.rs) : lancé depuis la clé, le guide les a tout de suite, même
# sur un ordinateur sans Internet. Une fois par jour au plus ; sans Internet, la clé garde les siens. Avant le
# manifeste : une archive remplacée sur la clé par quelqu'un d'autre se verra au retour. Un programme d'avant
# « deploiement » échoue sur l'usage : le message le dit, et la clé garde ses archives.
./"$LINUX" deploiement tldr "$CLE/tldr" || echo "Exemples de tldr-pages non mis à jour sur la clé."
# Manifeste de la clé (src/protection/manifeste.rs) : l'empreinte de chaque fichier (vanguard.jeton compris), gardée
# sur cet ordinateur et jamais sur la clé ; le bilan la compare quand la clé revient de chez quelqu'un. La même
# commande note la clé parmi celles que cet ordinateur connaît, avec l'état de son carnet. Elle ne reprend sans accord
# que ce que ce déploiement vient de poser (programmes, guides, lanceurs, code source, tldr) : un fichier apparu
# depuis la comparaison du début la fait refuser (code 2), --accepter-cle la force.
FORCER=()
[[ -z $ACCEPTER ]] || FORCER=(--forcer)
CODE_MANIFESTE=0
./"$LINUX" manifeste --ecrire "$CLE" "${FORCER[@]}" || CODE_MANIFESTE=$?
if ((CODE_MANIFESTE == 2)); then
  avertir_cle "Clé VANGUARD : référence pas réécrite" "Un fichier est apparu sur la clé pendant le déploiement. À \
regarder ; si c'est voulu : outils/deployer.sh --accepter-cle"
  exit 1
elif ((CODE_MANIFESTE != 0)); then
  echo "Manifeste de la clé non écrit : le bilan ne pourra pas la comparer."
else
  rm -f "$REPRISE"
fi
sync
duree clé "$T_CLE"
echo "Clé VANGUARD à jour : $CLE ($(./"$LINUX" --version))"
# Une seule notification par version copiée : le lancement manuel et le service qui le suit copient les mêmes
# binaires. (Remplacer la notification ne suffit pas : la barre l'oublie dès que la bulle a disparu.)
EMPREINTE_FICHIER="${XDG_RUNTIME_DIR:-/tmp}/vanguard-notification.empreinte"
EMPREINTE=$({ cat "$LINUX" "$WINDOWS" 2>/dev/null || true; } | sha256sum)
if command -v notify-send >/dev/null && [[ $(cat "$EMPREINTE_FICHIER" 2>/dev/null) != "$EMPREINTE" ]]; then
  notify-send -a Vanguard -i vanguard "Clé VANGUARD à jour${VENU_DE_GITHUB:+ (depuis GitHub)}" "$(./"$LINUX" --version)" || true
  echo "$EMPREINTE" >"$EMPREINTE_FICHIER"
fi
publier_la_version
dire_durees
