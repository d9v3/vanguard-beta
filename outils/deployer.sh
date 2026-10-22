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
# VANGUARD_INTERMEDIAIRE=1 : une version d'une série livrée d'affilée. Pas de page (la dernière de la série reprend
# leurs notes) ni de dépôt dans la VM Windows (son test automatique passerait sur chacune) : le Mac de GitHub et la VM
# ne voient que la dernière.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

LINUX=target/x86_64-unknown-linux-musl/release/vanguard
WINDOWS=target/x86_64-pc-windows-gnu/release/vanguard.exe
# Commit dont viennent les binaires compilés : on ne recompile pas une version déjà compilée.
COMMIT_COMPILE=target/.commit-compile
MODE=${1:-}
if [[ $MODE == --publier ]]; then
  MODE=""
fi
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
  [[ -s $1 ]] || return 0
  mkdir -p "$RETOURS"
  local nb
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
  cle=$(find "/run/media/$USER" -maxdepth 2 -name vanguard.cle -printf '%h\n' 2>/dev/null | head -1 || true)
  [[ -z $cle ]] || journal=$(findmnt -nro TARGET -S LABEL=VANGUARDLOG 2>/dev/null | head -1 || true)
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
  git rev-parse HEAD >"$COMMIT_COMPILE"
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
  if [[ ! -f $LINUX || $(cat "$COMMIT_COMPILE" 2>/dev/null) != $(git rev-parse HEAD) ]]; then
    compiler
  fi
elif [[ $MODE != --sans-compiler ]]; then
  compiler
fi
# Une DLL posée à côté de vanguard.exe ne doit jamais être chargée : le programme Windows qui n'en porte pas la
# garde (chargement.rs) ne part nulle part. Vérifié après la compilation, sur le programme qui va être copié, par le
# programme Linux (src/machine/pe.rs) ; sans repli : un .exe non vérifié n'est jamais compté sain.
if [[ -f $WINDOWS ]]; then
  ./"$LINUX" deploiement verifier-pe "$WINDOWS" || {
    echo "✖ vanguard.exe non vérifié (DLL depuis System32) : rien ne part. Un programme Linux d'avant « deploiement » ne sait pas le vérifier : recompiler."
    exit 1
  }
fi
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
      # Les captures ne sont pas dans le programme : celui qui vient d'être compilé reste celui de ce commit, que
      # outils/publier-version.sh publiera.
      git commit -q -m "Captures d'écran : v$VERSION" -- assets/captures assets/partage.png &&
        echo "Captures d'écran refaites (v$VERSION)." && git rev-parse HEAD >"$COMMIT_COMPILE"
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
        echo "Page des fonctions refaite (v$VERSION) : docs/index.html." && git rev-parse HEAD >"$COMMIT_COMPILE"
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
  elif ! python3 outils/liens.py ${A_PUBLIER:+--version vanguard-windows-x86_64.exe vanguard-linux-x86_64 vanguard-macos}; then
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

CLE=$(find "/run/media/$USER" -maxdepth 2 -name vanguard.cle -printf '%h\n' 2>/dev/null | head -1)
if [[ -z $CLE ]]; then
  echo "Clé VANGUARD non branchée : elle sera mise à jour au prochain branchement."
  publier_la_version
  dire_durees
  exit 0
fi
T_CLE=$SECONDS

# Jeton d'identité de la clé (src/protection/cles_connues.rs) : 32 caractères hexadécimaux tirés une fois et gardés
# ensuite ; cet ordinateur le note (vanguard manifeste --ecrire, plus bas) et, depuis sa copie locale, ne reconnaît
# plus un volume au seul témoin vanguard.cle. La partition des journaux reçoit le même jeton.
if ! grep -qxE '[0-9a-fA-F]{32}' "$CLE/vanguard.jeton" 2>/dev/null; then
  head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$CLE/vanguard.jeton"
  echo >>"$CLE/vanguard.jeton"
fi

# Partition VANGUARDLOG (la seule modifiable sur les autres ordinateurs) : elle se monte en même temps que VANGUARD,
# parfois une seconde après. Son journal d'erreurs est rapatrié ici puis vidé, pour améliorer Vanguard.
JOURNAL=""
for _ in {1..10}; do
  JOURNAL=$(findmnt -nro TARGET -S LABEL=VANGUARDLOG 2>/dev/null | head -1 || true)
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
# Empreinte de cet ordinateur (SHA-1 de /etc/machine-id) : partout ailleurs, Vanguard remonte la clé en lecture seule
# sous Linux (src/protection/cle.rs).
printf '%s' "$(cat /etc/machine-id)" | sha1sum | cut -d' ' -f1 >"$CLE/vanguard.cle"
copier "$LINUX" "$CLE/Linux/vanguard"
[[ -f $WINDOWS ]] && copier "$WINDOWS" "$CLE/Windows/vanguard.exe"
# Version macOS : compilée sur un Mac de GitHub (.github/workflows/macos.yml, chaque nuit si le code a changé),
# récupérée ici quand une compilation plus récente a réussi. Sans Internet ou sans gh : on garde la dernière.
MAC=target/macos
if [[ -z $LOCAL ]] && command -v gh >/dev/null; then
  # La dernière compilation réussie qui a vraiment produit le programme : une exécution de nuit sautée (code
  # inchangé) réussit aussi, sans rien produire. Toutes branches confondues (le passage d'une branche sur le Mac,
  # avant sa fusion, est souvent la dernière), mais seulement un commit déjà dans celui-ci : jamais celui d'une
  # branche pas encore fusionnée.
  RUN=""
  for execution in $(timeout 20 gh run list --workflow macos.yml --status success --limit 20 \
    --json databaseId,headSha -q '.[] | "\(.databaseId):\(.headSha)"' 2>/dev/null || true); do
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
      rm -rf "$MAC" && mv "$MAC.nouveau" "$MAC" && echo "Version macOS récupérée de GitHub (commit ${RUN#* })."
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
rsync -rt --delete --modify-window=2 --exclude /target/ --exclude /.claude/worktrees/ ./ "$CLE/source/"
# Exemples de tldr-pages sur la clé (src/guide/tldr.rs) : lancé depuis la clé, le guide les a tout de suite, même sur
# un ordinateur sans Internet. Une fois par jour au plus ; sans Internet, la clé garde les siens. Avant le manifeste :
# une archive remplacée sur la clé par quelqu'un d'autre se verra au retour.
outils/tldr-cle.sh "$CLE/tldr" || echo "Exemples de tldr-pages non mis à jour sur la clé."
# Manifeste de la clé (src/protection/manifeste.rs) : l'empreinte de chaque fichier (vanguard.jeton compris), gardée
# sur cet ordinateur et jamais sur la clé ; le bilan la compare quand la clé revient de chez quelqu'un. La même
# commande note la clé parmi celles que cet ordinateur connaît, avec l'état de son carnet. Un programme d'avant la
# 0.59 n'a pas cette commande : la clé est à jour quand même.
./"$LINUX" manifeste --ecrire "$CLE" || echo "Manifeste de la clé non écrit : le bilan ne pourra pas la comparer."
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
