# shellcheck shell=bash
# Le socle de la veille continue (outils/veille/LISEZMOI.md), lu par nuit.sh, alerte.sh, hebdo.sh et matin.sh :
# chemins, verrou, journal, notification, garde-fous du budget de l'IA et ligne de commande de claude.
# Chaque chemin se remplace par une variable : essai.sh fait tourner toute la chaîne dans un banc jetable.

ICI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export PATH="$HOME/.cargo/bin:$PATH"

VEILLE=${VANGUARD_VEILLE:-$HOME/.cache/vanguard-dev/veille}
# Le dépôt principal (worktree add/list/remove, branches veille/*) et le worktree détaché de la veille.
DEPOT=${VANGUARD_VEILLE_DEPOT:-$HOME/Projects/vanguard}
ARBRE=${VANGUARD_VEILLE_ARBRE:-$HOME/Projects/vanguard-veille}
BASE=${VANGUARD_VEILLE_BASE:-master}
# Les arbres jetables des corrections, hors de $VEILLE : l'IA n'a le droit de rien lire dans $VEILLE (copies brutes
# venues d'Internet, rapports), mais doit lire son arbre.
ARBRES_IA=${VANGUARD_VEILLE_ARBRES_IA:-$HOME/.cache/vanguard-dev/veille-arbres}
CLAUDE=${VANGUARD_VEILLE_CLAUDE:-claude}
FUZZ=${VANGUARD_FUZZ:-$HOME/.cache/vanguard-dev/fuzz}
VM_RESERVEE=${VANGUARD_VEILLE_VM_RESERVEE:-$HOME/Windows/VANGUARD-TEST/resultats/.test-en-cours.txt}
JOUR=${VANGUARD_VEILLE_JOUR:-$(date +%F)}
# Une seule compilation de la veille, partagée en série sous le verrou ; « target-* » la laisse au ménage de
# menage-dev.sh après 14 jours sans usage.
export CARGO_TARGET_DIR=${VANGUARD_VEILLE_CIBLE:-$HOME/.cache/vanguard-dev/target-veille}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-8}

ETAT=$VEILLE/etat
mkdir -p "$VEILLE" "$ETAT" "$VEILLE/journal"

# Budget de l'IA (LISEZMOI.md, « Coût ») : lancements de correction par semaine glissante, hors relecture
# hebdomadaire ; tours par lancement ; durée.
IA_PAR_SEMAINE=${VANGUARD_VEILLE_IA_PAR_SEMAINE:-3}
TOURS_CORRECTION=60
TOURS_RELECTURE=20
TOURS_HEBDO=40
DUREE_IA=${VANGUARD_VEILLE_DUREE_IA:-90m}
MODELE=${VANGUARD_VEILLE_MODELE:-opus}

journal() {
  local ligne
  ligne="$(date '+%F %T') [$(basename "$0" .sh)] $*"
  printf '%s\n' "$ligne" >>"$VEILLE/journal/$JOUR.log"
  printf '%s\n' "$ligne" >&2
}

# Une notification du bureau, courte, toujours la même forme ; « a-lire » la fait rappeler à 08 h 30 (matin.sh).
# Le corps ne vient jamais d'Internet ni de l'IA tel quel : rapport.py le compose de champs bornés.
notifier() {
  local titre=$1 corps=$2
  journal "notification : $titre — $corps"
  printf '%s\n%s\n' "$titre" "$corps" >"$VEILLE/a-lire"
  notify-send -a Vanguard -i vanguard -u critical "$titre" "$corps" 2>/dev/null ||
    journal "notify-send a échoué (pas de session graphique ?)"
}

# Une seule partie de la veille à la fois (nuit, alerte, hebdo). $1 : secondes d'attente (0 : sortir tout de suite).
# Jamais en silence : une partie qui ne tourne pas le dit par une notification (alerte.sh porte celle de la nuit, qui
# part donc quand même, avec le résumé de la nuit).
prendre_verrou() {
  local attente=${1:-0} qui corps
  [[ $attente != 0 && -n ${VANGUARD_VEILLE_ATTENTE_VERROU:-} ]] && attente=$VANGUARD_VEILLE_ATTENTE_VERROU
  exec 9>"$VEILLE/verrou"
  if [[ $attente == 0 ]]; then flock -n 9; else flock -w "$attente" 9; fi && return 0
  qui=$(basename "$0")
  journal "verrou pris par une autre partie de la veille (attendu $attente s) : rien fait"
  corps="$qui non lancé : une autre partie de la veille tenait le verrou (attendu $attente s ; journal : $VEILLE/journal/$JOUR.log)"
  if [[ $qui == alerte.sh && -f $VEILLE/dernier.txt ]]; then
    corps="$(head -n1 "$VEILLE/dernier.txt") ; correction non lancée (verrou pris après $attente s)"
  fi
  notifier "Vanguard veille" "$corps"
  exit 0
}

# Pourquoi la passe doit être reportée (un jeu, la VM réservée) ; rien : elle peut tourner.
raison_de_reporter() {
  if command -v gamemoded >/dev/null && gamemoded -s 2>/dev/null | grep -q 'is active'; then
    echo "jeu en cours (gamemode)"
  elif [[ -e $VM_RESERVEE ]]; then
    echo "VM réservée ($VM_RESERVEE)"
  fi
}

# Les branches veille/* ni fusionnées dans la base ni supprimées : une seule proposition attend l'auteur à la fois.
propositions_en_attente() {
  git -C "$DEPOT" branch --format='%(refname:short)' --no-merged "$BASE" --list 'veille/*' 2>/dev/null
}

# Lancements de l'IA notés dans budget.tsv (jour, genre, durée, tours, état) depuis $1 jours, du genre $2 (« hebdo »)
# ou de tout autre genre (« correction »).
lancements_depuis() {
  local jours=$1 genre=$2 limite
  limite=$(date -d "$JOUR - $jours days" +%F)
  [[ -f $ETAT/budget.tsv ]] || { echo 0; return; }
  awk -F'\t' -v l="$limite" -v g="$genre" '
    $1 > l && (g == "hebdo" ? $2 == "hebdo" : $2 != "hebdo" && $2 != "relecture") { n++ } END { print n + 0 }' \
    "$ETAT/budget.tsv"
}

# Les garde-fous du budget, vérifiés avant tout appel à claude. $1 : correction ou hebdo. Rien : permis ; sinon la
# raison, dite dans le rapport.
# Le premier, commun à tout lancement (relecture comprise) : IA coupée, limite d'usage atteinte.
refus_commun() {
  [[ -e $VEILLE/COUPER-TOUT ]] && { echo "tout coupé ($VEILLE/COUPER-TOUT)"; return; }
  [[ -e $VEILLE/COUPER-IA ]] && { echo "IA coupée ($VEILLE/COUPER-IA)"; return; }
  if [[ -f $ETAT/quota-jusqua && $(<"$ETAT/quota-jusqua") > $JOUR ]]; then
    echo "limite d'usage de Claude atteinte : pas d'IA avant le $(<"$ETAT/quota-jusqua")"
  fi
}
refus_ia() {
  local genre=$1 attente commun
  commun=$(refus_commun)
  [[ -n $commun ]] && { echo "$commun"; return; }
  # Lancé à la main par l'auteur (VANGUARD_VEILLE_DEMANDE=1, jamais posé par les minuteries) : sa demande passe
  # toujours, même si la relecture de la semaine ou la correction de la nuit a déjà eu lieu. Ses interrupteurs et la
  # limite d'usage de Claude valent encore (refus_commun, plus haut).
  [[ -n ${VANGUARD_VEILLE_DEMANDE:-} ]] && return
  if [[ $genre == hebdo ]]; then
    (($(lancements_depuis 6 hebdo) == 0)) || echo "relecture hebdomadaire déjà faite cette semaine"
    return
  fi
  attente=$(propositions_en_attente | head -n1)
  [[ -n $attente ]] && { echo "la proposition $attente attend l'auteur"; return; }
  (($(lancements_depuis 1 correction) == 0)) || { echo "déjà une correction cette nuit"; return; }
  (($(lancements_depuis 7 correction) < IA_PAR_SEMAINE)) ||
    echo "budget de la semaine épuisé ($IA_PAR_SEMAINE corrections en 7 jours)"
}

noter_lancement() { # genre durée tours état
  printf '%s\t%s\t%s\t%s\t%s\n' "$JOUR" "$1" "$2" "$3" "$4" >>"$ETAT/budget.tsv"
}

# Les refus communs à tous les lancements : jamais le réseau (sauf cargo dans le bac à sable), jamais GitHub, jamais
# rien qui sorte de la branche de la proposition, jamais les garde-fous eux-mêmes.
REFUS_CLAUDE=(
  "WebFetch" "WebSearch" "Bash(gh *)" "Bash(curl *)" "Bash(wget *)" "Bash(ssh *)" "Bash(scp *)" "Bash(rsync *)"
  "Bash(nc *)" "Bash(rm *)" "Bash(sudo *)" "Bash(pkexec *)" "Bash(systemctl *)" "Bash(git push *)"
  "Bash(git remote *)" "Bash(git config *)" "Bash(git worktree *)" "Bash(git checkout *)" "Bash(git switch *)"
  "Bash(git reset *)" "Bash(git rebase *)" "Bash(git merge *)" "Bash(git branch *)" "Bash(git tag *)"
  "Bash(git fetch *)" "Bash(git pull *)" "Bash(cargo install *)" "Bash(cargo publish *)" "Bash(cargo login *)"
  "Bash(outils/deployer.sh *)" "Bash(outils/livrer-branche.sh *)" "Bash(outils/publier-version.sh *)"
  "Edit(./.github/**)" "Write(./.github/**)" "Edit(./outils/veille/**)" "Write(./outils/veille/**)"
  "Edit(./.claude/**)" "Write(./.claude/**)" "Edit(./CLAUDE.md)" "Write(./CLAUDE.md)" "Edit(./deny.toml)"
  "Write(./deny.toml)" "Edit(./fuzz/deny.toml)" "Edit(./extensions/deny.toml)" "Edit(./.cargo/**)"
  "Write(./.cargo/**)" "Edit(./outils/exceptions-rustsec.py)" "Edit(./outils/hooks/**)" "Write(./outils/hooks/**)"
  # Ce qui tourne hors du bac à sable de l'IA (crochets de git, verifier.sh, vm-tester.sh) ou décide de la chaîne de
  # compilation, et le lien du worktree vers son dépôt (.git) : la veille relance git dessus hors bac à sable.
  "Edit(./outils/confidentialite.py)" "Write(./outils/confidentialite.py)" "Edit(./outils/verifier.sh)"
  "Write(./outils/verifier.sh)" "Edit(./outils/vm-tester.sh)" "Write(./outils/vm-tester.sh)" "Edit(./**/build.rs)"
  "Write(./**/build.rs)" "Edit(./rust-toolchain*)" "Write(./rust-toolchain*)" "Edit(./.git)" "Write(./.git)"
  "Edit(./.git/**)" "Write(./.git/**)"
  "Read(~/.cache/vanguard-dev/veille/**)" "Read(~/.ssh/**)" "Read(~/.gnupg/**)" "Read(~/.config/**)"
  "Read(~/.local/share/vanguard/**)" "Read(~/.claude/**)"
)

# Les réglages d'un lancement : reglages-claude.json, l'arbre de travail mis à sa place. $1 : arbre ; $2 : fichier
# produit ; $3 : réseau de cargo (1 : crates.io seulement, pour une mise à jour de dépendance) ; $4 : 1 pour la
# correction, qui écrit dans son arbre et dans SA compilation et SON cargo ($CIBLE_IA, $CARGO_IA : jetables, jamais
# partagés avec la nuit ni avec l'auteur, qu'un build.rs pourrait sinon empoisonner) ; 0 : aucune écriture.
reglages_claude() {
  local domaines='[]' ecriture=${4:-0}
  [[ ${3:-0} == 1 ]] && domaines='["index.crates.io","static.crates.io"]'
  if [[ $ecriture == 1 && (-z ${CIBLE_IA:-} || -z ${CARGO_IA:-}) ]]; then
    journal "réglages de claude : CIBLE_IA ou CARGO_IA manquant"
    return 1
  fi
  jq --arg arbre "$1" --arg cible "${CIBLE_IA:-}" --arg cargo "${CARGO_IA:-}" --arg maison "$HOME" \
    --argjson domaines "$domaines" --argjson ecriture "$ecriture" '
    walk(if type == "string" then gsub("@ARBRE@"; $arbre) | gsub("@CIBLE_IA@"; $cible) | gsub("@CARGO_IA@"; $cargo)
         | gsub("@MAISON@"; $maison) else . end)
    | .sandbox.network.allowedDomains = $domaines
    | if $ecriture == 1 then . else .sandbox.filesystem.allowWrite = [] end' "$ICI/reglages-claude.json" >"$2"
}

# Le code d'une branche écrite par l'IA (build.rs, macros, tests, verifier.sh qui les lance) ne tourne qu'ici : sans
# réseau ni les prises de la session (D-Bus, Wayland, agents SSH et GPG), le dossier personnel masqué sauf les outils
# de compilation, écriture dans les dossiers donnés seulement. $1 : dossier courant ; puis les dossiers en écriture ;
# « -- » ; la commande. Sans bwrap, rien ne tourne (125).
bac_a_sable() {
  local cwd=$1 d args
  shift
  command -v bwrap >/dev/null || { echo "bwrap absent : le code de l'IA ne tourne jamais hors bac à sable" >&2; return 125; }
  args=(--ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /run --tmpfs "$HOME"
    --dir "$HOME/.cache/vanguard-dev")
  for d in .cargo/bin .rustup .local/bin .local/share/mise .local/share/Steam/compatibilitytools.d \
    .cache/vanguard-dev/pwsh .cache/vanguard-dev/outils-dp40; do
    args+=(--ro-bind-try "$HOME/$d" "$HOME/$d")
  done
  # Le worktree pointe sur le dépôt : lisible, jamais modifiable (ni commit, ni config, ni crochet).
  args+=(--ro-bind-try "$DEPOT/.git" "$DEPOT/.git")
  while (($#)) && [[ $1 != -- ]]; do
    args+=(--bind "$1" "$1")
    shift
  done
  shift
  bwrap "${args[@]}" --unshare-all --die-with-parent --new-session \
    --unsetenv DBUS_SESSION_BUS_ADDRESS --unsetenv SSH_AUTH_SOCK --unsetenv GPG_AGENT_INFO \
    --unsetenv WAYLAND_DISPLAY --unsetenv DISPLAY --unsetenv XDG_RUNTIME_DIR \
    --setenv VANGUARD_HORS_LIGNE 1 --chdir "$cwd" "$@"
}

# Options en plus d'un lancement (--add-dir du dossier des données de l'alerte).
AJOUTS_CLAUDE=()

# Lance claude -p dans l'arbre $1 : $2 rôle (correction, relecture, hebdo), $3 entrée (fichier JSON de champs sûrs),
# $4 sortie JSON, $5 réglages ; les outils permis suivent « -- ». Un seul passage, borné en tours et en durée.
lancer_claude() {
  local arbre=$1 role=$2 entree=$3 sortie=$4 reglages=$5 tours outils
  shift 5
  [[ ${1:-} == -- ]] && shift
  case $role in
    correction) tours=$TOURS_CORRECTION; outils="Read,Edit,Write,Glob,Grep,Bash" ;;
    relecture) tours=$TOURS_RELECTURE; outils="Read,Glob,Grep,Bash" ;;
    hebdo) tours=$TOURS_HEBDO; outils="Read,Glob,Grep,Bash" ;;
  esac
  (
    cd "$arbre" || exit 1
    timeout --kill-after=60 "$DUREE_IA" "$CLAUDE" -p "$(<"$entree")" \
      --append-system-prompt "$(<"$ICI/consignes-$role.md")" \
      --model "$MODELE" --safe-mode --restricted --strict-mcp-config --no-session-persistence \
      --settings "$reglages" "${AJOUTS_CLAUDE[@]}" \
      --permission-mode dontAsk --permission-prompts none \
      --max-turns "$tours" --max-budget-usd 5 \
      --output-format json --json-schema "$(<"$ICI/schema-$role.json")" \
      --tools "$outils" \
      --allowedTools "$@" \
      --disallowedTools "${REFUS_CLAUDE[@]}" \
      </dev/null >"$sortie" 2>"$sortie.err"
  )
}

# Une sortie de claude qui dit la limite d'usage : plus d'IA avant le lendemain.
noter_quota_si_atteint() {
  local sortie=$1
  if grep -qiE 'usage limit|rate limit|limite d.usage|quota' "$sortie" "$sortie.err" 2>/dev/null &&
    ! jq -e '.is_error == false' "$sortie" >/dev/null 2>&1; then
    date -d "$JOUR + 1 day" +%F >"$ETAT/quota-jusqua"
    journal "limite d'usage de Claude : pas d'IA avant demain"
  fi
}

python_rapport() { python3 -I "$ICI/rapport.py" "$@"; }
