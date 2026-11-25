#!/usr/bin/env bash
# La nuit de la veille continue, SANS IA (outils/veille/LISEZMOI.md) : le worktree de veille remis sur la tête de
# master, verifier.sh complet, proptest à la graine du jour, l'autotest, le journal des erreurs rapatrié trié par le
# programme, les envois des ordinateurs relevés au relais et comptés par le programme, le jeudi Miri et Kani
# (outils/preuves.sh), cargo audit sur chaque Cargo.lock (exceptions de son deny.toml) avec la base RUSTSEC fraîche,
# canaris des vraies sources lues par le programme, liens.py, la CI de nuit, la VM par vm-tester.sh s'il existe, et en
# DERNIER le fuzz de chaque cible (le corpus grandit : c'est l'adaptation), dans le temps qui reste : c'est la seule
# étape qui s'allonge à chaque cible ajoutée (nov. 2026 : 47 cibles × 5 min, la nuit coupée par systemd avant les
# failles, les canaris et les liens, plusieurs nuits de suite).
# Puis le rapport (JSON et Markdown), une seule notification si quelque chose ne va pas, et, sur alerte et dans le
# budget, une correction proposée par alerte.sh.
#   nuit.sh                       la nuit entière (minuterie vanguard-veille-nuit.timer)
#   nuit.sh --sans-ia             sans jamais lancer alerte.sh
#   nuit.sh --sans-fuzz --sans-vm --sans-verifier --sans-reseau
#   nuit.sh --fuzz-secondes N     N secondes par cible au plus (300 par défaut), moins si le temps manque
#   nuit.sh --essai               banc de essai.sh : rien de réel (voir essai.sh)
# Une étape sautée dit pourquoi et n'est jamais comptée verte : le résumé la dit, et elle notifie sauf si elle a été
# demandée (--sans-…).
set -uo pipefail
source "$(dirname "$0")/commun.sh"

SANS_IA="" SANS_FUZZ="" SANS_VM="" SANS_VERIFIER="" SANS_RESEAU="" ESSAI="" FUZZ_SECONDES=300
while (($#)); do
  case $1 in
    --sans-ia) SANS_IA=1 ;;
    --sans-fuzz) SANS_FUZZ=1 ;;
    --sans-vm) SANS_VM=1 ;;
    --sans-verifier) SANS_VERIFIER=1 ;;
    --sans-reseau) SANS_RESEAU=1 ;;
    --essai) ESSAI=1 ;;
    --fuzz-secondes) FUZZ_SECONDES=$2; shift ;;
    *) echo "usage : nuit.sh [--sans-ia] [--sans-fuzz] [--sans-vm] [--sans-verifier] [--sans-reseau] [--fuzz-secondes N]" >&2
       exit 2 ;;
  esac
  shift
done
[[ $FUZZ_SECONDES =~ ^[1-9][0-9]*$ ]] || { echo "--fuzz-secondes : un nombre de secondes" >&2; exit 2; }
# Deuxième essai d'un canari au format cassé, pour ne pas alerter sur une réponse d'un instant.
ATTENTE_FORMAT=${VANGUARD_VEILLE_ATTENTE_FORMAT:-600}
# La limite du service (TimeoutStartSec de vanguard-veille-nuit.service, comparée par essai.sh), et ce qui en reste
# toujours pour le rapport. Le fuzz en tout : 90 min au plus, compilation à part, partagées entre les cibles.
LIMITE=${VANGUARD_VEILLE_LIMITE:-14400}
RESERVE_RAPPORT=600 FUZZ_TOTAL=5400 FUZZ_COMPILATION=900 FUZZ_MINIMUM=10
[[ $LIMITE =~ ^[1-9][0-9]*$ ]] || { echo "VANGUARD_VEILLE_LIMITE : un nombre de secondes" >&2; exit 2; }

[[ -e $VEILLE/COUPER-TOUT ]] && { journal "COUPER-TOUT présent : la nuit ne fait rien"; exit 0; }
prendre_verrou 0
DEBUT=$SECONDS
TRAVAIL=$VEILLE/nuits/$JOUR
rm -rf "$TRAVAIL" && mkdir -p "$TRAVAIL"
journal "début de la nuit $JOUR (arbre $ARBRE, base $BASE)"

# Une ligne par étape : {nom, etat: ok|echec|sautee, duree, code, raison}.
noter() { # nom etat debut code [raison]
  jq -cn --arg nom "$1" --arg etat "$2" --argjson duree "$((SECONDS - $3))" --argjson code "$4" --arg raison "${5:-}" \
    '{nom: $nom, etat: $etat, duree: $duree, code: $code} + (if $raison == "" then {} else {raison: $raison} end)' \
    >>"$TRAVAIL/etapes.jsonl"
  journal "étape $1 : $2${5:+ ($5)}"
}
# Une étape : son nom, son journal, sa commande (lancée dans l'arbre de veille). 77 : sautée, comme verifier.sh.
etape() {
  local nom=$1 log=$2 debut=$SECONDS code
  shift 2
  (cd "$ARBRE" && "$@") >"$log" 2>&1
  code=$?
  case $code in
    0) noter "$nom" ok "$debut" 0 ;;
    77) noter "$nom" sautee "$debut" 77 "$(head -n1 "$log" | cut -c1-120)" ;;
    124 | 137) noter "$nom" echec "$debut" "$code" "arrêtée après $(((SECONDS - debut) / 60)) min : pas finie" ;;
    *) noter "$nom" echec "$debut" "$code" ;;
  esac
  return "$code"
}
sauter() { noter "$1" sautee "$SECONDS" 77 "$2"; }
# Ce qui reste avant la limite du service, le rapport mis à part. SECONDS compte depuis le lancement, comme systemd.
restant() { echo $((LIMITE - RESERVE_RAPPORT - SECONDS)); }
# Une étape longue : arrêtée à sa borne, ou avant si la limite du service approche ; sans une minute devant elle, sautée
# et dite. Une seule étape bloquée ne prive plus la nuit de son rapport.
etape_bornee() { # nom journal secondes-au-plus commande…
  local nom=$1 log=$2 borne=$3 reste
  shift 3
  reste=$(restant)
  ((reste < borne)) && borne=$reste
  ((borne >= 60)) || { sauter "$nom" "plus le temps avant la limite de la nuit"; return 77; }
  etape "$nom" "$log" timeout --kill-after=60 "$borne" "$@"
}

# Arrêtée par systemd (TimeoutStartSec) ou à la main : l'auteur le sait quand même.
interrompue() {
  trap - TERM INT
  journal "nuit interrompue avant la fin"
  printf 'Veille %s : interrompue avant la fin (journal : %s)\n' "$JOUR" "$VEILLE/journal/$JOUR.log" >"$VEILLE/dernier.txt"
  notifier "Vanguard veille" "$(cat "$VEILLE/dernier.txt")"
  exit 143
}
trap interrompue TERM INT

# ── Report : un jeu ou la VM réservée. Une nuit reportée n'est pas une nuit verte : dès la deuxième de suite, notifiée
# (et rappelée à 08 h 30 par a-lire). ──
REPORT=$(raison_de_reporter)
if [[ -n $REPORT ]]; then
  n=$(cat "$VEILLE/reports-de-suite" 2>/dev/null)
  [[ $n =~ ^[0-9]+$ ]] || n=0
  n=$((n + 1))
  echo "$n" >"$VEILLE/reports-de-suite"
  journal "nuit reportée : $REPORT ($n de suite)"
  printf 'Veille %s : nuit reportée (%s), %d nuit(s) de suite\n' "$JOUR" "$REPORT" "$n" >"$VEILLE/dernier.txt"
  ((n >= 2)) && notifier "Vanguard veille : $n nuits reportées" "$REPORT : aucun contrôle depuis $n nuits"
  exit 0
fi
rm -f "$VEILLE/reports-de-suite"

# ── 1. Le worktree de veille, remis sur la tête de la base ──
# Jamais un autre worktree : reset seulement si le chemin est listé par git ET détaché (une session ne travaille
# jamais sur un HEAD détaché ; un worktree sur une branche est celui de quelqu'un).
arbre_sur() {
  git -C "$DEPOT" worktree list --porcelain | awk -v a="$(realpath -m "$ARBRE")" '
    /^worktree / { dans = (substr($0, 10) == a) }
    dans && /^detached$/ { d = 1 }
    dans && /^branch / { b = 1 }
    END { exit !(d && !b) }'
}
preparer_arbre() {
  local debut=$SECONDS
  if [[ ! -e $ARBRE ]]; then
    git -C "$DEPOT" worktree add -q --detach "$ARBRE" "$BASE" >"$TRAVAIL/arbre.log" 2>&1 ||
      { noter arbre echec "$debut" 1 "worktree add refusé"; return 1; }
  elif ! arbre_sur; then
    noter arbre echec "$debut" 1 "$ARBRE n'est pas un worktree détaché de ce dépôt : rien n'est remis"
    return 1
  fi
  {
    git -C "$ARBRE" checkout -q --detach "$BASE" &&
      git -C "$ARBRE" reset -q --hard "$BASE" &&
      git -C "$ARBRE" clean -fdq
  } >>"$TRAVAIL/arbre.log" 2>&1 || { noter arbre echec "$debut" 1 "remise sur $BASE impossible"; return 1; }
  noter arbre ok "$debut" 0
}
ARBRE_OK=""
preparer_arbre && ARBRE_OK=1
TETE=$(git -C "$DEPOT" rev-parse "$BASE" 2>/dev/null)

# La copie qui tourne (installer.sh) comparée à outils/veille/ de la base : un changement demande de réinstaller.
COPIE=$(cat "$ICI/.source" 2>/dev/null)
if [[ -z $COPIE ]]; then
  COPIE_A_JOUR=non-installee
elif [[ $(git -C "$DEPOT" rev-parse "$BASE:outils/veille" 2>/dev/null) == "$(cat "$ICI/.arbre" 2>/dev/null)" ]]; then
  COPIE_A_JOUR=oui
else
  COPIE_A_JOUR=non
fi

if [[ -n $ARBRE_OK ]]; then
  # ── 2. verifier.sh complet (non modifié). Il réécrit verifier-dernier.txt, que page-fonctions.py lit au
  # déploiement : sauvegardé avant, remis après. ──
  if [[ -n $SANS_VERIFIER ]]; then
    sauter verifier "--sans-verifier"
  else
    RESUME_DEV=$HOME/.cache/vanguard-dev/verifier-dernier.txt
    [[ -f $RESUME_DEV ]] && cp -p "$RESUME_DEV" "$TRAVAIL/verifier-dernier.sauve"
    etape_bornee verifier "$TRAVAIL/verifier.log" 5400 outils/verifier.sh
    if [[ -f $TRAVAIL/verifier-dernier.sauve ]]; then
      cp -p "$TRAVAIL/verifier-dernier.sauve" "$RESUME_DEV"
    else
      rm -f "$RESUME_DEV"
    fi
  fi

  # ── 3. Proptest à la graine du jour : d'autres entrées chaque nuit (la graine fixe de .cargo/config.toml reste
  # celle de verifier.sh et de la CI) ; un échec se rejoue avec la graine du rapport. ──
  GRAINE=${JOUR//-/}
  etape_bornee proptest "$TRAVAIL/proptest.log" 3600 env PROPTEST_RNG_SEED="$GRAINE" PROPTEST_CASES=2000 cargo test -q

  # ── 3 bis. L'autodiagnostic de la base sur cet ordinateur (lecture seule, hors ligne) : la première machine à voir un
  # format changer (mise à jour d'Arch) est celle de l'auteur, la nuit même. Son --json ne porte aucune valeur (il peut
  # partir à alerte.sh, donc à une IA en ligne) ; jamais --detail ici. 1 : écart, échec de l'étape ; 2 (rien de
  # fautif, du non vérifié) : sautée, dite. Sa durée (bilan et règles) va dans etat/durees.tsv, par rapport.py, si
  # l'autotest a rendu 0 ou 2 : l'alerte « lenteur ». ──
  autotest_de_nuit() {
    local code
    cargo run -q -- autotest --json >"$TRAVAIL/autotest.json"
    code=$?
    if ((code == 2)); then
      echo "autotest : rien de fautif, en partie non vérifié (voir autotest.json)"
      return 77
    fi
    jq -r '.croisees[] | select(.verdict == "different") | "\(.id) \(.genre)"' "$TRAVAIL/autotest.json" 2>/dev/null
    return "$code"
  }
  etape autotest "$TRAVAIL/autotest.log" autotest_de_nuit

  # ── 3 ter. Le journal des erreurs rapatrié par deployer.sh (retours/journal-cet-ordinateur.txt et journal-cle.txt),
  # trié par le programme de la base (src/compte_rendu/triage.rs, lecteur fuzzé) : la file des causes en champs
  # validés, jamais le texte d'une entrée (rapport.py la refiltre encore). Le suivi d'une nuit à l'autre :
  # etat/causes.json ; les causes déjà traitées : etat/alertes-traitees.txt. ──
  if [[ ! -f $ARBRE/src/compte_rendu/triage.rs ]]; then
    sauter journal "src/compte_rendu/triage.rs absent de $BASE"
  else
    journal_de_nuit() {
      cargo run -q -- compte-rendu journal --cet-ordinateur "$RETOURS/journal-cet-ordinateur.txt" \
        --cle "$RETOURS/journal-cle.txt" --etat "$ETAT/causes.json" --traitees "$ETAT/alertes-traitees.txt" \
        --sortie "$TRAVAIL/journal-file.json" >"$TRAVAIL/journal-comptes.txt"
    }
    etape journal "$TRAVAIL/journal.log" journal_de_nuit
  fi

  # ── 3 quater. Les envois des ordinateurs : relevés au relais (releve-envois.sh, de la copie installée : c'est lui
  # qui lit le secret de relève, jamais le code de la base), gardés bruts dans retours/envois/ (une quarantaine que
  # ni l'IA ni le rapport n'ouvrent), puis lus par le programme de la base (src/compte_rendu/flotte.rs : même lecture
  # stricte que le relais, versions publiées, règles et outils de leur version, une voix par source et par jour).
  # Seuls des comptes en sortent (etat/flotte/<version>.json), puis les signaux, calculés par le même programme, sans
  # IA (src/compte_rendu/flotte/signaux.rs) : flotte-signaux.json (champs fermés, que rapport.py refiltre) et les
  # tickets de retours/tickets/ (données ouvertes, échappées, pour une session que l'auteur lance ; jamais pour l'IA
  # de nuit). Les noms de logiciels ne vont à l'IA qu'approuvés (noms-connus.txt, approuver-nom.sh). Relais pas
  # configuré : les deux étapes sautées, une seule ligne neutre au résumé, sans notification. ──
  if [[ -n $SANS_RESEAU ]]; then
    sauter envois "--sans-reseau"
  else
    etape envois "$TRAVAIL/envois.log" env VANGUARD_VEILLE_JOUR="$JOUR" VANGUARD_VEILLE_RETOURS="$RETOURS" \
      bash "$ICI/releve-envois.sh"
  fi
  if [[ ! -f $ARBRE/src/compte_rendu/flotte.rs ]]; then
    sauter flotte "src/compte_rendu/flotte.rs absent de $BASE"
  elif [[ ! -d $RETOURS/envois ]]; then
    if [[ -e ${XDG_CONFIG_HOME:-$HOME/.config}/vanguard-dev/relais-adresse ]]; then
      sauter flotte "aucun envoi relevé (${RETOURS/#"$HOME"/\~}/envois absent)"
    else
      sauter flotte "relais pas configuré : aucun envoi à lire"
    fi
  else
    flotte_de_nuit() {
      "$ICI/references-flotte.sh" "$ARBRE" "$TRAVAIL/references" || return 1
      cargo run -q --locked ${SANS_RESEAU:+--offline} --features reception -- compte-rendu flotte --dossier "$RETOURS/envois" --references "$TRAVAIL/references" \
        --etat "$ETAT/flotte" --aujourdhui "$JOUR" --signaux "$TRAVAIL/flotte-signaux.json" \
        --tickets "$RETOURS/tickets" --noms "$ICI/noms-connus.txt" --arbre "$ARBRE" >"$TRAVAIL/flotte-comptes.txt"
    }
    etape flotte "$TRAVAIL/flotte.log" flotte_de_nuit
  fi

  # ── 4. Une fois par semaine, la nuit du jeudi (la relecture hebdomadaire du vendredi 05 h 30 lit les sept
  # dernières nuits ; celle du vendredi, qui finit après 05 h, n'y serait pas encore) : Miri sur les `unsafe` qui
  # touchent à la mémoire de Vanguard, puis les preuves bornées de Kani (outils/preuves.sh). Trop lentes pour chaque
  # nuit ; les autres nuits, l'étape n'apparaît pas. Sans Miri ou sans Kani : sautée, dite. ──
  if [[ $(date -d "$JOUR" +%u) == 4 ]]; then
    if [[ ! -x $ARBRE/outils/preuves.sh ]]; then
      sauter preuves "preuves.sh absent de $BASE"
    else
      etape_bornee preuves "$TRAVAIL/preuves.log" 2700 outils/preuves.sh
    fi
  fi

  # ── 5. Failles des dépendances, base RUSTSEC fraîche (cargo audit la télécharge), chaque Cargo.lock du dépôt avec
  # les exceptions de SON deny.toml (outils/failles-programmes.sh --exceptions-depot : la même correspondance que
  # verifier.sh), jamais celles de Vanguard prêtées au banc de fuzzing ou à la fenêtre. cargo audit tourne dans un
  # dossier vide à lui : lancé dans l'arbre, il y lirait .cargo/audit.toml et tairait les avis admis par Vanguard dans
  # toutes les crates. Il voit donc tout ; le rapport dit lesquels sont admis, et par quel deny.toml. ──
  if [[ -n $SANS_RESEAU ]]; then
    sauter rustsec "--sans-reseau : base RUSTSEC pas à jour"
  elif ! command -v cargo-audit >/dev/null; then
    sauter rustsec "cargo-audit absent"
  elif ! (cd "$ARBRE" && bash outils/failles-programmes.sh --exceptions-depot) >"$TRAVAIL/verrous.tsv" \
    2>>"$TRAVAIL/audit.log" || [[ ! -s $TRAVAIL/verrous.tsv ]]; then
    rm -f "$TRAVAIL/verrous.tsv"
    noter rustsec echec "$SECONDS" 1 "liste des Cargo.lock et de leurs exceptions illisible (audit.log)"
  else
    debut=$SECONDS code=0 i=0
    VIDE=$TRAVAIL/audit-vide
    mkdir -p "$VIDE/.cargo"
    echo "# outils/veille/nuit.sh : aucune exception ici, chaque deny.toml est lu par le rapport." >"$VIDE/.cargo/audit.toml"
    while IFS=$'\t' read -r lock _; do
      if [[ -f $ARBRE/$lock ]]; then
        # Code 1 quand une faille est trouvée : le JSON dit lesquelles ; seule une sortie illisible est un échec.
        (cd "$VIDE" && cargo audit --json --file "$ARBRE/$lock") >"$TRAVAIL/audit-$i.json" 2>>"$TRAVAIL/audit.log"
        jq -e .vulnerabilities "$TRAVAIL/audit-$i.json" >/dev/null 2>&1 || { code=1; rm -f "$TRAVAIL/audit-$i.json"; }
      fi
      i=$((i + 1))
    done <"$TRAVAIL/verrous.tsv"
    if ((code)); then noter rustsec echec "$debut" 1 "cargo audit illisible (réseau ?)"; else noter rustsec ok "$debut" 0; fi
  fi

  # ── 6. Canaris : les vraies sources aux adresses du programme, relues par ses lecteurs (src/canaris.rs). ──
  CANARIS=$VEILLE/canaris/$JOUR
  if [[ -n $SANS_RESEAU ]]; then
    sauter canaris "--sans-reseau"
  elif [[ ! -f $ARBRE/src/canaris.rs ]]; then
    sauter canaris "src/canaris.rs absent de $BASE (lot-veille-continue pas encore fusionné)"
  else
    rm -rf "$CANARIS" && mkdir -p "$CANARIS"
    canari() { # dossier, puis le nom exact de l'essai
      env VANGUARD_CANARIS="$1" ${AVANT:+VANGUARD_CANARIS_AVANT="$AVANT"} \
        cargo test -q --bin vanguard "canaris::$2" -- --ignored --exact
    }
    AVANT=""
    precedent=$(find "$VEILLE/canaris" -mindepth 2 -maxdepth 2 -name kev.json -path '*/????-??-??/*' 2>/dev/null |
      sort | awk -v j="$CANARIS/" 'index($0, j) != 1' | tail -n1)
    [[ -n $precedent ]] && AVANT=$precedent
    if etape canaris "$TRAVAIL/canaris.log" canari "$CANARIS" canaris_telecharger; then
      if jq -e 'any(.[]; .etat == "format")' "$CANARIS/canaris.json" >/dev/null; then
        journal "format refusé : deuxième essai dans $ATTENTE_FORMAT s"
        sleep "$ATTENTE_FORMAT"
        mkdir -p "$CANARIS/second"
        (cd "$ARBRE" && canari "$CANARIS/second" canaris_telecharger) >>"$TRAVAIL/canaris.log" 2>&1
      fi
      etape canaris-kev "$TRAVAIL/canaris-kev.log" canari "$CANARIS" canaris_kev
      # Les essais existants, plus exigeants (seuils : ≥ 140 entrées d'Échap, > 1000 avis MFSA…), sur ces copies.
      etape canaris-essais "$TRAVAIL/canaris-essais.log" env VANGUARD_ESSAI_PERIMES="$CANARIS" \
        VANGUARD_ESSAI_ECHAP="$CANARIS/ioc.yaml" cargo test -q --bin vanguard -- \
        vraies_copies_si_presentes vraie_copie_si_presente vrai_fichier_d_echap
    fi
    # Sept jours de copies gardés.
    find "$VEILLE/canaris" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} + 2>/dev/null
  fi

  # ── 7. Liens (avec Internet). ──
  if [[ -n $SANS_RESEAU ]]; then
    sauter liens "--sans-reseau"
  else
    # Un lien mort ne fait qu'entrer au rapport (code 1 de liens.py) ; mort trois nuits de suite, il devient une
    # alerte. Seule une panne de liens.py elle-même est un échec de l'étape.
    liens() { python3 -I outils/liens.py; local c=$?; ((c == 1)) && return 0; return "$c"; }
    etape liens "$TRAVAIL/liens.log" liens
  fi

  # ── 7 bis. La dernière CI de nuit sur GitHub, en lecture seule. ──
  # Restée rouge quatre nuits de suite sans que personne ne le voie (nov. 2026) : la veille la lit et le dit. Ce que
  # GitHub rend est une donnée : seul l'état, comparé à une liste fermée, décide de l'étape ; rapport.py revalide
  # chaque champ avant de l'écrire. Sans gh, sans Internet ou sans jeton valide : sautée, avec la raison (notifiée).
  if [[ -n $SANS_RESEAU ]]; then
    sauter ci-github "--sans-reseau"
  elif ! command -v "$GH" >/dev/null; then
    sauter ci-github "gh absent : CI de nuit pas lue"
  else
    ci_github() {
      local conclusion
      if ! timeout 60 "$GH" run list -R d9v3/vanguard-beta --workflow ci.yml --event schedule --status completed -L 1 \
        --json conclusion,createdAt,headSha,url >"$TRAVAIL/ci-github.json" 2>"$TRAVAIL/ci-github.err"; then
        # La première ligne devient la raison de l'étape sautée ; l'erreur de gh suit, dans ci-github.log seulement.
        echo "gh n'a pas pu lire la CI de nuit (hors ligne ou jeton)"
        tail -n 5 "$TRAVAIL/ci-github.err"
        return 77
      fi
      conclusion=$(jq -r 'if type == "array" and length == 1 and (.[0].conclusion | type) == "string"
        then .[0].conclusion else "" end' "$TRAVAIL/ci-github.json" 2>/dev/null) || conclusion=""
      case $conclusion in
        success)
          # Le vert se redit par jq -e, qui échoue sur toute autre réponse : jamais un vert par défaut. rapport.py
          # revalide ensuite chaque champ ; s'il ne la lit pas verte, la réponse est dite refusée (ci_refusee).
          if ! jq -e 'type == "array" and length == 1 and .[0].conclusion == "success"' \
            "$TRAVAIL/ci-github.json" >/dev/null 2>&1; then
            echo "dernière CI de nuit introuvable ou illisible"
            return 77
          fi
          echo "dernière CI de nuit : verte"
          ;;
        failure | timed_out | startup_failure | action_required)
          echo "dernière CI de nuit : rouge ($conclusion)"
          return 1
          ;;
        cancelled | skipped | neutral | stale)
          echo "dernière CI de nuit non conclue ($conclusion)"
          return 77
          ;;
        *)
          echo "dernière CI de nuit introuvable ou illisible"
          return 77
          ;;
      esac
    }
    etape ci-github "$TRAVAIL/ci-github.log" ci_github
  fi

  # ── 8. La VM, par vm-tester.sh s'il existe (il respecte la réservation ; jamais xfreerdp3 tué). ──
  if [[ -n $SANS_VM ]]; then
    sauter vm "--sans-vm"
  elif [[ ! -x $ARBRE/outils/vm-tester.sh ]]; then
    sauter vm "vm-tester.sh absent de $BASE"
  else
    # Bornée sous le TimeoutStartSec du service : au-delà, le travail reste dans la file de la VM
    # (vm-tester.sh --attendre <id> pour le lire plus tard), et la nuit écrit quand même son rapport.
    etape_bornee vm "$TRAVAIL/vm.log" 3000 outils/vm-tester.sh --delai 30
  fi

  # ── 8 bis. Fuzz, en dernier : chaque cible, le corpus suivi avant et après (il grandit), les plantages comparés à ceux
  # connus. Le temps qui reste, 90 min au plus, est partagé entre les cibles : une cible ajoutée raccourcit les autres,
  # jamais le reste de la nuit (la CI passe en plus cinq minutes par cible chaque nuit). Les cibles comme les lit fuzz.sh
  # (chaque [[bin]] de fuzz/Cargo.toml). ──
  if [[ -n $SANS_FUZZ ]]; then
    sauter fuzz "--sans-fuzz"
  else
    mapfile -t CIBLES < <(sed -n 's/^name = "\(.*\)"$/\1/p' "$ARBRE/fuzz/Cargo.toml" | tail -n +2)
    # Le dimanche, le corpus de chaque cible est minimisé (cargo fuzz cmin) : 30 min gardées.
    CMIN=0
    [[ $(date -d "$JOUR" +%u) == 7 && -z $ESSAI ]] && CMIN=1800
    pour_fuzz=$(($(restant) - CMIN - FUZZ_COMPILATION))
    ((pour_fuzz > FUZZ_TOTAL)) && pour_fuzz=$FUZZ_TOTAL
    # Aucune cible lue : fuzz.sh le dit lui-même, en échec.
    par_cible=$((pour_fuzz / (${#CIBLES[@]} ? ${#CIBLES[@]} : 1)))
    ((par_cible > FUZZ_SECONDES)) && par_cible=$FUZZ_SECONDES
    if ((par_cible < FUZZ_MINIMUM && par_cible < FUZZ_SECONDES)); then
      sauter fuzz "plus le temps : moins de $FUZZ_MINIMUM s pour chacune des ${#CIBLES[@]} cibles"
    else
      journal "fuzz : ${#CIBLES[@]} cibles, $par_cible s chacune"
      python_rapport fuzz-compter "$FUZZ" "$TRAVAIL/fuzz-avant.tsv"
      etape_bornee fuzz "$TRAVAIL/fuzz.log" "$(($(restant) - CMIN))" \
        env VANGUARD_FUZZ="$FUZZ" outils/fuzz.sh tout "$par_cible"
    fi
    if ((CMIN)); then
      for c in "${CIBLES[@]}"; do
        # Jamais un cmin commencé sans cinq minutes devant lui.
        reste=$(restant)
        ((reste >= 300)) || { journal "cmin : plus le temps à partir de $c (corpus gardés tels quels)"; break; }
        # Compilées dans le target/ de l'arbre.
        (cd "$ARBRE" && timeout --kill-after=60 "$reste" cargo +nightly fuzz cmin --fuzz-dir fuzz \
          --target-dir "$ARBRE/target/fuzz" "$c" "$FUZZ/corpus/$c") \
          >>"$TRAVAIL/fuzz-cmin.log" 2>&1 || journal "cmin $c : échec (corpus gardé tel quel)"
      done
    fi
  fi
fi

# ── 9. Rapport, notification, décision de l'IA. ──
REFUS=""
[[ -z $SANS_IA ]] && REFUS=$(refus_ia correction)
mapfile -t PROPOSITIONS < <(propositions_en_attente)
python_rapport nuit --travail "$TRAVAIL" --veille "$VEILLE" --jour "$JOUR" --arbre "$ARBRE" --fuzz "$FUZZ" \
  --sortie "$VEILLE/$JOUR.json" --tete "$TETE" --base "$BASE" --copie "${COPIE:-dépôt}" --copie-a-jour "$COPIE_A_JOUR" \
  --duree "$((SECONDS - DEBUT))" --graine "${GRAINE:-}" --refus-ia "$REFUS" ${SANS_IA:+--sans-ia} \
  --propositions "${PROPOSITIONS[@]}" ||
  { notifier "Vanguard veille" "Veille $JOUR : le rapport n'a pas pu être écrit (journal : $VEILLE/journal/$JOUR.log)"; exit 1; }
journal "rapport : $VEILLE/$JOUR.md"
# Quinze nuits de journaux de travail gardées.
find "$VEILLE/nuits" -mindepth 1 -maxdepth 1 -type d -mtime +15 -exec rm -rf {} + 2>/dev/null

trap - TERM INT
if [[ -f $VEILLE/alerte-demandee.json ]]; then
  # La correction notifiera elle-même à la fin : une seule notification pour la nuit.
  journal "alerte confiée à alerte.sh : $(jq -r .signature "$VEILLE/alerte-demandee.json")"
  exec 9>&-
  if [[ -n ${VANGUARD_VEILLE_ALERTE_DIRECTE:-} ]]; then
    "$ICI/alerte.sh"
  else
    systemctl --user start --no-block vanguard-veille-alerte.service ||
      notifier "Vanguard veille" "$(cat "$VEILLE/dernier.txt") ; alerte.sh n'a pas pu partir"
  fi
elif [[ $(jq -r 'type' "$VEILLE/$JOUR.notification.json") == object ]]; then
  notifier "$(jq -r .titre "$VEILLE/$JOUR.notification.json")" "$(jq -r .corps "$VEILLE/$JOUR.notification.json")"
else
  rm -f "$VEILLE/a-lire"
fi
exit 0
