#!/usr/bin/env bash
# Essais de outils/verifier.sh lui-même, sur ce que lance l'audit de nuit de la CI (--seulement) : un vert qui n'a
# rien vérifié y passerait inaperçu chaque nuit, sans personne devant l'écran.
#   1. Une étape demandée qui se dit sautée (ici Wine absent : tests Windows, corpus de détection sous Wine) fait
#      échouer, avec sa raison.
#   2. Une étape demandée qui ne tourne jamais sous --seulement (la mise en forme) fait échouer.
#   3. Un nom d'étape inconnu (mal écrit, ou renommé sans suivre ci.yml) est refusé, code 2 ; une option inconnue,
#      une liste d'étapes vide (« , », « "" », absente) ou mal écrite (espace, tabulation, majuscule), ou un argument
#      en trop aussi, avant de rien lancer.
#   4. Une étape demandée qui réussit (scripts Python) donne « Vert pour les étapes demandées seulement », jamais
#      « Tout est vert » : seul le passage complet le dit.
#   5. Le passage complet (celui de la livraison) : une étape sautée ou jamais lancée y est un échec, pas un vert ;
#      --rapide et --sans-wine la disent « partiel » ; sous --ci, une étape lancée qui se dit sautée y est un échec,
#      sauf les exclusions nommées (EXCLUES_CI), et une étape absente aussi, sauf celles que --ci ne lance pas exprès
#      (ABSENTES_CI, Wine) (juger_etape, lue dans verifier.sh : le passage complet ne se relance pas d'ici, il dure
#      des minutes et lance ces essais mêmes).
#   6. Les relectures de cargo vet sans Internet (VANGUARD_HORS_LIGNE) : imports.lock cru sur parole, l'étape se dit
#      sautée avec sa raison, jamais verte (sauté sans cargo-vet 0.10.3).
#   7. Les protections des programmes (durcissement, lue dans verifier.sh, cargo et le programme remplacés par des
#      faux) : jamais sautée ; les programmes de publication vérifiés seulement s'ils sont ceux de ce commit (sinon
#      c'est dit) ; chacun avec son système (--attendu linux ou windows) ; un refus, ou le programme absent, est un
#      échec.
#   8. Les relectures de cargo vet : un Cargo.lock ou un supply-chain/ changé pendant l'étape la fait échouer, et
#      il est remis tel qu'avant (le passage suivant n'est pas vert sur un verrou réécrit), après que l'état d'après
#      a été gardé dans un dossier daté et dit ; pas gardé, rien n'est remis (la garde lue dans verifier.sh, l'étape
#      remplacée par une fausse, dépôt jetable).
#   9. Les dépendances (cargo deny) hors ligne : sautée avec sa raison, jamais un vert ; un refus reste un échec.
#  10. Le second avis (cargo audit, failles-programmes.sh --depot) : chaque Cargo.lock suivi par git est lu, chacun
#      avec les seules exceptions de son deny.toml (lues ici sans outils/exceptions-rustsec.py), jamais celles de
#      Vanguard pour une crate à part ; une faille dans l'une fait échouer (faux cargo-audit). Les programmes de la
#      fenêtre (--fenetre) : les exceptions de fenetre/deny.toml seulement, ses avis hors cibles écartés seulement si
#      cargo tree les dit absents de ses deux cibles, et ses caisses lues dans les octets dans la liste de leur
#      cible (caisses-fenetre.sh --publies) ; sinon rien n'est audité et elle ne part pas. L'étape « fenêtre » :
#      la garde de ses caisses ou ses essais en échec la font échouer, et le résumé dit les caisses lues.
#  11. Les essais sautés à l'intérieur d'une étape verte (« (sauté : … », tests de cargo notés) : montrés sous sa
#      ligne et comptés jusqu'à la dernière, « Tout est vert, avec N essai(s) sauté(s) » (M-8).
#  12. Le dossier de travail d'un verifier.sh tué (SIGKILL) : retiré au départ suivant (son verrou est libre), jamais
#      celui d'un autre en cours, même d'un autre espace de PID (verrou tenu, numéro absent d'ici), ni un tout neuf.
#  13. Les scripts shell (shellcheck) : chaque script suivi par git, crochets sans extension compris, un
#      avertissement fait échouer ; shellcheck absent, l'étape se dit sautée, jamais verte.
# Chaque essai ne lance que des étapes de quelques secondes, sans Internet ni compilation.
# Lancé par outils/verifier.sh.
#   outils/essais-verifier.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

# Le script lancé comme la CI le lance ; sa sortie et son code gardés pour les essais.
lancer() {
  SORTIE=$("$@" 2>&1)
  CODE=$?
}

lancer env VANGUARD_WINE=/inexistant/wine bash outils/verifier.sh --seulement tests-windows
if ((CODE == 1)) && grep -q '✖ tests Windows.*sautée, pas un vert : Wine absent' <<<"$SORTIE"; then
  ok "étape demandée et sautée : un échec, avec sa raison"
else
  ko "étape demandée et sautée (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer env VANGUARD_WINE=/inexistant/wine bash outils/verifier.sh --seulement regression-detection-windows
if ((CODE == 1)) && grep -q '✖ régression de détection Windows.*sautée, pas un vert : Wine absent' <<<"$SORTIE"; then
  ok "corpus de détection demandé sous Wine, Wine absent : un échec, avec sa raison"
else
  ko "corpus de détection demandé sous Wine, Wine absent (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer bash outils/verifier.sh --seulement mise-en-forme
if ((CODE == 1)) && grep -q 'mise en forme.*non lancé' <<<"$SORTIE"; then
  ok "étape demandée et jamais lancée : un échec"
else
  ko "étape demandée et jamais lancée (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer bash outils/verifier.sh --seulement dependances,failles-connue
if ((CODE == 2)) && grep -q 'étape inconnue : failles-connue' <<<"$SORTIE"; then
  ok "nom d'étape inconnu : refusé, code 2"
else
  ko "nom d'étape inconnu (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

# Rien ne doit tourner avant le refus : une heure de vérification pour finir « partiel » sans dire pourquoi, ou une
# liste vide qui ne lance rien et se dit verte. Un verifier.sh qui accepterait ces arguments lancerait tout, ces
# essais compris : il tourne dans son propre groupe de processus, tué en entier après 10 s (timeout seul laisserait
# ses étapes en fond), et ne relance pas ces cas-ci en lui-même.
refus_sans_rien_lancer() {
  local attendu=$1 nom=$2
  shift 2
  SORTIE_OPTION=$(mktemp "$HOME/.cache/vanguard-dev/essai-option.XXXX")
  VANGUARD_ESSAI_OPTION_INCONNUE=1 setsid bash outils/verifier.sh "$@" >"$SORTIE_OPTION" 2>&1 &
  GROUPE=$!
  for _ in {1..100}; do kill -0 "$GROUPE" 2>/dev/null || break; sleep 0.1; done
  if kill -0 "$GROUPE" 2>/dev/null; then
    kill -KILL -- "-$GROUPE" 2>/dev/null
    wait "$GROUPE" 2>/dev/null
    CODE=124
  else
    wait "$GROUPE"
    CODE=$?
  fi
  SORTIE=$(<"$SORTIE_OPTION")
  rm -f "$SORTIE_OPTION"
  if ((CODE == 2)) && grep -q -- "$attendu" <<<"$SORTIE"; then
    ok "$nom : refusé, code 2, rien lancé"
  else
    ko "$nom (code $CODE, 124 : lancé au lieu d'être refusé) : $(tail -n 2 <<<"$SORTIE")"
  fi
}
if [[ -z ${VANGUARD_ESSAI_OPTION_INCONNUE:-} ]]; then
  refus_sans_rien_lancer '✖ option inconnue : --tout' "option inconnue" --tout
  refus_sans_rien_lancer '✖ --seulement : liste d.étapes vide' "--seulement « , »" --seulement ,
  refus_sans_rien_lancer '✖ --seulement : liste d.étapes vide' "--seulement « \"\" »" --seulement ""
  refus_sans_rien_lancer '✖ --seulement : liste d.étapes vide' "--seulement sans liste" --seulement
  refus_sans_rien_lancer '✖ --seulement : liste d.étapes vide' "--seulement « python,,shell »" --seulement python,,shell
  refus_sans_rien_lancer '✖ argument en trop : en-trop' "--seulement, argument en trop" --seulement python en-trop
  refus_sans_rien_lancer '✖ argument en trop : en-trop' "--rapide, argument en trop" --rapide en-trop
  # O-1 (relecture 0.94) : une espace ou une tabulation dans la liste ne lançait rien et sortait verte.
  mal_ecrite='✖ --seulement : liste d.étapes vide ou mal écrite'
  refus_sans_rien_lancer "$mal_ecrite" "--seulement « \" \" »" --seulement " "
  refus_sans_rien_lancer "$mal_ecrite" "--seulement « python shell »" --seulement "python shell"
  refus_sans_rien_lancer "$mal_ecrite" "--seulement « python<tab>shell »" --seulement $'python\tshell'
  refus_sans_rien_lancer "$mal_ecrite" "--seulement « python  »" --seulement "python "
  refus_sans_rien_lancer "$mal_ecrite" "--seulement « dependances, failles-connues »" --seulement "dependances, failles-connues"
  refus_sans_rien_lancer "$mal_ecrite" "--seulement « Python »" --seulement Python
  # Un nom en double tournait une fois et se disait vert : la liste n'est pas ce qui a tourné (relecture 0.94, N-3).
  refus_sans_rien_lancer '✖ --seulement : étape en double : python' "--seulement « python,python »" --seulement python,python
  refus_sans_rien_lancer '✖ --seulement : étape en double : python' "--seulement « python,shell,python »" \
    --seulement python,shell,python
else
  # Posée par refus_sans_rien_lancer pour le verifier.sh qu'il lance : celui-là, s'il acceptait l'option, relancerait
  # ces essais, qui ne doivent pas se relancer en boucle (il est tué après 10 s, et compté en échec). Posée ailleurs,
  # les refus ne seraient pas joués : jamais en silence (relecture 0.94, M-7).
  ko "refus des options pas joués : VANGUARD_ESSAI_OPTION_INCONNUE est posée dans l'environnement"
fi

lancer bash outils/verifier.sh --seulement python
if ((CODE == 0)) && grep -q '✔ scripts Python' <<<"$SORTIE" &&
  grep -q '^Vert pour les étapes demandées seulement (python)' <<<"$SORTIE" && ! grep -qi 'tout est vert' <<<"$SORTIE"; then
  ok "étape demandée et réussie : vert pour elle seulement, jamais « Tout est vert »"
else
  ko "étape demandée et réussie (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

# La règle du résumé, lue telle quelle dans verifier.sh et jugée dans chaque mode.
juge=$(mktemp "$HOME/.cache/vanguard-dev/juger-etape.XXXX")
{ grep -E '^(EXCLUES|ABSENTES)_CI=' outils/verifier.sh; awk '/^juger_etape\(\) \{/,/^\}/' outils/verifier.sh; } >"$juge"
juger() { MODE=$1 SEULEMENT=$2 bash -c "source '$juge'; juger_etape $3 ${4:-}"; }
if [[ -s $juge && $(juger "" "" sautee) == echec && $(juger "" "" absente) == echec && $(juger "" "" ok) == vert &&
  $(juger --seulement ,python, sautee) == echec && $(juger --sans-wine "" sautee nomenclatures) == partiel &&
  $(juger --sans-wine "" absente) == partiel && $(juger --rapide "" echec) == echec ]]; then
  ok "passage complet : une étape sautée ou jamais lancée est un échec ; --rapide, --sans-wine : partiel"
else
  ko "passage complet : une étape sautée ou jamais lancée n'y est pas un échec (juger_etape de verifier.sh)"
fi
# Sous --ci : une étape sautée est un échec (nomenclatures, relectures…), sauf les exclusions nommées
# (preuves-compilees, Kani absent de la CI) ; une étape absente aussi (oubliée, tuée), sauf celles que --ci ne lance
# pas exprès (Wine) ; une exclusion d'un genre ne vaut pas pour l'autre.
if [[ -s $juge && $(juger --ci "" sautee nomenclatures) == echec && $(juger --ci "" sautee relectures) == echec &&
  $(juger --ci "" sautee) == echec && $(juger --ci "" sautee preuves-compilees) == partiel &&
  $(juger --ci "" absente tests-windows) == partiel && $(juger --ci "" absente regression-detection-windows) == partiel &&
  $(juger --ci "" absente nomenclatures) == echec && $(juger --ci "" absente) == echec &&
  $(juger --ci "" absente preuves-compilees) == echec && $(juger --ci "" sautee tests-windows) == echec &&
  $(juger --ci "" ok nomenclatures) == vert ]]; then
  ok "--ci : une étape sautée ou absente est un échec, sauf les exclusions nommées (preuves-compilees ; Wine)"
else
  ko "--ci : une étape sautée ou absente n'y est pas un échec, ou une exclusion nommée l'est (juger_etape)"
fi
rm -f "$juge"
grep -q '^echo "Tout est vert' outils/verifier.sh && grep -q 'Passage partiel (\$MODE)' outils/verifier.sh &&
  ok "un passage partiel ne finit jamais « Tout est vert »" || ko "verifier.sh : fin d'un passage partiel introuvable"

# Le faux programme note les fichiers qu'on lui donne, chacun avec le système attendu (« aucun » sans --attendu), et
# répond le code écrit dans « code » ; la vraie lecture des en-têtes est essayée par les tests de
# src/deploiement/binaire.rs.
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-durcissement.XXXX")
mkdir -p "$faux/x86_64-unknown-linux-musl/debug" "$faux/x86_64-unknown-linux-musl/release" \
  "$faux/x86_64-pc-windows-gnu/release"
cat >"$faux/x86_64-unknown-linux-musl/debug/vanguard" <<FAUX
#!/usr/bin/env bash
[[ "\$1 \$2" == "deploiement verifier-binaire" ]] || exit 9
shift 2
attendu=aucun
if [[ \$1 == --attendu ]]; then attendu=\$2; shift 2; fi
for f; do echo "\$attendu \$f" >>"$faux/appels"; done
exit \$(cat "$faux/code")
FAUX
chmod +x "$faux/x86_64-unknown-linux-musl/debug/vanguard"
echo linux >"$faux/x86_64-unknown-linux-musl/release/vanguard"
echo windows >"$faux/x86_64-pc-windows-gnu/release/vanguard.exe"
empreinte() { sha256sum "$faux/$1" | cut -d' ' -f1; }
repere() {
  printf 'commit %s\npropre %s\nlinux-x86_64 %s\nwindows-x86_64 %s\n' "$1" "$2" \
    "$(empreinte x86_64-unknown-linux-musl/release/vanguard)" "$3" >"$faux/.compilation"
}
fonction=$(awk '/^durcissement\(\) \{/,/^\}/' outils/verifier.sh)
durcir() {
  : >"$faux/appels"
  echo "$1" >"$faux/code"
  SORTIE=$(CARGO_TARGET_DIR=$faux TRAVAIL=$faux bash -c "cargo() { :; }; $fonction
durcissement" 2>&1)
  CODE=$?
  APPELS=$(wc -l <"$faux/appels")
}
# Chaque programme Linux vérifié comme Linux, le .exe comme Windows : jamais sans --attendu, jamais croisés.
systemes_justes() { ! grep -vE '^(linux .*/vanguard|windows .*/vanguard\.exe)$' "$faux/appels" | grep -q .; }
ici=$(git rev-parse HEAD)
durcir 0
[[ -n $fonction && $CODE == 0 && $APPELS == 1 ]] && grep -q 'pas compilés de ce commit' <<<"$SORTIE" &&
  repere "$ici" oui "$(empreinte x86_64-pc-windows-gnu/release/vanguard.exe)" && durcir 0 &&
  [[ $CODE == 0 && $APPELS == 3 ]] && systemes_justes && repere "$ici" non "$(empreinte x86_64-pc-windows-gnu/release/vanguard.exe)" &&
  durcir 0 && [[ $CODE == 0 && $APPELS == 1 ]] && repere "$ici" oui autre && durcir 0 &&
  [[ $CODE == 0 && $APPELS == 2 ]] && grep -q 'vanguard.exe n.est plus celui' <<<"$SORTIE" &&
  ok "protections des programmes : ceux de publication vérifiés seulement s'ils sont de ce commit, sinon dit, chacun avec son système" ||
  ko "protections des programmes, programmes vérifiés (code $CODE, $APPELS programme(s)) : $(tail -n 2 <<<"$SORTIE") $(cat "$faux/appels")"
durcir 1
if [[ -n $fonction && $CODE != 0 && $CODE != 77 ]]; then
  rm "$faux/x86_64-unknown-linux-musl/debug/vanguard"
  durcir 0
fi
[[ -n $fonction && $CODE != 0 && $CODE != 77 ]] &&
  ok "protections des programmes : un refus ou le programme absent est un échec, jamais sautée" ||
  ko "protections des programmes : un refus ou le programme absent n'échoue pas (code $CODE)"
rm -rf "$faux"
grep -q '{ etape durcissement durcissement || true; } && etape regression-detection' outils/verifier.sh &&
  grep -q '^ligne durcissement ' outils/verifier.sh && ok "protections des programmes : lancées et jugées à chaque passe" ||
  ko "verifier.sh : l'étape durcissement n'est pas dans la chaîne Linux ou dans le résumé"

if [[ $(cargo vet --version 2>/dev/null) == "cargo-vet 0.10.3" ]]; then
  lancer env VANGUARD_HORS_LIGNE=1 bash outils/verifier.sh --seulement relectures
  if ((CODE == 1)) && grep -q '✖ dépendances tracées.*sautée, pas un vert : relectures importées pas confrontées' <<<"$SORTIE"; then
    ok "relectures de cargo vet hors ligne : sautées et dites, pas un vert"
  else
    ko "relectures de cargo vet hors ligne (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
  fi
else
  echo "  (sauté : cargo-vet 0.10.3 absent, relectures hors ligne pas essayées)"
fi

# Les relectures de cargo vet (--store-path ne prend pas --locked) : un Cargo.lock ou un supply-chain/ changé
# pendant l'étape la fait échouer, même verte ; inchangés, son code passe tel quel (vert, sautée ou échec). La garde
# lue dans verifier.sh, l'étape elle-même remplacée par une fausse, dans un dépôt jetable.
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-verrous.XXXX")
mkdir -p "$faux/supply-chain" "$faux/fenetre/supply-chain"
garde=$(awk '/^VERROUS=/; /^empreinte_verrous\(\) \{/,/^\}/; /^restaurer_verrous\(\) \{/,/^\}/; /^relectures\(\) \{/,/^\}/' outils/verifier.sh)
verrous() {
  printf 'verrou\n' >"$faux/Cargo.lock"
  printf 'verrou\n' >"$faux/fenetre/Cargo.lock"
  printf 'relu\n' >"$faux/supply-chain/audits.toml"
  printf 'relu\n' >"$faux/fenetre/supply-chain/audits.toml"
  rm -f "$faux/supply-chain/imports.lock" "$faux/fenetre/supply-chain/imports.lock"
  SORTIE=$(cd "$faux" && HOME=$faux_maison TRAVAIL=$faux_travail bash -c "relectures_lancees() { $1; }; $garde
relectures" 2>&1)
  CODE=$?
  # Remis tels qu'avant : le contenu d'origine, rien d'apparu.
  REMIS=$(cd "$faux" && find . -type f | LC_ALL=C sort | xargs cat | tr '\n' ' ')
}
faux_travail=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-verrous-travail.XXXX")
faux_maison=$faux_travail/maison
mkdir -p "$faux_maison/.cache/vanguard-dev"
verrous 'return 0' && verrous_vert=$CODE
verrous 'return 77' && verrous_saute=$CODE
intact='verrou verrou relu relu '
verrous 'echo neuf >>Cargo.lock; return 0'
[[ -n $garde && $verrous_vert == 0 && $verrous_saute == 77 && $CODE == 1 && $REMIS == "$intact" ]] &&
  grep -q 'cargo vet a changé' <<<"$SORTIE" && grep -q 'remis tels qu.avant' <<<"$SORTIE" &&
  verrous 'echo neuf >fenetre/supply-chain/imports.lock; return 0' && [[ $CODE == 1 && $REMIS == "$intact" ]] &&
  verrous 'echo neuf >>fenetre/Cargo.lock; return 77' && [[ $CODE == 1 && $REMIS == "$intact" ]] &&
  verrous 'echo neuf >supply-chain/audits.toml; return 0' && [[ $CODE == 1 && $REMIS == "$intact" ]] &&
  ok "relectures : Cargo.lock ou supply-chain/ changés par cargo vet font échouer, puis sont remis tels qu'avant" ||
  ko "relectures : un verrou changé passe ou reste changé (vert $verrous_vert, sautée $verrous_saute, changé $CODE, contenu « $REMIS ») : $(tail -n 1 <<<"$SORTIE")"
# L'état d'après est gardé avant la remise, dans un dossier daté de ~/.cache/vanguard-dev, et dit (W-3) : un
# changement fait pendant l'étape par une autre fenêtre (ici, une ligne et un fichier neuf) n'est pas perdu. Le
# dossier pas créable : rien n'est remis, et c'est dit.
rm -rf "$faux_maison/.cache/vanguard-dev"/verrous-changes.*
verrous 'echo "ligne de l auteur" >>supply-chain/audits.toml; echo neuf >supply-chain/autre.toml; return 0'
gardes=("$faux_maison/.cache/vanguard-dev"/verrous-changes.*/)
garde_dit=""
[[ ${#gardes[@]} == 1 && -d ${gardes[0]} ]] && grep -qF "état d'après gardé : ${gardes[0]%/}/apres.tar" <<<"$SORTIE" &&
  garde_dit=1
# Un fichier à la fois : tar -xO suit l'ordre de l'archive (celui de find, propre au système de fichiers), pas celui
# des noms donnés ; ext4 (la CI) et btrfs ne rangent pas pareil.
apres=$(for f in audits autre; do tar -xOf "${gardes[0]}apres.tar" "supply-chain/$f.toml"; done 2>/dev/null | tr '\n' ' ')
avant_garde=$(tar -xOf "${gardes[0]}avant.tar" supply-chain/audits.toml 2>/dev/null)
code_garde=$CODE remis_garde=$REMIS
rm -rf "$faux_maison/.cache/vanguard-dev"
: >"$faux_maison/.cache/vanguard-dev"
verrous 'echo neuf >>Cargo.lock; return 0'
if [[ -n $garde_dit && $apres == "relu ligne de l auteur neuf " && $avant_garde == relu && $code_garde == 1 &&
  $remis_garde == "$intact" && $CODE == 1 && $REMIS == *neuf* ]] && grep -q "rien n'est remis" <<<"$SORTIE"; then
  ok "relectures : l'état d'après gardé dans un dossier daté et dit, puis remis ; pas gardé, rien de remis"
else
  ko "relectures : état d'après (dit ${garde_dit:-non}, gardé « $apres », avant « $avant_garde », code $code_garde ; sans dossier : code $CODE, « $REMIS ») : $(tail -n 2 <<<"$SORTIE")"
fi
rm -rf "$faux" "$faux_travail"

# cargo deny hors ligne (VANGUARD_HORS_LIGNE, ou sans réseau) : une base RustSec peut-être en retard, ou aucune, n'est
# pas un vert ; l'étape se dit sautée, la raison en première ligne. Un refus reste un échec ; en ligne, vert. Lue
# dans verifier.sh, cargo deny remplacé par un faux qui rend le code écrit dans « code ».
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-deny.XXXX")
printf '#!/bin/sh\n' >"$faux/cargo-deny" && chmod +x "$faux/cargo-deny"
fonction=$(awk '/^dependances\(\) \{/,/^\}/' outils/verifier.sh)
deny() {
  echo "$1" >"$faux/code"
  mkdir -p "$faux/cargo/advisory-dbs" && rm -rf "$faux/cargo/advisory-dbs/"*
  [[ $3 == base ]] && mkdir "$faux/cargo/advisory-dbs/advisory-db-0"
  SORTIE=$(PATH=$faux:$PATH CARGO_HOME=$faux/cargo SAUTEE=77 bash -c "internet() { return $2; }
cargo() { [[ \$1 == deny ]] || return 9; echo \"\$*\" >>'$faux/appels'; return \$(cat '$faux/code'); }
$fonction
dependances" 2>&1)
  CODE=$?
}
deny 0 0 base && deny_en_ligne=$CODE
deny 0 1 base && deny_base=$CODE && raison_base=$(head -n1 <<<"$SORTIE")
deny 0 1 aucune && deny_aucune=$CODE && raison_aucune=$(head -n1 <<<"$SORTIE")
deny 1 1 base
[[ -n $fonction && $deny_en_ligne == 0 && $deny_base == 77 && $deny_aucune == 77 && $CODE == 1 ]] &&
  [[ $raison_base == "sans Internet : "* && $raison_aucune == "sans Internet ni base RustSec : "* ]] &&
  grep -q -- '--offline' "$faux/appels" &&
  ok "dépendances hors ligne : sautée avec sa raison, jamais un vert ; un refus reste un échec" ||
  ko "dépendances hors ligne (en ligne $deny_en_ligne, base $deny_base, sans base $deny_aucune, refus $CODE) : $raison_base"
rm -rf "$faux"

# Le second avis (cargo audit, failles-programmes.sh --depot) lit chaque Cargo.lock du dépôt, crates à part comprises
# (fuzz, extensions, preuves Kani), chacun avec les exceptions de son deny.toml et rien d'autre (les preuves Kani, sans
# deny.toml : aucune) ; une faille dans l'une fait échouer.
# cargo-audit, curl et cargo remplacés par des faux : le premier note ses arguments, refuse le verrou écrit dans
# « refuse ».
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-audit.XXXX")
version=$(sed -n 's/.*cargo-audit@\([0-9][0-9.]*\).*/\1/p' .github/workflows/ci.yml | head -1)
cat >"$faux/cargo-audit" <<FAUX
#!/usr/bin/env bash
[[ \$1 == --version ]] && { echo "cargo-audit $version"; exit 0; }
echo "\$*" >>"$faux/appels"
[[ -s "$faux/refuse" && "\$*" == *"\$(cat "$faux/refuse")"* ]] && exit 1
exit 0
FAUX
printf '#!/bin/sh\nexit 0\n' >"$faux/curl"
printf '#!/bin/sh\n[ "$1" = tree ] || exit 9\n' >"$faux/cargo"
chmod +x "$faux/cargo-audit" "$faux/curl" "$faux/cargo"
# Les avis écartés pour un verrou (les --ignore de l'appel qui le lit), triés ; ceux qu'un deny.toml admet, lus par
# grep et non par outils/exceptions-rustsec.py, que cet essai juge aussi.
ignores_de() {
  awk -v f="$PWD/$1" '$NF == f { for (i = 1; i < NF; i++) if ($i == "--ignore") print $(i + 1) }' "$faux/appels" |
    sort | paste -sd' '
}
admises_de() {
  [[ -z ${1:-} ]] || grep -oE 'id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' "$1" | cut -d'"' -f2 | sort | paste -sd' '
}
auditer() {
  : >"$faux/appels"
  printf '%s' "$1" >"$faux/refuse"
  SORTIE=$(env -u VANGUARD_HORS_LIGNE PATH="$faux:$PATH" bash outils/failles-programmes.sh --depot 2>&1)
  CODE=$?
}
auditer ""
audit_vert=$CODE
lus=$(grep -oE -- '--file [^ ]+' "$faux/appels" | sed "s|--file $PWD/||" | sort | paste -sd' ')
attendus=$(git ls-files '*Cargo.lock' | sort | paste -sd' ')
# Chaque verrou et le deny.toml dont il reçoit les exceptions ; la fenêtre reçoit en plus ses avis hors cibles,
# prouvés absents de ses deux cibles par le faux cargo tree (vide).
mal_places=""
for paire in Cargo.lock:deny.toml fuzz/Cargo.lock:fuzz/deny.toml extensions/sdk/Cargo.lock:extensions/deny.toml \
  extensions/exemples/rust-exemple/Cargo.lock:extensions/deny.toml outils/preuves/Cargo.lock: \
  fenetre/Cargo.lock:fenetre/deny.toml; do
  verrou=${paire%%:*}
  read -ra admises <<<"$(admises_de "${paire#*:}")"
  [[ $verrou != fenetre/Cargo.lock ]] || admises+=(RUSTSEC-2026-0370 RUSTSEC-2026-0371 RUSTSEC-2026-0372)
  voulus=$( ((${#admises[@]} == 0)) || printf '%s\n' "${admises[@]}" | sort | paste -sd' ')
  ecartes=$(ignores_de "$verrou")
  [[ $ecartes == "$voulus" ]] || mal_places+=" $verrou (« $ecartes » au lieu de « $voulus »)"
done
auditer "fuzz/Cargo.lock"
[[ $audit_vert == 0 && -n $attendus && $lus == "$attendus" && -z $mal_places && $CODE == 1 ]] &&
  ok "cargo audit : chaque Cargo.lock du dépôt lu, chacun avec les exceptions de son deny.toml, une faille fait échouer" ||
  ko "cargo audit (vert $audit_vert, refus $CODE, exceptions mal placées :${mal_places:- aucune}) : lus « $lus », attendus « $attendus » $(tail -n 1 <<<"$SORTIE")"
rm -rf "$faux"

# La fenêtre (failles-programmes.sh --fenetre) : sa liste gravée compte des bibliothèques qu'elle ne compile pas
# (cargo auditable, options unies de toutes les plateformes). Aucune exception de Vanguard, seulement celles de
# fenetre/deny.toml ; ses HORS_CIBLES écartées
# seulement si cargo tree les dit absentes de ses deux cibles. Le faux cargo tree -i en trouve une si « compilee »
# existe ; sans -i, il donne la liste versionnée de la cible (caisses-fenetre.sh --publies compare les octets à
# celle-ci), et cargo metadata ne dit aucune source remplacée.
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-audit-fenetre.XXXX")
cat >"$faux/cargo-audit" <<FAUX
#!/usr/bin/env bash
[[ \$1 == --version ]] && { echo "cargo-audit $version"; exit 0; }
echo "\$*" >>"$faux/appels"
for p in "\$@"; do [[ -f \$p ]] && echo "Found 'cargo auditable' data in \$p (7 dependencies)"; done
exit 0
FAUX
printf '#!/bin/sh\nexit 0\n' >"$faux/curl"
cat >"$faux/cargo" <<FAUX
#!/usr/bin/env bash
[[ \$1 == metadata ]] && { echo '{"packages":[]}'; exit 0; }
[[ \$1 == tree ]] || exit 9
if [[ " \$* " == *" -i "* ]]; then
  [[ -e "$faux/compilee" ]] && echo "zvariant v0.0.0"
  exit 0
fi
while [[ \$# -gt 0 && \$1 != --target ]]; do shift; done
sed 's/ / v/' "$PWD/outils/caisses-fenetre/\$2.txt"
FAUX
chmod +x "$faux/cargo-audit" "$faux/curl" "$faux/cargo"
# Des octets où se lit une caisse de la liste de sa cible (chemin de panique), comme dans une vraie fenêtre, avec
# l'en-tête de son système : sans rien de lisible, --fenetre dirait « non vérifié » (outils/essais-caisses-fenetre.sh
# l'essaie).
caisse_de() { head -1 "outils/caisses-fenetre/$1.txt" | tr ' ' '-'; }
printf '\177ELF\0/cargo/registry/src/index.crates.io-0123456789abcdef/%s/src/lib.rs\0' \
  "$(caisse_de x86_64-unknown-linux-gnu)" >"$faux/fenetre-linux"
printf 'MZ\0/cargo/registry/src/index.crates.io-0123456789abcdef/%s/src/lib.rs\0' \
  "$(caisse_de x86_64-pc-windows-gnu)" >"$faux/fenetre.exe"
auditer_fenetre() {
  : >"$faux/appels"
  SORTIE=$(env -u VANGUARD_HORS_LIGNE PATH="$faux:$PATH" bash outils/failles-programmes.sh --fenetre \
    "$faux/fenetre-linux" "$faux/fenetre.exe" 2>&1)
  CODE=$?
}
auditer_fenetre
fenetre_vert=$CODE
ecartes=$(grep -oE -- '--ignore [^ ]+' "$faux/appels" | sort -u | paste -sd' ')
touch "$faux/compilee"
auditer_fenetre
read -ra admises_fenetre <<<"$(admises_de fenetre/deny.toml)"
voulus=$(printf -- '--ignore %s\n' "${admises_fenetre[@]}" RUSTSEC-2026-0370 RUSTSEC-2026-0371 RUSTSEC-2026-0372 |
  sort -u | paste -sd' ')
[[ $fenetre_vert == 0 && $ecartes == "$voulus" && $CODE == 1 && ! -s $faux/appels ]] &&
  ok "cargo audit de la fenêtre : seulement les exceptions de fenetre/deny.toml, hors cibles écartées seulement prouvées" ||
  ko "cargo audit de la fenêtre (vert $fenetre_vert, compilée $CODE) : écartés « $ecartes » $(tail -n 1 <<<"$SORTIE")"
rm -rf "$faux"

# L'étape « fenêtre » : la garde de ses caisses (outils/caisses-fenetre.sh) et ses essais la font échouer, et le résumé
# dit les nombres de caisses lus dans son journal, jamais un texte écrit d'avance (relecture du 13 nov. 2026 : rien ne
# gardait cet appel). fenetre et caisses_lues lues dans verifier.sh, dans un dossier jetable ; cargo, les deux scripts
# et le programme vanguard qui juge les protections remplacés par des cales qui ne font rien.
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-etape-fenetre.XXXX")
fonction=$(awk '/^fenetre\(\) \{/,/^\}/; /^caisses_lues\(\) \{/,/^\}/' outils/verifier.sh)
mkdir -p "$faux/outils" "$faux/cibles/x86_64-unknown-linux-musl/debug"
printf '#!/bin/sh\nexit 0\n' >"$faux/cibles/x86_64-unknown-linux-musl/debug/vanguard"
chmod +x "$faux/cibles/x86_64-unknown-linux-musl/debug/vanguard"
etape_fenetre() { # code de la cale de caisses-fenetre.sh, puis de celle de ses essais ; le code de l'étape
  {
    echo "echo '✔ x86_64-unknown-linux-gnu : 7 caisses, celles de outils/caisses-fenetre/x86_64-unknown-linux-gnu.txt'"
    echo "echo '✔ x86_64-pc-windows-gnu : 5 caisses, celles de outils/caisses-fenetre/x86_64-pc-windows-gnu.txt'"
    echo "exit $1"
  } >"$faux/outils/caisses-fenetre.sh"
  echo "exit $2" >"$faux/outils/essais-caisses-fenetre.sh"
  (cd "$faux" && TRAVAIL=$faux CARGO_TARGET_DIR=$faux/cibles bash -c "cargo() { :; }; sautes() { :; }; $fonction
fenetre >fenetre.log 2>&1")
}
etape_fenetre 1 0
rouge_caisses=$?
etape_fenetre 0 1
rouge_essais=$?
etape_fenetre 0 0
vert=$?
lues=$(TRAVAIL=$faux bash -c "$fonction
caisses_lues fenetre" 2>&1)
echo "  ✔ x86_64-unknown-linux-gnu : 9 caisses, celles de la liste (ligne d'un essai)" >"$faux/fenetre.log"
aucune=$(TRAVAIL=$faux bash -c "$fonction
caisses_lues fenetre" 2>&1)
[[ -n $fonction && $rouge_caisses != 0 && $rouge_essais != 0 && $vert == 0 && $lues == "7 Linux, 5 Windows" &&
  $aucune == "aucune liste lue" ]] && grep -q '^  ligne fenetre ".*\$(caisses_lues fenetre)' outils/verifier.sh &&
  ok "étape fenêtre : la garde des caisses ou ses essais en échec la font échouer ; le résumé dit les caisses lues" ||
  ko "étape fenêtre (caisses en échec $rouge_caisses, essais en échec $rouge_essais, vert $vert) : lues « $lues »," \
    "sans liste « $aucune »"
rm -rf "$faux"

# Les essais sautés à l'intérieur d'une étape verte : montrés sous sa ligne, comptés jusqu'à la dernière ligne (même
# « Tout est vert »). sautes_dits lue dans verifier.sh, sur un journal inventé de 8 sauts (6 montrés, le reste dit).
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-sautes.XXXX")
{
  echo "  ✔ un essai juste"
  for i in 1 2 3 4 5 6 7; do echo "  (sauté : raison $i)"; done
  echo "(sauté : sans retrait)"
  echo "  le mot (sauté : au milieu) ne compte pas"
} >"$faux/etape.log"
fonction=$(awk '/^sautes_dits\(\) \{/,/^\}/' outils/verifier.sh)
SORTIE=$(TRAVAIL=$faux RESUME=/dev/null bash -c "SAUTES_DITS=2; $fonction
sautes_dits etape; sautes_dits vide; echo \"compte \$SAUTES_DITS\"" 2>&1)
[[ -n $fonction ]] && grep -qx 'compte 10' <<<"$SORTIE" && grep -qx '      (sauté : raison 1)' <<<"$SORTIE" &&
  grep -q '8 en tout' <<<"$SORTIE" && ! grep -q 'raison 7' <<<"$SORTIE" &&
  grep -q '^    sautes_dits "\$nom"$' outils/verifier.sh &&
  grep -q '^  echo "Tout est vert, avec \$SAUTES_DITS essai(s) sauté(s)' outils/verifier.sh &&
  grep -q '(sauté : essais du lanceur de la clé' outils/verifier.sh &&
  ok "essais sautés dans une étape verte : montrés sous sa ligne, comptés jusqu'à « Tout est vert »" ||
  ko "essais sautés dans une étape verte : ni montrés ni comptés : $(tr '\n' '|' <<<"$SORTIE")"
rm -rf "$faux"

# Le dossier de travail d'un verifier.sh tué (SIGKILL) est retiré au départ suivant ; celui d'un verifier.sh en cours
# jamais, ni un autre fichier. menage_travaux lue dans verifier.sh, dans un dossier personnel jetable. La preuve de
# la mort est le verrou libre, pas le numéro du processus : « vivant-ailleurs » porte le numéro d'un mort (comme un
# verifier.sh d'un autre espace de PID) mais son verrou est tenu (relecture 0.95, V-7).
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-menage.XXXX")
v=$faux/.cache/vanguard-dev
mkdir -p "$v"
bash -c 'exit 0' &
mort=$!
wait "$mort"
mkdir "$v/verifier.$mort.mort" "$v/verifier.$mort.ailleurs" "$v/verifier.$mort.neuf" "$v/verifier.$mort.ancien" \
  "$v/verifier.$mort.ancien-recent" "$v/verifier.$$.vivant" "$v/verifier.abcd" "$v/verifier.x1.abcd"
touch "$v/verifier.$mort.mort/etape.log" "$v/verifier-0.94.log"
for d in "verifier.$mort.mort" "verifier.$mort.ailleurs" "verifier.$mort.neuf" "verifier.$$.vivant"; do : >"$v/$d/verrou"; done
# Le verrou de « ailleurs » et de « vivant » tenu ici, comme le tient leur verifier.sh.
exec {tient1}>"$v/verifier.$mort.ailleurs/verrou" {tient2}>"$v/verifier.$$.vivant/verrou"
flock -n "$tient1" && flock -n "$tient2" || ko "ménage des dossiers de travail : verrous de l'essai pas pris"
# Tous vieux de dix minutes, sauf « neuf » (le verrou se prend juste après la création) ; « ancien » (sans verrou,
# verifier.sh d'avant 0.95) d'il y a deux jours, « ancien-recent » d'il y a une heure.
for d in mort ailleurs ancien-recent; do touch -d '-10 min' "$v/verifier.$mort.$d"; done
touch -d '-1 hour' "$v/verifier.$mort.ancien-recent"
touch -d '-2 days' "$v/verifier.$mort.ancien"
touch -d '-10 min' "$v/verifier.$$.vivant"
fonction=$(awk '/^menage_travaux\(\) \{/,/^\}/' outils/verifier.sh)
HOME=$faux bash -c "$fonction
menage_travaux"
exec {tient1}>&- {tient2}>&-
reste=$(cd "$v" && ls -d -- * | sort | paste -sd' ')
attendu=$(printf '%s\n' verifier-0.94.log "verifier.$$.vivant" verifier.abcd verifier.x1.abcd "verifier.$mort.ailleurs" \
  "verifier.$mort.neuf" "verifier.$mort.ancien-recent" | sort | paste -sd' ')
[[ -n $fonction && ! -e /proc/$mort && $reste == "$attendu" ]] &&
  grep -q '^TRAVAIL=$(mktemp -d "$HOME/.cache/vanguard-dev/verifier.$$.XXXX")$' outils/verifier.sh &&
  grep -q '^exec {VERROU}>"$TRAVAIL/verrou"$' outils/verifier.sh &&
  ok "dossier d'un verifier.sh tué : retiré au départ suivant ; d'un vivant, même d'un autre espace de PID, gardé" ||
  ko "ménage des dossiers de travail : reste « $reste », attendu « $attendu »"
rm -rf "$faux"

# Les scripts shell lus par shellcheck : chaque script suivi par git (*.sh et les crochets sans extension de
# outils/hooks), un avertissement fait échouer ; shellcheck absent, l'étape se dit sautée, jamais verte. Lue dans
# verifier.sh, sur un dépôt jetable.
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-shell.XXXX")
fonction=$(awk '/^scripts_shell\(\) \{/,/^\}/' outils/verifier.sh)
shell_juge() { # PATH
  SORTIE=$(cd "$faux/depot" && PATH=$1 SAUTEE=77 "$BASH" -c "$fonction
scripts_shell" 2>&1)
  CODE=$?
}
mkdir -p "$faux/depot/outils/hooks" "$faux/sans" && ln -s "$(command -v git)" "$faux/sans/git"
git -C "$faux/depot" init -q
printf '#!/usr/bin/env bash\necho "propre"\n' >"$faux/depot/outils/propre.sh"
cp "$faux/depot/outils/propre.sh" "$faux/depot/outils/hooks/pre-push"
printf '#!/usr/bin/env bash\ncd "$1"\n' >"$faux/depot/outils/non-suivi.sh"
git -C "$faux/depot" add outils/propre.sh outils/hooks/pre-push
shell_juge "$faux/sans" && sans_code=$CODE && sans_raison=$(head -n1 <<<"$SORTIE")
if ! command -v shellcheck >/dev/null; then
  [[ -n $fonction && $sans_code == 77 && $sans_raison == "shellcheck absent"* ]] &&
    ok "shellcheck absent : l'étape se dit sautée, jamais verte" || ko "shellcheck absent (code $sans_code) : $sans_raison"
  echo "  (sauté : shellcheck absent ici, avertissements pas essayés)"
else
  shell_juge "$PATH" && propre=$CODE
  printf '#!/usr/bin/env bash\ncd "$1"\n' >"$faux/depot/outils/hooks/pre-push"
  shell_juge "$PATH" && crochet=$CODE && crochet_dit=$SORTIE
  cp "$faux/depot/outils/propre.sh" "$faux/depot/outils/hooks/pre-push"
  printf '#!/usr/bin/env bash\nVIDE= echo "$VIDE"\n' >"$faux/depot/extensions.sh" && git -C "$faux/depot" add extensions.sh
  shell_juge "$PATH" && suivi=$CODE
  [[ -n $fonction && $sans_code == 77 && $sans_raison == "shellcheck absent"* && $propre == 0 && $crochet == 1 &&
    $suivi == 1 ]] && grep -q 'SC2164' <<<"$crochet_dit" &&
    ok "scripts shell : un avertissement (crochet sans extension compris) fait échouer, un non suivi n'est pas lu ; shellcheck absent : sautée" ||
    ko "scripts shell (absent $sans_code « $sans_raison », propre $propre, crochet $crochet, suivi $suivi)"
fi
rm -rf "$faux"

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "verifier.sh : tout est juste."
