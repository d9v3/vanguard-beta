#!/usr/bin/env bash
# Essais de outils/verifier.sh lui-même, sur ce que lance l'audit de nuit de la CI (--seulement) : un vert qui n'a
# rien vérifié y passerait inaperçu chaque nuit, sans personne devant l'écran.
#   1. Une étape demandée qui se dit sautée (ici Wine absent : tests Windows, corpus de détection sous Wine) fait
#      échouer, avec sa raison.
#   2. Une étape demandée qui ne tourne jamais sous --seulement (la mise en forme) fait échouer.
#   3. Un nom d'étape inconnu (mal écrit, ou renommé sans suivre ci.yml) est refusé, code 2 ; une option inconnue
#      aussi, avant de rien lancer.
#   4. Une étape demandée qui réussit (scripts Python) donne bien « Tout est vert ».
#   5. Le passage complet (celui de la livraison) : une étape sautée ou jamais lancée y est un échec, pas un vert ;
#      --rapide, --sans-wine et --ci la disent « partiel » (juger_etape, lue dans verifier.sh : le passage complet
#      ne se relance pas d'ici, il dure des minutes et lance ces essais mêmes).
#   6. Les relectures de cargo vet sans Internet (VANGUARD_HORS_LIGNE) : imports.lock cru sur parole, l'étape se dit
#      sautée avec sa raison, jamais verte (sauté sans cargo-vet 0.10.3).
#   7. Les protections des programmes (durcissement, lue dans verifier.sh, cargo et le programme remplacés par des
#      faux) : jamais sautée ; les programmes de publication vérifiés seulement s'ils sont ceux de ce commit (sinon
#      c'est dit) ; un refus, ou le programme absent, est un échec.
# Chaque essai ne lance que des étapes de quelques secondes, sans Internet ni compilation.
# Lancé par outils/verifier.sh.
#   outils/essais-verifier.sh
set -uo pipefail
cd "$(dirname "$0")/.."
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

# Le script lancé comme la CI le lance ; sa sortie et son code gardés pour les essais.
lancer() {
  SORTIE=$("$@" 2>&1)
  CODE=$?
}

lancer env VANGUARD_WINE=/inexistant/wine bash outils/verifier.sh --seulement tests-windows
if ((CODE == 1)) && grep -q '✖ tests Windows.*sautée, rien vérifié : Wine absent' <<<"$SORTIE"; then
  ok "étape demandée et sautée : un échec, avec sa raison"
else
  ko "étape demandée et sautée (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer env VANGUARD_WINE=/inexistant/wine bash outils/verifier.sh --seulement regression-detection-windows
if ((CODE == 1)) && grep -q '✖ régression de détection Windows.*sautée, rien vérifié : Wine absent' <<<"$SORTIE"; then
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

# Rien ne doit tourner avant le refus : une heure de vérification pour finir « partiel » sans dire pourquoi. Un
# verifier.sh qui l'accepterait lancerait tout, ces essais compris : il tourne dans son propre groupe de processus,
# tué en entier après 10 s (timeout seul laisserait ses étapes en fond), et ne relance pas ce cas-ci en lui-même.
if [[ -z ${VANGUARD_ESSAI_OPTION_INCONNUE:-} ]]; then
  SORTIE_OPTION=$(mktemp "$HOME/.cache/vanguard-dev/essai-option.XXXX")
  VANGUARD_ESSAI_OPTION_INCONNUE=1 setsid bash outils/verifier.sh --tout >"$SORTIE_OPTION" 2>&1 &
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
  if ((CODE == 2)) && grep -q '✖ option inconnue : --tout' <<<"$SORTIE"; then
    ok "option inconnue : refusée, code 2, rien lancé"
  else
    ko "option inconnue (code $CODE, 124 : lancée au lieu d'être refusée) : $(tail -n 2 <<<"$SORTIE")"
  fi
fi

lancer bash outils/verifier.sh --seulement python
if ((CODE == 0)) && grep -q '✔ scripts Python' <<<"$SORTIE" && grep -q '^Tout est vert' <<<"$SORTIE"; then
  ok "étape demandée et réussie : tout est vert"
else
  ko "étape demandée et réussie (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

# La règle du résumé, lue telle quelle dans verifier.sh et jugée dans chaque mode.
juge=$(mktemp "$HOME/.cache/vanguard-dev/juger-etape.XXXX")
awk '/^juger_etape\(\) \{/,/^\}/' outils/verifier.sh >"$juge"
juger() { MODE=$1 SEULEMENT=$2 bash -c "source '$juge'; juger_etape $3"; }
if [[ -s $juge && $(juger "" "" sautee) == echec && $(juger "" "" absente) == echec && $(juger "" "" ok) == vert &&
  $(juger --seulement ,python, sautee) == echec && $(juger --ci "" sautee) == partiel &&
  $(juger --sans-wine "" absente) == partiel && $(juger --rapide "" echec) == echec ]]; then
  ok "passage complet : une étape sautée ou jamais lancée est un échec ; --rapide, --sans-wine, --ci : partiel"
else
  ko "passage complet : une étape sautée ou jamais lancée n'y est pas un échec (juger_etape de verifier.sh)"
fi
rm -f "$juge"
grep -q '^echo "Tout est vert' outils/verifier.sh && grep -q 'Passage partiel (\$MODE)' outils/verifier.sh &&
  ok "un passage partiel ne finit jamais « Tout est vert »" || ko "verifier.sh : fin d'un passage partiel introuvable"

# Le faux programme note les fichiers qu'on lui donne et répond le code écrit dans « code » ; la vraie lecture des
# en-têtes est essayée par les tests de src/deploiement/binaire.rs.
faux=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-durcissement.XXXX")
mkdir -p "$faux/x86_64-unknown-linux-musl/debug" "$faux/x86_64-unknown-linux-musl/release" \
  "$faux/x86_64-pc-windows-gnu/release"
cat >"$faux/x86_64-unknown-linux-musl/debug/vanguard" <<FAUX
#!/usr/bin/env bash
[[ "\$1 \$2" == "deploiement verifier-binaire" ]] || exit 9
shift 2
for f; do echo "✔ \$f" >>"$faux/appels"; done
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
ici=$(git rev-parse HEAD)
durcir 0
[[ -n $fonction && $CODE == 0 && $APPELS == 1 ]] && grep -q 'pas compilés de ce commit' <<<"$SORTIE" &&
  repere "$ici" oui "$(empreinte x86_64-pc-windows-gnu/release/vanguard.exe)" && durcir 0 &&
  [[ $CODE == 0 && $APPELS == 3 ]] && repere "$ici" non "$(empreinte x86_64-pc-windows-gnu/release/vanguard.exe)" &&
  durcir 0 && [[ $CODE == 0 && $APPELS == 1 ]] && repere "$ici" oui autre && durcir 0 &&
  [[ $CODE == 0 && $APPELS == 2 ]] && grep -q 'vanguard.exe n.est plus celui' <<<"$SORTIE" &&
  ok "protections des programmes : ceux de publication vérifiés seulement s'ils sont de ce commit, sinon dit" ||
  ko "protections des programmes, programmes vérifiés (code $CODE, $APPELS programme(s)) : $(tail -n 2 <<<"$SORTIE")"
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
  if ((CODE == 1)) && grep -q '✖ dépendances tracées.*sautée, rien vérifié : relectures importées pas confrontées' <<<"$SORTIE"; then
    ok "relectures de cargo vet hors ligne : sautées et dites, pas un vert"
  else
    ko "relectures de cargo vet hors ligne (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
  fi
else
  echo "  (sauté : cargo-vet 0.10.3 absent, relectures hors ligne pas essayées)"
fi

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "verifier.sh : tout est juste."
