#!/usr/bin/env bash
# Les preuves de la mémoire et des lecteurs (guide de l'ANSSI, règles UNSAFE et outils de vérification) : deux outils
# de la chaîne nightly, trop lents pour chaque vérification, lancés une fois par semaine par la veille continue (la
# nuit du vendredi, avant la relecture hebdomadaire : outils/veille/nuit.sh) et à la main après avoir touché à un
# `unsafe` ou à l'un des lecteurs prouvés.
#  1. Miri interprète les essais qui exercent les `unsafe` portant sur la mémoire de Vanguard (et non sur celle que
#     rend le système, que Miri ne sait pas simuler) : effacement des secrets (socle::effacer), allocateur compteur des
#     essais, lecteurs de textes UTF-16 de Windows, structures C mises à zéro. Pour Linux, puis pour Windows (Miri
#     interprète la cible sans jamais lancer de .exe). Tout comportement indéfini (lecture hors limites, alignement,
#     valeur interdite, provenance des pointeurs) fait échouer l'essai.
#  2. Kani prouve, pour TOUTES les entrées dans une borne, l'absence de panique, de débordement et de boucle sans fin
#     de trois lecteurs de données hostiles (outils/preuves/ : entiers de SQLite, bits de zstd, noms DNS), plus une
#     propriété simple de chacun (aller-retour, lecture bit à bit, position dans le message).
#   outils/preuves.sh             Miri puis Kani
#   outils/preuves.sh miri        Miri seul
#   outils/preuves.sh kani        Kani seul
# Code 0 : tout est prouvé ; 1 : un échec (le journal est dit) ; 77 : un outil manque, rien n'est compté vert
# (« sautée » pour la veille). Les journaux vont dans ~/.cache/vanguard-dev/preuves/ (VANGUARD_PREUVES pour un autre
# dossier) ; les compilations dans target/ de CET arbre (target/miri, target/kani).
# Prérequis : rustup toolchain install nightly --component miri rust-src ; cargo install --locked kani-verifier &&
# cargo kani setup (sa propre chaîne nightly, dans ~/.kani, sans droits d'administrateur).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

QUOI=${1:-tout}
case $QUOI in
  tout | miri | kani) ;;
  *) echo "usage : outils/preuves.sh [tout|miri|kani]" >&2; exit 2 ;;
esac
JOURNAUX=${VANGUARD_PREUVES:-$HOME/.cache/vanguard-dev/preuves}
mkdir -p "$JOURNAUX"
# La chaîne de Miri : nightly, ou une autre datée (VANGUARD_NUIT_MIRI=nightly-2026-10-21) si une nightly nouvelle
# casse la compilation ; la version utilisée est toujours écrite.
NUIT=${VANGUARD_NUIT_MIRI:-nightly}

# Les essais lancés sous Miri, par cible, à leur nom exact : un essai renommé ou disparu ne passe pas pour vert (le
# nombre d'essais passés doit être celui de la liste). L'allocateur compteur des essais n'est vérifié que pour Linux :
# pour Windows, Miri refuse la libération d'une allocation très alignée par l'allocateur du système de std lui-même
# (src/protection/perimes/sources/mod.rs, COMPTEUR).
LINUX=(
  socle::tests::effacer_remet_la_tranche_a_zero_et_rien_d_autre
  protection::perimes::sources::tests::compteur_delegue_et_compte
  socle::tests::structures_c_mises_a_zero
)
WINDOWS=(
  socle::tests::effacer_remet_la_tranche_a_zero_et_rien_d_autre
  machine::windows::impression::tests::texte_utf16_nul_termine_et_borne
  machine::windows::partages::tests::texte_utf16_nul_termine_et_borne
  machine::windows::comptes::tests::texte_large_nul_termine_et_borne
  machine::windows::processus::tests::entree_mise_a_zero
  machine::windows::memoire::tests::information_mise_a_zero
)

ECHECS=0 SAUTEES=0

# Une cible sous Miri : ses essais, à leur nom exact ; vert seulement si chacun est passé, aucun ignoré.
miri_cible() {
  local cible=$1 journal debut=$SECONDS
  shift
  journal=$JOURNAUX/miri-$cible.log
  # -Zmiri-strict-provenance : un entier changé en pointeur est refusé (règle de provenance stricte), plutôt que
  # deviné.
  if MIRIFLAGS="-Zmiri-strict-provenance" cargo "+$NUIT" miri test --locked --target "$cible" --bin vanguard \
    -- --exact "$@" >"$journal" 2>&1 &&
    grep -q "^test result: ok\. $# passed; 0 failed; 0 ignored" "$journal"; then
    echo "  ✔ Miri $cible : $# essai(s), aucun comportement indéfini ($((SECONDS - debut)) s)"
  else
    echo "  ✖ Miri $cible : échec (journal : $journal)"
    grep -E '^error|^test .* (FAILED|ignored)$|^test result' "$journal" | head -n 12 | sed 's/^/      /'
    ECHECS=$((ECHECS + 1))
  fi
}

if [[ $QUOI != kani ]]; then
  if ! cargo "+$NUIT" miri --version >/dev/null 2>&1; then
    echo "  – Miri absent de la chaîne $NUIT (rustup toolchain install nightly --component miri rust-src) : sauté"
    SAUTEES=$((SAUTEES + 1))
  else
    echo "Miri : $(cargo "+$NUIT" miri --version) ; $(rustc "+$NUIT" -V)"
    miri_cible x86_64-unknown-linux-gnu "${LINUX[@]}"
    miri_cible x86_64-pc-windows-gnu "${WINDOWS[@]}"
  fi
fi

if [[ $QUOI != miri ]]; then
  if ! command -v cargo-kani >/dev/null; then
    echo "  – Kani absent (cargo install --locked kani-verifier && cargo kani setup) : sauté"
    SAUTEES=$((SAUTEES + 1))
  else
    echo "Kani : $(cargo kani --version 2>/dev/null | head -n 1)"
    journal=$JOURNAUX/kani.log debut=$SECONDS
    # Autant de preuves vérifiées que de #[kani::proof] écrites : une preuve que Kani ne trouverait plus (module
    # renommé, inclusion cassée) ne passe pas pour verte.
    attendues=$(cat outils/preuves/src/preuve_*.rs | grep -c '^#\[kani::proof\]')
    if (cd outils/preuves && cargo kani --target-dir "$PWD/../../target/kani" --output-format terse) >"$journal" 2>&1 &&
      grep -q "^Complete - $attendues successfully verified harnesses, 0 failures, $attendues total\.$" "$journal"; then
      echo "  ✔ Kani : $attendues preuve(s) bornée(s) vérifiée(s) ($((SECONDS - debut)) s)"
    else
      echo "  ✖ Kani : échec (journal : $journal)"
      grep -E '^error|^VERIFICATION:|^Failed Checks|^Complete|Harness' "$journal" | head -n 12 | sed 's/^/      /'
      ECHECS=$((ECHECS + 1))
    fi
  fi
fi

if ((ECHECS)); then
  echo "✖ $ECHECS échec(s)"
  exit 1
elif ((SAUTEES)); then
  echo "– $SAUTEES outil(s) absent(s) : rien n'est compté vert"
  exit 77
fi
echo "✔ Miri et Kani : tout est vert"
