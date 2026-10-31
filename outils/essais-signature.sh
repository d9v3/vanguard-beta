#!/usr/bin/env bash
# Essais de outils/signer-versions.sh, avec des clés d'essai et de faux programmes, dans un dossier jetable : rien de
# la vraie clé de signature n'est lu, rien n'est publié.
#   1. derniere.txt et derniere.txt.sig sont identiques, à l'octet, à ceux du script de master (la version que les
#      copies déjà installées, 0.85.0 et d'avant, savent lire) : mêmes programmes, même clé, Ed25519 déterministe.
#      L'historique des versions est un fichier à part : ce que lisent ces copies ne change pas.
#   2. L'historique signé grandit d'une version à l'autre, la plus récente en tête, et commence au manifeste signé de
#      la version d'avant quand il n'y a pas encore d'historique.
#   3. Un historique d'avant signé par une autre clé est refusé : rien ne s'ajoute à un historique douteux.
#   4. Sans rien d'avant ni --premier (un téléchargement raté chez publier-version.sh), rien n'est signé : l'historique
#      ne repart pas de zéro avant que les pages d'avant soient effacées.
#   5. La révocation de la clé principale (--secours --revoquer) : la ligne « revoque principale » vient après les
#      trois programmes, que le lecteur de la 0.85.0 (refait ici en awk, comme github.rs le recopie) trouve tous
#      avant elle ; jamais dans l'historique ; refusée sans --secours, ou si un programme garde la principale (sans
#      la marque de PRINCIPALE_RETIREE à true) ; signés par la principale, des programmes qui la retirent ou sans
#      marque sont refusés (5b). La phrase de la clé de secours d'essai (chiffrée, comme la vraie) passe par un
#      pseudo-terminal (script) ; sans script, cet essai est sauté et dit.
#   7. Le point sûr (le dernier historique publié d'ici, campagne d'attaque n° 3) : la clé de secours ne contresigne
#      pas un bloc que la principale, peut-être volée, a ajouté après lui ; sans point sûr, elle refuse un historique
#      signé par la principale ; la principale refuse un historique tronqué ou à une version inconnue d'ici ; avec un
#      point sûr, ni repli sur derniere.txt ni --premier. Jamais le vrai point sûr : VANGUARD_HISTORIQUE_PUBLIE.
#   7b. Le point sûr réécrit lui aussi avec la principale volée (campagne d'attaque n° 4) : la clé de secours montre
#      ses versions et ne contresigne rien sans « contresigner » tapé ; sans terminal, elle refuse (7c).
#   8. Les programmes publiés sont les octets que outils/compiler-version.sh a relevés pour leur commit
#      (publier-version.sh, verifier_compilation, dans un dépôt git jetable) : remplacés, compilés d'un arbre modifié,
#      d'un commit au code changé depuis, ou à la date gravée d'un autre commit, ils sont refusés ; un commit qui ne
#      touche que .github/hors-code.txt (captures, documentation) les laisse valoir.
#   9. .github/workflows/claude.yml ne lance jamais Claude (cargo build et test, droit d'écrire, jeton de
#      l'abonnement) sur une demande de fusion venue d'un fork : son garde, rejoué ici avec un faux gh. Ni sur un
#      ticket « journal », ni sur un ticket ou une demande qu'un autre que le propriétaire a écrits, ni sur un fil où
#      un autre a commenté ou relu (et un fil illisible est refusé).
#   6b. Linux et Windows publiés portent les empreintes de la compilation reproductible de la CI (ci.yml, master) :
#      publier-version.sh (empreintes_de_la_ci, face à un faux gh) refuse un octet changé, un travail en échec ou
#      un journal sans empreintes, et ignore une autre branche (campagne d'attaque n° 6, F1).
#   6. Le programme Mac que la clé signe vient d'une exécution de master : publier-version.sh (sa fonction
#      avec_programme, face à un faux gh) écarte celle d'une autre branche, même plus récente et du même commit ; et
#      macos.yml ne reprend aucun cache sur master. Sans jq, cet essai est sauté et dit. Chaque action des workflows
#      est épinglée à un commit, jamais à une étiquette qui bouge.
# Lancé par outils/verifier.sh ; code 77 (sauté) sans la branche master ici (clone partiel) ou sans openssl.
#   outils/essais-signature.sh
set -uo pipefail
cd "$(dirname "$0")/.."
DEPOT=$PWD

command -v openssl >/dev/null || { echo "openssl absent"; exit 77; }
git rev-parse --verify -q 'master^{commit}' >/dev/null || { echo "pas de branche master ici : rien à comparer"; exit 77; }
mkdir -p "$HOME/.cache/vanguard-dev"
T=$(mktemp -d "$HOME/.cache/vanguard-dev/essais-signature.XXXX")
trap 'rm -rf "$T"' EXIT
ECHECS=0
# Le point sûr d'essai, absent sauf quand un essai le pose : jamais celui de cet ordinateur.
export VANGUARD_HISTORIQUE_PUBLIE=$T/point-sur/historique-publie.txt
mkdir -p "$T/point-sur"
poser_point() { cp "$1" "$VANGUARD_HISTORIQUE_PUBLIE" && cp "$1.sig" "$VANGUARD_HISTORIQUE_PUBLIE.sig"; }
retirer_point() { rm -f "$VANGUARD_HISTORIQUE_PUBLIE" "$VANGUARD_HISTORIQUE_PUBLIE.sig"; }
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

# Deux clés d'essai, gravées dans un faux github.rs comme le vrai les grave (32 octets en décimal).
for nom in principale secours autre; do
  openssl genpkey -algorithm ed25519 -out "$T/$nom.pem" 2>/dev/null || { echo "openssl sans Ed25519"; exit 77; }
done
gravee() {
  openssl pkey -in "$T/$1.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | od -An -tu1 | tr -s ' \n' ' ' |
    sed 's/^ //; s/ $//; s/ /, /g'
}
# Un dépôt factice : le script à essayer, le faux github.rs, un Cargo.toml à la version voulue.
banc() { # $1 : dossier, $2 : script, $3 : version de Cargo.toml
  mkdir -p "$1/outils" "$1/src/mise_a_jour"
  cp "$2" "$1/outils/signer-versions.sh"
  printf 'const CLE_PUBLIQUE: [u8; 32] = [\n    %s,\n];\nconst CLE_SECOURS: [u8; 32] = [\n    %s,\n];\n' \
    "$(gravee principale)" "$(gravee secours)" >"$1/src/mise_a_jour/github.rs"
  printf '[package]\nname = "vanguard"\nversion = "%s"\n' "$3" >"$1/Cargo.toml"
}
# Trois faux programmes à la forme attendue (ELF x86-64, PE x86-64, Mach-O universel arm64 + x86_64), avec leur
# version gravée et la principale gardée, comme le marque github.rs (RETIREE=true : retirée, pour --revoquer).
programmes() { # $1 : dossier, $2 : version gravée
  mkdir -p "$1"
  local v="VANGUARD-VERSION:$2; VANGUARD-PRINCIPALE:GARDEE;"
  [[ ${RETIREE:-false} == false ]] || v="VANGUARD-VERSION:$2; VANGUARD-PRINCIPALE:RETIREE;"
  { printf '\x7fELF\x02\x01'; head -c 12 /dev/zero; printf '\x3e\x00'; printf 'linux %s' "$v"; } >"$1/vanguard-linux-x86_64"
  { printf 'MZ'; head -c 58 /dev/zero; printf '\x40\x00\x00\x00'; printf 'PE\x00\x00\x64\x86'; printf 'windows %s' "$v"; } \
    >"$1/vanguard-windows-x86_64.exe"
  { printf '\xca\xfe\xba\xbe\x00\x00\x00\x02'; printf '\x01\x00\x00\x0c'; head -c 16 /dev/zero
    printf '\x01\x00\x00\x07'; head -c 16 /dev/zero; printf 'macos %s' "$v"; } >"$1/vanguard-macos"
}
signer() { # $1 : banc, $2 : dossier des programmes, puis les options ; la sortie gardée dans $2.log
  # Jamais la vraie clé de secours ni une fenêtre de phrase, même si un contrôle régresse : --secours essayé ici
  # doit être refusé avant de lire la clé.
  VANGUARD_CLE_SECOURS=$T/absente.pem WAYLAND_DISPLAY='' DISPLAY='' VANGUARD_CLE_VERSIONS=$T/${CLE:-principale}.pem bash "$1/outils/signer-versions.sh" "${@:3}" "$2" </dev/null \
    >"$2.log" 2>&1
}
# Une signature sous ce domaine, par la clé principale d'essai.
signe() { # $1 : fichier, $2 : domaine
  { printf '%s\n' "$2"; cat "$1"; } >"$T/message"
  openssl pkey -in "$T/principale.pem" -pubout -out "$T/publique.pem" 2>/dev/null
  openssl pkeyutl -verify -pubin -inkey "$T/publique.pem" -rawin -in "$T/message" -sigfile "$1.sig" >/dev/null 2>&1
}

git show master:outils/signer-versions.sh >"$T/ancien.sh"
banc "$T/ancien" "$T/ancien.sh" 0.86.0
banc "$T/nouveau" "$DEPOT/outils/signer-versions.sh" 0.86.0
programmes "$T/v86-ancien" 0.86.0+1792600000
cp -r "$T/v86-ancien" "$T/v86"
# Le script de master connaît --premier depuis qu'il tient l'historique (0.86) : sans rien d'avant, il l'exige.
premier_ancien=()
grep -q -- '--premier' "$T/ancien.sh" && premier_ancien=(--premier)
signer "$T/ancien" "$T/v86-ancien" "${premier_ancien[@]}" || { ko "script de master : $(tail -n 1 "$T/v86-ancien.log")"; }
if signer "$T/nouveau" "$T/v86" --premier; then
  if cmp -s "$T/v86/derniere.txt" "$T/v86-ancien/derniere.txt" &&
    cmp -s "$T/v86/derniere.txt.sig" "$T/v86-ancien/derniere.txt.sig"; then
    ok "derniere.txt et sa signature identiques à l'octet à ceux du script de master (ce que lit la 0.85.0)"
  else
    ko "derniere.txt ou sa signature diffèrent de ceux du script de master"
  fi
  signe "$T/v86/historique.txt" 'vanguard-historique 1' && ok "historique signé sous son propre domaine" ||
    ko "signature de l'historique"
  signe "$T/v86/historique.txt" 'vanguard-versions 1' && ko "l'historique se vérifie sous le domaine du manifeste" ||
    ok "une signature de l'historique ne vaut pas pour un manifeste"
  cmp -s "$T/v86/historique.txt" "$T/v86/derniere.txt" && ok "sans historique d'avant, il commence à cette version" ||
    ko "premier historique : $(head -c 200 "$T/v86/historique.txt")"
else
  ko "nouveau script : $(tail -n 3 "$T/v86.log")"
fi

# La version suivante reprend l'historique d'avant ; une troisième, elle aussi.
banc "$T/nouveau87" "$DEPOT/outils/signer-versions.sh" 0.87.0
programmes "$T/v87" 0.87.0+1792700000
mkdir -p "$T/v87/avant" && cp "$T/v86/historique.txt" "$T/v86/historique.txt.sig" "$T/v87/avant/"
if signer "$T/nouveau87" "$T/v87" && [[ $(grep -c '^version ' "$T/v87/historique.txt") == 2 ]] &&
  [[ $(head -n 1 "$T/v87/historique.txt") == "version 0.87.0+1792700000" ]] && signe "$T/v87/historique.txt" 'vanguard-historique 1'; then
  ok "l'historique reprend celui d'avant, la version la plus récente en tête"
else
  ko "historique de la version suivante : $(tail -n 2 "$T/v87.log")"
fi
# Sa forme, que lit src/mise_a_jour/github.rs (lire_historique) : « version … » en tête de chaque bloc, puis trois
# champs par programme, rien d'autre.
awk 'NR == 1 && !/^version / { exit 1 } /^version / { next } NF != 3 { exit 1 }' "$T/v87/historique.txt" &&
  ok "forme de l'historique : celle que lit github.rs" || ko "forme de l'historique"

# Pas encore d'historique publié (la 0.85.0) : il commence au manifeste signé de la version d'avant.
banc "$T/nouveau88" "$DEPOT/outils/signer-versions.sh" 0.88.0
programmes "$T/v88" 0.88.0+1792800000
mkdir -p "$T/v88/avant" && cp "$T/v86/derniere.txt" "$T/v86/derniere.txt.sig" "$T/v88/avant/"
if signer "$T/nouveau88" "$T/v88" && [[ $(grep -c '^version ' "$T/v88/historique.txt") == 2 ]]; then
  ok "sans historique d'avant, il reprend le manifeste signé de la version d'avant"
else
  ko "historique commencé au manifeste d'avant : $(tail -n 2 "$T/v88.log")"
fi

# Un historique d'avant signé par une autre clé : refusé, rien n'est signé.
programmes "$T/v89" 0.88.0+1792900000
mkdir -p "$T/v89/avant" && cp "$T/v87/historique.txt" "$T/v89/avant/"
{ printf '%s\n' 'vanguard-historique 1'; cat "$T/v89/avant/historique.txt"; } >"$T/message"
openssl pkeyutl -sign -inkey "$T/autre.pem" -rawin -in "$T/message" -out "$T/v89/avant/historique.txt.sig" 2>/dev/null
if signer "$T/nouveau88" "$T/v89"; then
  ko "un historique d'avant signé par une autre clé a été repris"
elif grep -q "historique d'avant mal signé" "$T/v89.log"; then
  ok "un historique d'avant signé par une autre clé est refusé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/v89.log")"
fi

# Rien d'avant, sans --premier : un téléchargement raté, pas une première fois. Refusé, rien n'est signé.
programmes "$T/v90" 0.88.0+1793000000
if signer "$T/nouveau88" "$T/v90"; then
  ko "sans rien d'avant ni --premier, un historique d'une seule version a été signé"
elif grep -q "ni historique ni manifeste d'avant" "$T/v90.log" && [[ ! -e $T/v90/historique.txt.sig ]]; then
  ok "sans rien d'avant ni --premier : refusé, rien n'est signé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/v90.log")"
fi

# La révocation : refusée sans la clé de secours.
# Les programmes que la clé de secours signe en révoquant retirent la principale (jusqu'au point 7 de la principale).
RETIREE=true
programmes "$T/v91" 0.88.0+1793100000
mkdir -p "$T/v91/avant" && cp "$T/v88/historique.txt" "$T/v88/historique.txt.sig" "$T/v91/avant/"
if signer "$T/nouveau88" "$T/v91" --revoquer; then
  ko "--revoquer sans --secours a signé"
elif grep -q -- "--revoquer va avec --secours" "$T/v91.log"; then
  ok "--revoquer sans --secours : refusé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/v91.log")"
fi
# La révocation par des programmes qui gardent la principale (un seul suffit, ici celui de macOS, lu en dernier) :
# refusée avant toute signature, la phrase de la clé n'est même pas demandée.
programmes "$T/sans-retrait" 0.88.0+1793100000
RETIREE=false programmes "$T/garde" 0.88.0+1793100000 && cp "$T/garde/vanguard-macos" "$T/sans-retrait/"
if signer "$T/nouveau88" "$T/sans-retrait" --secours --revoquer; then
  ko "--revoquer a signé des programmes qui acceptent encore la principale"
elif grep -q "vanguard-macos accepte encore la principale" "$T/sans-retrait.log" &&
  [[ ! -e $T/sans-retrait/derniere.txt.sig ]]; then
  ok "--revoquer avec un programme qui garde la principale : refusé, rien n'est signé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/sans-retrait.log")"
fi
# Les deux marques dans un même programme (macOS universel à moitié recompilé) : refusé de même.
programmes "$T/deux-marques" 0.88.0+1793100000
printf 'VANGUARD-PRINCIPALE:GARDEE;' >>"$T/deux-marques/vanguard-macos"
if signer "$T/nouveau88" "$T/deux-marques" --secours --revoquer; then
  ko "--revoquer a signé un programme qui porte aussi la marque de la principale gardée"
elif grep -q "vanguard-macos accepte encore la principale" "$T/deux-marques.log" &&
  [[ ! -e $T/deux-marques/derniere.txt.sig ]]; then
  ok "--revoquer avec un programme aux deux marques : refusé, rien n'est signé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/deux-marques.log")"
fi
# Le lecteur de la 0.85.0 (lire_manifeste) : la version en tête, puis la ligne du système cherché trouvée avant toute
# ligne qui n'a pas trois champs.
lu_par_la_0_85() { # $1 : manifeste, $2 : système ; affiche « empreinte taille »
  awk -v s="$2" 'NR == 1 { if ($0 !~ /^version /) exit 1; next } NF != 3 { exit 1 } $1 == s { print $2, $3; trouve = 1; exit }
    END { exit !trouve }' "$1"
}
if command -v script >/dev/null; then
  openssl pkcs8 -topk8 -v2 aes-256-cbc -in "$T/secours.pem" -out "$T/secours-chiffree.pem" -passout pass:essai \
    2>/dev/null
  # Le point sûr : l'historique que la principale avait publié (v88), que la clé de secours reprend.
  poser_point "$T/v88/historique.txt"
  printf 'essai\ncontresigner\n' | VANGUARD_CLE_SECOURS=$T/secours-chiffree.pem script -qec \
    "bash '$T/nouveau88/outils/signer-versions.sh' --secours --revoquer '$T/v91'" /dev/null >"$T/v91.log" 2>&1
  retirer_point
  if [[ -f $T/v91/derniere.txt.sig ]] && [[ $(tail -n 1 "$T/v91/derniere.txt") == "revoque principale" ]]; then
    ok "--secours --revoquer : « revoque principale » en dernière ligne"
    pareil=1
    for s in linux-x86_64 windows-x86_64 macos; do
      attendu=$(grep "^$s " "$T/v91/derniere.txt" | cut -d' ' -f2-)
      [[ -n $attendu && $(lu_par_la_0_85 "$T/v91/derniere.txt" "$s") == "$attendu" ]] || pareil=
    done
    [[ -n $pareil ]] && ok "le lecteur de la 0.85.0 lit chaque programme du manifeste qui révoque" ||
      ko "le lecteur de la 0.85.0 ne lit plus le manifeste qui révoque"
    grep -q '^revoque' "$T/v91/historique.txt" && ko "la révocation est entrée dans l'historique" ||
      ok "la révocation n'entre pas dans l'historique"
    awk '/^version / { next } NF != 3 { exit 1 }' "$T/v91/historique.txt" && ok "historique toujours lisible par github.rs" ||
      ko "forme de l'historique après une révocation"
  else
    ko "--secours --revoquer : $(tail -n 2 "$T/v91.log")"
  fi
  # 7. Le voleur de la principale ajoute au dépôt un bloc forgé (un programme Linux inventé), signé par elle.
  secours_signe() { # dossier [réponse à la confirmation du point sûr] ; la sortie dans dossier.log
    printf 'essai\n%s\n' "${2-contresigner}" | VANGUARD_CLE_SECOURS=$T/secours-chiffree.pem script -qec \
      "bash '$T/nouveau88/outils/signer-versions.sh' --secours --revoquer '$1'" /dev/null >"$1.log" 2>&1
  }
  forger() { # dossier : avant/historique.txt = le bloc forgé puis l'historique v88, signé par la principale
    mkdir -p "$1/avant"
    { printf 'version 0.87.5+1792999999\nlinux-x86_64 %s 123\nwindows-x86_64 %s 1\nmacos %s 1\n' \
      "$(printf 'f%.0s' {1..64})" "$(printf 'e%.0s' {1..64})" "$(printf 'd%.0s' {1..64})"
      cat "$T/v88/historique.txt"; } >"$1/avant/historique.txt"
    { printf '%s\n' 'vanguard-historique 1'; cat "$1/avant/historique.txt"; } >"$T/message"
    openssl pkeyutl -sign -inkey "$T/principale.pem" -rawin -in "$T/message" -out "$1/avant/historique.txt.sig"
  }
  programmes "$T/v92" 0.88.0+1793200000
  forger "$T/v92"
  poser_point "$T/v88/historique.txt"
  secours_signe "$T/v92"
  if [[ -f $T/v92/historique.txt.sig ]] && ! grep -q 'version 0.87.5' "$T/v92/historique.txt" &&
    grep -q "Écartées.*0.87.5" "$T/v92.log" && [[ $(grep -c '^version ' "$T/v92/historique.txt") == 3 ]]; then
    ok "secours : le bloc que la principale a signé après le point sûr est écarté, et nommé"
  else
    ko "secours : bloc forgé repris ou historique faux ($(tail -n 2 "$T/v92.log"))"
  fi
  # 7b. Le voleur réécrit aussi le point sûr (le même historique forgé, signé par la principale) : la clé de secours
  # le montre, bloc forgé compris, et ne contresigne rien sans « contresigner » tapé.
  programmes "$T/v95" 0.88.0+1793500000
  forger "$T/v95"
  poser_point "$T/v95/avant/historique.txt"
  secours_signe "$T/v95" non
  # Ni l'historique ni derniere.txt signés : un derniere.txt.sig seul se publierait sans confirmation.
  if [[ ! -e $T/v95/historique.txt.sig && ! -e $T/v95/derniere.txt.sig ]] &&
    grep -q "0.87.5+1792999999 (2026-" "$T/v95.log" &&
    grep -q "non confirmé" "$T/v95.log"; then
    ok "secours : un point sûr de la principale est montré, rien n'est contresigné sans confirmation tapée"
  else
    ko "secours : point sûr forgé contresigné sans confirmation ($(tail -n 2 "$T/v95.log"))"
  fi
  # 7c. Sans terminal (une tâche, un script) : la phrase de la clé vient de zenity, mais la confirmation, elle, ne se
  # demande qu'au terminal ; rien n'est signé, ni l'historique ni derniere.txt.
  programmes "$T/v96" 0.88.0+1793600000
  forger "$T/v96"
  mkdir -p "$T/faux-zenity"
  printf '#!/bin/sh\necho essai\n' >"$T/faux-zenity/zenity"
  chmod +x "$T/faux-zenity/zenity"
  PATH="$T/faux-zenity:$PATH" WAYLAND_DISPLAY=essai VANGUARD_CLE_SECOURS=$T/secours-chiffree.pem \
    bash "$T/nouveau88/outils/signer-versions.sh" --secours --revoquer "$T/v96" </dev/null >"$T/v96.log" 2>&1
  if [[ ! -e $T/v96/historique.txt.sig && ! -e $T/v96/derniere.txt.sig ]] &&
    grep -q "pas de terminal pour confirmer le point sûr" "$T/v96.log"; then
    ok "secours sans terminal : un point sûr de la principale n'est jamais contresigné"
  else
    ko "secours sans terminal : point sûr contresigné ($(tail -n 2 "$T/v96.log"))"
  fi
  retirer_point
  programmes "$T/v93" 0.88.0+1793300000
  forger "$T/v93"
  secours_signe "$T/v93"
  if [[ ! -e $T/v93/historique.txt.sig ]] && grep -q "pas de point sûr" "$T/v93.log"; then
    ok "secours sans point sûr : un historique signé par la principale est refusé, et dit"
  else
    ko "secours sans point sûr : $(tail -n 2 "$T/v93.log")"
  fi
  # Un historique d'avant signé par la clé de secours elle-même (v92) : repris.
  programmes "$T/v94" 0.88.0+1793400000
  mkdir -p "$T/v94/avant" && cp "$T/v92/historique.txt" "$T/v92/historique.txt.sig" "$T/v94/avant/"
  secours_signe "$T/v94"
  [[ -f $T/v94/historique.txt.sig && $(grep -c '^version ' "$T/v94/historique.txt") == 4 ]] &&
    ok "secours : un historique d'avant signé par le secours est repris" || ko "secours repris : $(tail -n 2 "$T/v94.log")"
else
  echo "  (sauté : script absent, pas de pseudo-terminal pour la phrase de la clé de secours d'essai)"
fi
RETIREE=false
# 7, la principale avec un point sûr : historique tronqué, version inconnue d'ici, repli, --premier.
poser_point "$T/v88/historique.txt"
programmes "$T/v95" 0.88.0+1793500000
mkdir -p "$T/v95/avant" && cp "$T/v88/historique.txt" "$T/v88/historique.txt.sig" "$T/v95/avant/"
signer "$T/nouveau88" "$T/v95" && ok "principale : l'historique d'avant est le point sûr, signé" ||
  ko "principale avec point sûr : $(tail -n 2 "$T/v95.log")"
refus() { # dossier, texte attendu, libellé
  if signer "$T/nouveau88" "$1" "${@:4}"; then ko "$3 : signé"
  elif grep -q -- "$2" "$1.log" && [[ ! -e $1/historique.txt.sig ]]; then ok "$3"
  else ko "$3 : $(tail -n 1 "$1.log")"; fi
}
programmes "$T/v96" 0.88.0+1793600000
mkdir -p "$T/v96/avant" && cp "$T/v86/historique.txt" "$T/v86/historique.txt.sig" "$T/v96/avant/"
refus "$T/v96" "n'a plus des versions" "principale : un historique d'avant tronqué (moins que le point sûr) est refusé"
programmes "$T/v97" 0.88.0+1793700000
mkdir -p "$T/v97/avant" && cp "$T/v87/historique.txt" "$T/v87/historique.txt.sig" "$T/v97/avant/"
poser_point "$T/v86/historique.txt"
refus "$T/v97" "pas publiées" "principale : une version que cet ordinateur n'a pas publiée est refusée"
programmes "$T/v98" 0.88.0+1793800000
mkdir -p "$T/v98/avant" && cp "$T/v86/derniere.txt" "$T/v86/derniere.txt.sig" "$T/v98/avant/"
refus "$T/v98" "retiré du" "avec un point sûr, l'historique publié disparu : pas de repli sur derniere.txt"
programmes "$T/v99" 0.88.0+1793900000
refus "$T/v99" "retiré du" "avec un point sûr : --premier refusé" --premier
retirer_point
# 5b. Signés par la principale, des programmes qui la retirent (une fois installés, plus rien d'elle ne passerait) ou
# sans marque (pas compilés de ce code) : refusés avant la clé, à chaque publication.
RETIREE=true programmes "$T/v100" 0.88.0+1794000000
refus "$T/v100" "seule marque de la principale gardée" "principale : un programme qui la retire est refusé"
programmes "$T/v101" 0.88.0+1794100000
sed 's/VANGUARD-PRINCIPALE:GARDEE;//' "$T/v101/vanguard-linux-x86_64" >"$T/v101/vanguard-linux-x86_64.tmp"
mv "$T/v101/vanguard-linux-x86_64.tmp" "$T/v101/vanguard-linux-x86_64"
refus "$T/v101" "seule marque de la principale gardée" "principale : un programme sans marque est refusé"
# Les deux marques (un macOS universel dont une moitié la retire) : refusé aussi, sans --secours.
programmes "$T/v102" 0.88.0+1794200000
printf 'VANGUARD-PRINCIPALE:RETIREE;' >>"$T/v102/vanguard-macos"
refus "$T/v102" "seule marque de la principale gardée" "principale : un programme aux deux marques est refusé"

# Le Mac signé : seulement une exécution de master. Un faux gh répond comme GitHub (jq applique les -q), avec deux
# passages réussis du même commit : le plus récent sur une autre branche, l'autre sur master par la nuit.
if command -v jq >/dev/null; then
  mkdir -p "$T/faux-gh"
  cat >"$T/faux-gh/runs.json" <<'JSON'
[{"databaseId": 2, "headSha": "c0ffee", "headBranch": "piege", "event": "workflow_dispatch"},
 {"databaseId": 1, "headSha": "c0ffee", "headBranch": "master", "event": "schedule"}]
JSON
  cat >"$T/faux-gh/gh" <<'GH'
#!/usr/bin/env bash
q=. branche=
while [[ $# -gt 0 ]]; do
  case $1 in
    -q) q=$2; shift ;;
    --branch) branche=$2; shift ;;
  esac
  shift
done
if [[ -n $branche ]]; then
  jq -r --arg b "$branche" "[.[] | select(.headBranch == \$b)] | $q" "$(dirname "$0")/runs.json"
else
  # « api …/artifacts » ou « run list » sans branche : chaque passage a son programme ; « run view … jobs » : chacun a
  # réussi son travail « attester ».
  case $q in
    *artifacts*) echo vanguard-macos ;;
    *attester*) echo attester ;;
    *) jq -r "$q" "$(dirname "$0")/runs.json" ;;
  esac
fi
GH
  chmod +x "$T/faux-gh/gh"
  awk '/^avec_programme\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh" >"$T/avec_programme.sh"
  choisi=$(PATH="$T/faux-gh:$PATH" COMMIT=c0ffee HORS_CODE= bash -c "source '$T/avec_programme.sh'; avec_programme")
  [[ $choisi == 1 ]] && ok "publier-version.sh prend la compilation Mac de master, pas celle d'une autre branche" ||
    ko "publier-version.sh a pris la compilation Mac « ${choisi:-aucune} » (attendu : 1, celle de master)"
  grep -q 'BRANCHE_RUN != "master schedule"' "$DEPOT/outils/publier-version.sh" &&
    ok "publier-version.sh relit la branche de l'exécution qu'il signe" || ko "branche de l'exécution signée non relue"
  # L'attestation du programme Mac et des nomenclatures : exigée, liée à macos.yml, à master et au commit du passage.
  awk '/gh attestation verify/ { v = 1 } /--signer-workflow "\$DEPOT_CODE\/.github\/workflows\/macos.yml"/ { w = 1 }
    /--source-ref refs\/heads\/master --source-digest "\$SHA_RUN"/ { r = 1 } END { exit !(v && w && r) }' \
    "$DEPOT/outils/publier-version.sh" &&
    ok "publier-version.sh exige l'attestation du Mac et des nomenclatures (macos.yml, master, commit du passage)" ||
    ko "publier-version.sh publie sans vérifier l'attestation de macos.yml sur master"
  # La version macOS mise sur la clé : de master aussi (campagne d'attaque n° 3), commit et empreinte relus.
  awk '/gh run list --workflow macos.yml --branch master/ { b = 1 } /select\(.headBranch == "master"/ { s = 1 }
    /EMPREINTE-VANGUARD-MACOS/ { e = 1 } END { exit !(b && s && e) }' "$DEPOT/outils/deployer.sh" &&
    ok "deployer.sh ne met sur la clé que la compilation macOS de master, commit et empreinte relus" ||
    ko "deployer.sh prend la compilation macOS de n'importe quelle branche"
else
  echo "  (sauté : jq absent, pas de faux gh pour essayer publier-version.sh)"
fi

# 6b. Linux et Windows publiés : les empreintes de la compilation reproductible de la CI (campagne d'attaque n° 6,
# F1). Un faux gh : les exécutions de ci.yml (une sur une autre branche, aux empreintes d'ici : jamais retenue), le
# travail « reproductible » de chacune, son journal. Sans jq, sauté et dit.
if command -v jq >/dev/null; then
  F=$T/faux-gh-ci
  mkdir -p "$F" "$T/dossier-ci"
  printf 'ELF linux' >"$T/dossier-ci/vanguard-linux-x86_64"
  printf 'MZ windows' >"$T/dossier-ci/vanguard-windows-x86_64.exe"
  E_LINUX=$(sha256sum "$T/dossier-ci/vanguard-linux-x86_64" | cut -d' ' -f1)
  E_WINDOWS=$(sha256sum "$T/dossier-ci/vanguard-windows-x86_64.exe" | cut -d' ' -f1)
  journal_ci() { # exécution, empreinte Linux, empreinte Windows ; la ligne du script, recopiée par GitHub, d'abord
    printf '%s\n' 'reproductible	Deux compilations	echo "EMPREINTE-VANGUARD-LINUX $(sha256sum premiere/vanguard)"' \
      "reproductible	Deux compilations	2026-10-31T08:00:00Z EMPREINTE-VANGUARD-LINUX $2" \
      "reproductible	Deux compilations	2026-10-31T08:00:00Z EMPREINTE-VANGUARD-WINDOWS $3" >"$F/journal-$1.txt"
  }
  cat >"$F/gh" <<'GH'
#!/usr/bin/env bash
# run list → runs.json ; run view N --json jobs → travaux-N.json ; run view N --job J --log → journal-N.txt.
q=. vue= travail=
[[ $1 == run && $2 == view ]] && vue=$3
while [[ $# -gt 0 ]]; do
  case $1 in
    -q) q=$2; shift ;;
    --job) travail=$2; shift ;;
  esac
  shift
done
d=$(dirname "$0")
if [[ -n $travail ]]; then
  cat "$d/journal-$vue.txt"
elif [[ -n $vue ]]; then
  jq -r "$q" "$d/travaux-$vue.json"
else
  jq -r "$q" "$d/runs.json"
fi
GH
  chmod +x "$F/gh"
  cat >"$F/runs.json" <<'JSON'
[{"databaseId": 3, "headSha": "c0ffee", "headBranch": "piege", "event": "workflow_dispatch", "status": "completed"},
 {"databaseId": 1, "headSha": "c0ffee", "headBranch": "master", "event": "push", "status": "completed"}]
JSON
  echo '{"jobs": [{"databaseId": 30, "name": "reproductible", "conclusion": "success"}]}' >"$F/travaux-3.json"
  echo '{"jobs": [{"databaseId": 10, "name": "reproductible", "conclusion": "success"}]}' >"$F/travaux-1.json"
  journal_ci 3 "$E_LINUX" "$E_WINDOWS"
  awk '/^empreintes_de_la_ci\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh" >"$T/empreintes_de_la_ci.sh"
  empreintes_ci() { # la sortie de empreintes_de_la_ci, puis « code N »
    local code=0 sortie
    sortie=$(cd "$T" && PATH="$F:$PATH" COMPILE=c0ffee HORS_CODE= DOSSIER=$T/dossier-ci \
      bash -c "source '$T/empreintes_de_la_ci.sh'; empreintes_de_la_ci" 2>&1) || code=$?
    printf '%s\ncode %s\n' "$sortie" "$code"
  }
  ZERO=0000000000000000000000000000000000000000000000000000000000000000
  journal_ci 1 "$E_LINUX" "$E_WINDOWS"
  r=$(empreintes_ci)
  [[ $r == *"exécution 1,"*"code 0" ]] && ok "publier : Linux et Windows aux empreintes de la CI de master acceptés" ||
    ko "publier : empreintes égales à celles de la CI refusées ($r)"
  journal_ci 1 "$ZERO" "$E_WINDOWS"
  r=$(empreintes_ci)
  [[ $r == *"Linux :"*"code 1" && $r != *"Windows :"* ]] &&
    ok "publier : un programme Linux qui n'est pas celui de la CI est refusé (même avec une autre branche d'accord)" ||
    ko "publier : Linux différent de la CI accepté ($r)"
  journal_ci 1 "$E_LINUX" "$ZERO"
  r=$(empreintes_ci)
  [[ $r == *"Windows :"*"code 1" ]] && ok "publier : un programme Windows qui n'est pas celui de la CI est refusé" ||
    ko "publier : Windows différent de la CI accepté ($r)"
  journal_ci 1 "$E_LINUX" "$E_WINDOWS"
  echo '{"jobs": [{"databaseId": 10, "name": "reproductible", "conclusion": "failure"}]}' >"$F/travaux-1.json"
  r=$(empreintes_ci)
  [[ $r == *"code 2" ]] && ok "publier : une compilation reproductible en échec ne compte pas (seule l'autre branche reste)" ||
    ko "publier : empreintes prises d'un travail en échec ou d'une autre branche ($r)"
  echo '{"jobs": [{"databaseId": 10, "name": "reproductible", "conclusion": "success"}]}' >"$F/travaux-1.json"
  printf 'reproductible\tDeux compilations\tcmp: differ\n' >"$F/journal-1.txt"
  r=$(empreintes_ci)
  [[ $r == *"code 2" ]] && ok "publier : un journal sans empreintes ne vaut pas accord" ||
    ko "publier : journal sans empreintes accepté ($r)"
  # Le passage lui-même : sans accord, rien de publié, sauf le passe-droit nommé, et dit.
  awk '/^EMPREINTES_CI=\$\(empreintes_de_la_ci\)/ { a = 1 }
    a && /VANGUARD_PUBLIER_SANS_EMPREINTES_CI:-/ { p = 1 } p && /^  exit 1$/ { x = 1 } END { exit !(a && p && x) }' \
    "$DEPOT/outils/publier-version.sh" &&
    ok "publier-version.sh s'arrête sans les empreintes de la CI (passe-droit nommé seulement)" ||
    ko "publier-version.sh publie sans comparer Linux et Windows à la CI"
else
  echo "  (sauté : jq absent, pas de faux gh pour les empreintes de la CI)"
fi
# Par le nom court : une étiquette nommée master a le même headBranch que la branche, que publier-version.sh
# accepte ; « github.ref != 'refs/heads/master' » lui laissait reprendre un cache préparé.
awk '/uses: Swatinem\/rust-cache/ { getline; exit !($0 ~ /if: github.ref_name != .master.$/) }' \
  "$DEPOT/.github/workflows/macos.yml" && ok "macos.yml : aucun cache repris sur master (branche ou étiquette)" ||
  ko "macos.yml reprend un cache sur master ou une étiquette « master » (le programme signé en sortirait)"
# Une étiquette se déplace (« v7 » suit chaque version) : quiconque la pousse chez l'éditeur de l'action change ce
# qui tourne avec les secrets et le programme signé. Chaque action, officielle comme tierce, à un commit nommé
# (campagne d'attaque n° 4, U-B3), l'étiquette en commentaire pour la relire. Tout fichier que GitHub lit : .yml et
# .yaml des workflows, et les actions du dépôt (.github/actions/*/action.yml), qui en appellent d'autres.
# Ancré au début de la ligne : un « # uses: …@<commit> » en commentaire ne fait pas passer l'étiquette d'avant.
if fichiers=$(find "$DEPOT/.github" \( -path "$DEPOT/.github/workflows/*" -o -path "$DEPOT/.github/actions/*" \) \
  \( -name '*.yml' -o -name '*.yaml' \) -type f) && [[ -n $fichiers ]]; then
  mobiles=$(xargs -d '\n' grep -Hn 'uses:' <<<"$fichiers" |
    grep -Ev '^[^:]+:[0-9]+:\s*(-\s*)?uses:\s*[^ @]+@[0-9a-f]{40} # v[0-9]' || true)
  [[ -z $mobiles ]] && ok "workflows : chaque action épinglée par commit, pas par étiquette" ||
    ko "workflows : action à une étiquette mobile : ${mobiles#"$DEPOT"/}"
else
  ko "workflows : aucun fichier de .github/workflows lu, les épingles ne sont pas vérifiées"
fi

# 8. Les octets publiés, ceux de la compilation de leur commit.
G=$T/depot-compilation
mkdir -p "$G/src" "$G/docs" "$G/.github" "$G/target/x86_64-unknown-linux-musl/release" "$G/target/x86_64-pc-windows-gnu/release"
grep -v '^#' "$DEPOT/.github/hors-code.txt" >"$G/.github/hors-code.txt"
mkdir -p "$G/outils" && cp "$DEPOT/outils/date-du-code.sh" "$G/outils/"
echo 'fn main() {}' >"$G/src/main.rs"
echo doc >"$G/docs/index.md"
git -C "$G" init -q && git -C "$G" add -A && git -C "$G" -c user.name=essai -c user.email=essai@exemple.invalid \
  commit -qm compile
C1=$(git -C "$G" rev-parse HEAD)
programmes_g() { # date gravée
  printf 'ELF VANGUARD-VERSION:0.88.0+%s;' "$1" >"$G/target/x86_64-unknown-linux-musl/release/vanguard"
  printf 'MZ windows' >"$G/target/x86_64-pc-windows-gnu/release/vanguard.exe"
  printf 'commit %s\npropre %s\nlinux-x86_64 %s\nwindows-x86_64 %s\n' "$C1" "${2:-oui}" \
    "$(sha256sum "$G/target/x86_64-unknown-linux-musl/release/vanguard" | cut -d' ' -f1)" \
    "$(sha256sum "$G/target/x86_64-pc-windows-gnu/release/vanguard.exe" | cut -d' ' -f1)" >"$G/target/.compilation"
}
{ grep '^repere() {' "$DEPOT/outils/publier-version.sh"
  awk '/^verifier_compilation\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh"; } >"$T/verifier_compilation.sh"
compilation() { # commit visé (HEAD par défaut) : la sortie de verifier_compilation, son code
  (cd "$G" && COMMIT=${1:-$(git rev-parse HEAD)} LINUX=target/x86_64-unknown-linux-musl/release/vanguard \
    WINDOWS=target/x86_64-pc-windows-gnu/release/vanguard.exe REPERE=target/.compilation \
    HORS_CODE=$(cat .github/hors-code.txt) bash -c "source '$T/verifier_compilation.sh'; verifier_compilation")
}
DATE1=$(git -C "$G" log -1 --format=%ct)
programmes_g "$DATE1"
[[ $(compilation) == "$C1" ]] && ok "publier : les octets de la compilation de ce commit valent" ||
  ko "publier, compilation juste refusée : $(compilation)"
echo autre >>"$G/docs/index.md"
GIT_COMMITTER_DATE="@$((DATE1 + 100)) +0000" git -C "$G" -c user.name=essai -c user.email=essai@exemple.invalid \
  commit -qam captures
[[ $(compilation) == "$C1" ]] && ok "publier : un commit hors du programme (documentation) ne les change pas" ||
  ko "publier après un commit de documentation : $(compilation)"
[[ $(cd "$G" && bash outils/date-du-code.sh) == "$DATE1" ]] &&
  ok "date du code : celle du dernier commit qui touche le programme (le Mac et Linux gravent la même)" ||
  ko "date du code : $(cd "$G" && bash outils/date-du-code.sh) au lieu de $DATE1"
programmes_g $((DATE1 + 100))
compilation >/dev/null && ko "publier : la date d'un commit de documentation gravée est acceptée" ||
  ok "publier : la date gravée doit être celle du code, pas d'un commit de documentation"
programmes_g "$DATE1"
printf 'MZ autre' >"$G/target/x86_64-pc-windows-gnu/release/vanguard.exe"
compilation >/dev/null && ko "publier : un programme remplacé depuis sa compilation est accepté" ||
  ok "publier : un programme remplacé depuis sa compilation (autre worktree, cargo build) est refusé"
programmes_g "$DATE1" non
compilation >/dev/null && ko "publier : une compilation d'un arbre modifié est acceptée" ||
  ok "publier : une compilation d'un arbre aux changements non commités est refusée"
programmes_g 1700000000
compilation >/dev/null && ko "publier : une date gravée d'un autre commit est acceptée" ||
  ok "publier : une date gravée qui n'est pas celle du commit compilé est refusée"
programmes_g "$DATE1"
echo 'fn main() { piege() }' >"$G/src/main.rs"
git -C "$G" -c user.name=essai -c user.email=essai@exemple.invalid commit -qam code
compilation >/dev/null && ko "publier : un code changé depuis la compilation est accepté" ||
  ok "publier : le code a changé depuis la compilation : refusé"

# 9. Le garde de claude.yml : le script de son étape, rejoué avec un faux gh qui dit d'où vient la demande.
Y=$DEPOT/.github/workflows/claude.yml
awk '/^  garde:/ { g = 1 } g && /^  claude:/ { exit } g && /^        run: \|/ { r = 1; next } r { sub(/^          /, ""); print }' \
  "$Y" >"$T/garde.sh"
mkdir -p "$T/faux-gh-garde"
# Le faux gh : d'où vient la demande, puis les auteurs du fil autres que le propriétaire (ESSAI_FIL pour les
# commentaires du ticket, ESSAI_REVUES pour les revues et commentaires de revue), ou une panne de leur lecture
# (ESSAI_PANNE) ; le fil déjà verrouillé ou non (ESSAI_VERROUILLE), et chaque verrouillage noté dans gh.appels.
cat >"$T/faux-gh-garde/gh" <<'FAUX'
#!/bin/sh
methode=GET
chemin=
while [ $# -gt 0 ]; do
  case "$1" in
    -X) methode=$2; shift ;;
    repos/*) chemin=$1 ;;
  esac
  shift
done
case "$methode $chemin" in
  "GET "*/issues/*/comments) printf '%s' "$ESSAI_FIL"; [ -z "$ESSAI_PANNE" ] ;;
  "GET "*/pulls/*/reviews | "GET "*/pulls/*/comments) printf '%s' "$ESSAI_REVUES"; [ -z "$ESSAI_PANNE" ] ;;
  "GET "*/pulls/*) echo "$ESSAI_TETE" ;;
  "GET "*/issues/*) echo "${ESSAI_VERROUILLE:-false}" ;;
  *) echo "$methode $chemin" >>"$ESSAI_APPELS" ;;
esac
FAUX
chmod +x "$T/faux-gh-garde/gh"
# Le script commun, là où les deux étapes le prennent (extrait de la branche principale dans .garde).
mkdir -p "$T/fil/.garde/outils"
cp "$DEPOT/outils/fil-du-proprietaire.sh" "$T/fil/.garde/outils/"
garde() { # numéro de la demande, dépôt d'où elle vient [, étiquettes] : la sortie « permis=… » du garde
  : >"$T/garde.sortie"
  (cd "$T/fil" && PATH="$T/faux-gh-garde:$PATH" GITHUB_OUTPUT=$T/garde.sortie GITHUB_REPOSITORY=d9v3/vanguard-beta \
    DEMANDE=$1 NUMERO=${1:-7} ESSAI_TETE=$2 ETIQUETTES=${3:-,} ESSAI_FIL=${ESSAI_FIL-} ESSAI_REVUES=${ESSAI_REVUES-} \
    ESSAI_PANNE=${ESSAI_PANNE-} ESSAI_APPELS=$T/gh.appels sh "$T/garde.sh" >/dev/null 2>&1)
  cat "$T/garde.sortie"
}
if [[ -s $T/garde.sh ]] && [[ $(garde 12 pirate/vanguard-beta) == permis=non ]] &&
  [[ $(garde 12 d9v3/vanguard-beta) == permis=oui ]] && [[ $(garde "" "") == permis=oui ]]; then
  ok "claude.yml : une demande venue d'un fork est refusée ; du dépôt, ou un ticket, permis"
else
  ko "claude.yml : garde absent ou qui laisse passer un fork ($(garde 12 pirate/vanguard-beta))"
fi
# publier-version.sh ne passe --premier que tapé par l'auteur, jamais d'après un dépôt des versions vide.
awk '/PREMIER=\(--premier\)/ { n++; if ($0 !~ /\$PREMIERE/) l = 1 } /^\[\[ \$\{1:-\} == --premier \]\] && PREMIERE=1$/ { t = 1 }
  END { exit !(n == 1 && !l && t) }' "$DEPOT/outils/publier-version.sh" &&
  ok "publier : --premier seulement tapé, jamais déduit d'un dépôt des versions vide" ||
  ko "publier : --premier passé sans que l'auteur l'ait tapé"
# Un ticket du journal de la clé (écrit depuis n'importe quel ordinateur) : refusé, seul ou parmi d'autres étiquettes,
# ticket ou demande ; « journaux » n'est pas « journal ».
if [[ $(garde "" "" "journal,") == permis=non && $(garde "" "" "bogue,journal,autotest,") == permis=non &&
  $(garde 12 d9v3/vanguard-beta ",journal") == permis=non && $(garde "" "" "journaux,") == permis=oui ]]; then
  ok "claude.yml : un ticket « journal » est refusé"
else
  ko "claude.yml : un ticket « journal » passe le garde"
fi
# Un fil où un autre que le propriétaire a commenté (ticket ou demande), ou a laissé une revue ou un commentaire de
# revue (demande) : refusé ; un fil illisible aussi (relecture adverse de la campagne 4).
if [[ $(ESSAI_FIL=4242 garde "" "") == permis=non && $(ESSAI_FIL=4242 garde 12 d9v3/vanguard-beta) == permis=non &&
  $(ESSAI_REVUES=4242 garde 12 d9v3/vanguard-beta) == permis=non && $(ESSAI_PANNE=1 garde "" "") == permis=non &&
  $(ESSAI_REVUES=4242 garde "" "") == permis=oui ]]; then
  ok "claude.yml : un fil où un autre a commenté ou relu est refusé, un fil illisible aussi"
else
  ko "claude.yml : un fil commenté par un autre passe le garde"
fi
# Le filtre du garde, sur une vraie réponse de l'API : le propriétaire et les robots passent, un autre non.
if command -v jq >/dev/null; then
  filtre=$(sed -n "s/.*--jq '\(.*\)'); then\$/\1/p" "$DEPOT/outils/fil-du-proprietaire.sh")
  fil='[{"id":1,"author_association":"OWNER","user":{"login":"d9v3"}},
    {"id":2,"author_association":"NONE","user":{"login":"passant"}},
    {"id":3,"author_association":"NONE","user":{"login":"claude[bot]"}},
    {"id":4,"author_association":"CONTRIBUTOR","user":{"login":"autre"}}]'
  [[ -n $filtre && $(jq -r "$filtre" <<<"$fil" | paste -sd' ') == "2 4" ]] &&
    ok "claude.yml : le filtre des auteurs du fil ne laisse que le propriétaire et les robots" ||
    ko "claude.yml : filtre des auteurs du fil faux ($filtre)"
else
  echo "  (sauté : jq absent, filtre des auteurs du fil non rejoué)"
fi
# Juste avant Claude : le fil verrouillé (s'il ne l'était pas déjà), puis relu par le même script que le garde ; un
# autre auteur arrivé entre-temps, ou un fil illisible, fait échouer l'étape, et le fil se déverrouille à la fin
# seulement si c'est ce travail qui l'a verrouillé (relecture adverse du 26 octobre : des minutes séparent les deux).
awk '/^      - id: verrou$/ { v = 1; next } v && /^        run: \|/ { r = 1; next } r && !/^          / { exit }
  r { sub(/^          /, ""); print }' "$Y" >"$T/verrou.sh"
verrou() { # numéro de la demande : « code sortie appels »
  : >"$T/verrou.sortie"
  : >"$T/gh.appels"
  (cd "$T/fil" && rm -rf .garde && mkdir -p .garde/outils && cp "$DEPOT/outils/fil-du-proprietaire.sh" .garde/outils/ &&
    PATH="$T/faux-gh-garde:$PATH" GITHUB_OUTPUT=$T/verrou.sortie GITHUB_REPOSITORY=d9v3/vanguard-beta DEMANDE=$1 \
    NUMERO=${1:-7} ESSAI_FIL=${ESSAI_FIL-} ESSAI_REVUES=${ESSAI_REVUES-} ESSAI_PANNE=${ESSAI_PANNE-} \
    ESSAI_VERROUILLE=${ESSAI_VERROUILLE-} ESSAI_APPELS=$T/gh.appels sh -e "$T/verrou.sh" >/dev/null 2>&1)
  echo "$? $(cat "$T/verrou.sortie") $(paste -sd, "$T/gh.appels")"
}
mkdir -p "$T/fil/.garde/outils"
if [[ -s $T/verrou.sh && $(verrou "") == "0 verrouille=oui PUT repos/d9v3/vanguard-beta/issues/7/lock" &&
  $(ESSAI_FIL=4242 verrou "") == "1 verrouille=oui PUT repos/d9v3/vanguard-beta/issues/7/lock" &&
  $(ESSAI_REVUES=4242 verrou 12) == "1 verrouille=oui PUT repos/d9v3/vanguard-beta/issues/12/lock" &&
  $(ESSAI_PANNE=1 verrou "") == "2 verrouille=oui PUT repos/d9v3/vanguard-beta/issues/7/lock" &&
  $(ESSAI_VERROUILLE=true verrou "") == "0  " ]]; then
  ok "claude.yml : juste avant Claude, le fil est verrouillé puis relu ; un autre auteur arrivé entre-temps l'arrête"
else
  ko "claude.yml : fil pas verrouillé ou pas relu avant Claude ($(ESSAI_FIL=4242 verrou ""))"
fi
# L'ordre : Rust, puis le verrou et la relecture, puis Claude aussitôt ; le déverrouillage en dernier, toujours, et
# seulement si ce travail a verrouillé. Les deux relectures prennent le script de la branche principale.
awk '/^  claude:/ { c = 1 } c && /name: Rust à jour/ { rust = NR } c && /^      - id: verrou$/ { v = NR }
  c && /claude-code-action@/ { a = NR } c && /if: always\(\) && steps.verrou.outputs.verrouille == .oui.$/ { d = NR }
  /ref: \$\{\{ github.event.repository.default_branch \}\}/ { ref++ }
  /sh .garde\/outils\/fil-du-proprietaire.sh/ { s++ }
  END { exit !(rust && rust < v && v < a && a < d && ref == 2 && s == 2) }' "$Y" &&
  ok "claude.yml : le verrou et la relecture juste avant Claude, déverrouillé en dernier, script de la branche principale" ||
  ko "claude.yml : ordre des étapes du verrou faux, ou script du fil pris ailleurs"
# Un seul Claude à la fois par fil : le groupe porte le numéro du ticket ou de la demande, et un second @claude attend
# sans annuler le premier (relecture adverse du 26 octobre : sinon le premier déverrouille le fil sous le second).
awk '/^  claude:/ { c = 1 } c && /^    concurrency:$/ { k = 1; next }
  k && /^      group: .*\$\{\{ github.event.issue.number \|\| github.event.pull_request.number \}\}$/ { g = 1 }
  k && /^      cancel-in-progress: false$/ { f = 1 } k && !/^      / { k = 0 } END { exit !(c && g && f) }' "$Y" &&
  ok "claude.yml : un seul Claude à la fois par fil, le second attend sans annuler le premier" ||
  ko "claude.yml : deux Claude sur un même fil en même temps (concurrency absente, mal groupée ou qui annule)"
# Le ticket ou la demande eux-mêmes écrits par le propriétaire, pas seulement le commentaire qui appelle Claude.
awk '/^  garde:/ { g = 1 } g && /^  claude:/ { exit }
  g && /issue_comment.*@claude/ { e = "ic" } g && /pull_request_review_comment.*@claude/ { e = "prc" }
  g && /pull_request_review.*review.body/ { e = "pr" }
  e == "ic" && /github.event.issue.author_association == .OWNER./ { ic = 1 }
  e == "prc" && /github.event.pull_request.author_association == .OWNER./ { prc = 1 }
  e == "pr" && /github.event.pull_request.author_association == .OWNER./ { pr = 1 }
  END { exit !(ic && prc && pr) }' "$Y" &&
  ok "claude.yml : seulement un ticket ou une demande du propriétaire" ||
  ko "claude.yml : un ticket ou une demande d'un autre passe le garde"
awk '/^  claude:/ { c = 1 } c && /needs: garde/ { n = 1 } c && /if: needs.garde.outputs.permis == .oui.$/ { i = 1 }
  c && /persist-credentials: false/ { p = 1 } END { exit !(n && i && p) }' "$Y" &&
  ok "claude.yml : Claude attend le garde, et le jeton de l'extraction n'est pas gardé" ||
  ko "claude.yml : Claude ne dépend pas du garde, ou garde le jeton de l'extraction"

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "Signature des versions : tout est juste."
