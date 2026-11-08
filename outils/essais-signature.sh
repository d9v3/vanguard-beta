#!/usr/bin/env bash
# Essais de outils/signer-versions.sh, avec des clés d'essai et de faux programmes, dans un dossier jetable : rien de
# la vraie clé de signature n'est lu, rien n'est publié.
#   1. derniere.txt et derniere.txt.sig sont identiques, à l'octet, à ceux du script de master (la version que les
#      copies déjà installées, 0.85.0 et d'avant, savent lire) : mêmes programmes, même clé, Ed25519 déterministe.
#      Tant que le script de master signe encore un programme Mac : le même derniere.txt sans sa ligne macos, signé
#      par la même clé, que le lecteur de la 0.85.0 lit pour Linux et Windows et où il ne trouve rien pour macos (un
#      ancien Mac ne se voit proposer aucune version, rien ne casse). L'historique des versions est un fichier à part :
#      ce que lisent ces copies ne change pas.
#   2. L'historique signé grandit d'une version à l'autre, la plus récente en tête, et commence au manifeste signé de
#      la version d'avant quand il n'y a pas encore d'historique.
#   3. Un historique d'avant signé par une autre clé est refusé : rien ne s'ajoute à un historique douteux.
#   4. Sans rien d'avant ni --premier (un téléchargement raté chez publier-version.sh), rien n'est signé : l'historique
#      ne repart pas de zéro avant que les pages d'avant soient effacées.
#   5. La révocation de la clé principale (--secours --revoquer) : la ligne « revoque principale » vient après les
#      deux programmes, que le lecteur de la 0.85.0 (refait ici en awk, comme github.rs le recopie) trouve tous
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
#      un journal sans empreintes, et ignore une autre branche (campagne d'attaque n° 6, F1). Avec le refus, les
#      outils de compilation qui diffèrent (outils/chaine-c.sh : repère d'ici, journal de la CI) sont montrés, sous
#      une forme sûre ; ils ne décident rien.
#   6g. À la publication, l'étiquette de la version d'avant est retirée du dépôt du code (retirer_etiquette_precedente,
#      face à un faux gh), elle seule et notée, une fois la nouvelle page en ligne et ses fichiers relus ; jamais
#      avec-macos, une plus vieille, une plus récente, une annotée, une hors de la ligne de la version, celle d'une
#      page encore en ligne, ni sans pouvoir lire les étiquettes ou noter le retrait.
#   6h. Une compilation reproductible de la CI faite sur un commit d'après celui de la version compte seulement en
#      ligne droite jusqu'à la tête de master, sans fusion, chaque commit entre les deux ne touchant que la liste
#      fermée HORS_COMPILATION (captures, image de partage, page des fonctions : descendant_hors_compilation, dans un
#      dépôt git jetable ; empreintes_de_la_ci, face à un faux gh), en fichiers ordinaires (ni lien symbolique ni
#      sous-module) ; rien du programme ne lit ces fichiers, et les notes le disent.
#   6i. zig, la chaîne C des programmes publiés (outils/chaine-zig.sh), n'est pris que sous sa signature minisign,
#      vérifiée par openssl : une signature d'essai juste passe ; un octet changé, un autre nom de fichier (retour en
#      arrière), un commentaire de confiance réécrit ou à deux noms, une autre clé, l'ancienne forme « Ed », une
#      signature abîmée ou incomplète sont refusés ; l'empreinte de zig et de cargo-zigbuild est épinglée.
#   6c. Au branchement de la clé, deployer.sh (ci_verte, face à un faux gh) ne récupère ni ne compile un commit de
#      GitHub sans CI verte sur ce commit exact (ci.yml, master ; campagne d'attaque n° 6, F4), et dit à part gh sans
#      compte connecté ou introuvable (sinon, sous le service de la clé, « réessayé » pour toujours sans alerte).
#   6e. publier-version.sh n'attend pas sans fin une exécution de GitHub (CI) bloquée : attendre_execution, face à un
#      faux gh qui ne finit jamais, abandonne au délai.
#   6f. Les protections des programmes qui partent (vanguard deploiement verifier-binaire) : publier-version.sh les
#      fait lire (verifier_binaires, face à un faux programme Linux) sur les copies Linux et Windows, après la relecture
#      de leurs empreintes ; deployer.sh, sur ce qui part ; un refus arrête tout.
#   6d. Un passe-droit de publier-version.sh (VANGUARD_PUBLIER_SANS_EMPREINTES_CI, VANGUARD_PUBLIER_SANS_VM) est dit
#      en tête des notes de la page (notes, face à un faux gh) et gardé dans le bloc de sa version de l'historique
#      signé (signer-versions.sh --passe-droit), sous la forme que lit github.rs, jamais dans derniere.txt ; de même
#      le commit entier d'une CI faite après la version (--ci-apres), retrouvé et revérifié par publier-version.sh.
#   6. Les nomenclatures attestées que la page publie viennent d'une exécution de master : publier-version.sh (sa
#      fonction avec_nomenclatures, face à un faux gh) écarte celle d'une autre branche, même plus récente et du même
#      commit ; et les travaux « nomenclatures » et « attester » de ci.yml ne reprennent aucun cache, « attester » ne
#      lance rien du dépôt. Sans jq, cet essai est sauté et dit. Chaque action des workflows est épinglée à un commit,
#      jamais à une étiquette qui bouge.
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
# Deux faux programmes à la forme attendue (ELF x86-64, PE x86-64), avec leur version gravée et la principale gardée,
# comme le marque github.rs (RETIREE=true : retirée, pour --revoquer). MAC=1 : un troisième, Mach-O universel arm64 +
# x86_64, pour le script de master tant qu'il signe encore un programme Mac.
programmes() { # $1 : dossier, $2 : version gravée
  mkdir -p "$1"
  local v="VANGUARD-VERSION:$2; VANGUARD-PRINCIPALE:GARDEE;"
  [[ ${RETIREE:-false} == false ]] || v="VANGUARD-VERSION:$2; VANGUARD-PRINCIPALE:RETIREE;"
  { printf '\x7fELF\x02\x01'; head -c 12 /dev/zero; printf '\x3e\x00'; printf 'linux %s' "$v"; } >"$1/vanguard-linux-x86_64"
  { printf 'MZ'; head -c 58 /dev/zero; printf '\x40\x00\x00\x00'; printf 'PE\x00\x00\x64\x86'; printf 'windows %s' "$v"; } \
    >"$1/vanguard-windows-x86_64.exe"
  [[ -n ${MAC:-} ]] || return 0
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

# Le lecteur de la 0.85.0 (lire_manifeste) : la version en tête, puis la ligne du système cherché trouvée avant toute
# ligne qui n'a pas trois champs.
lu_par_la_0_85() { # $1 : manifeste, $2 : système ; affiche « empreinte taille »
  awk -v s="$2" 'NR == 1 { if ($0 !~ /^version /) exit 1; next } NF != 3 { exit 1 } $1 == s { print $2, $3; trouve = 1; exit }
    END { exit !trouve }' "$1"
}

git show master:outils/signer-versions.sh >"$T/ancien.sh"
banc "$T/ancien" "$T/ancien.sh" 0.86.0
banc "$T/nouveau" "$DEPOT/outils/signer-versions.sh" 0.86.0
# Le script de master signe-t-il encore un programme Mac ? Il lui faut alors le sien, et son derniere.txt a une ligne
# macos de plus que celui d'ici.
MAC_ANCIEN=
grep -q 'vanguard-macos' "$T/ancien.sh" && MAC_ANCIEN=1
MAC=$MAC_ANCIEN programmes "$T/v86-ancien" 0.86.0+1792600000
programmes "$T/v86" 0.86.0+1792600000
# Le script de master connaît --premier depuis qu'il tient l'historique (0.86) : sans rien d'avant, il l'exige.
premier_ancien=()
grep -q -- '--premier' "$T/ancien.sh" && premier_ancien=(--premier)
signer "$T/ancien" "$T/v86-ancien" "${premier_ancien[@]}" || { ko "script de master : $(tail -n 1 "$T/v86-ancien.log")"; }
if signer "$T/nouveau" "$T/v86" --premier; then
  if [[ -z $MAC_ANCIEN ]]; then
    if cmp -s "$T/v86/derniere.txt" "$T/v86-ancien/derniere.txt" &&
      cmp -s "$T/v86/derniere.txt.sig" "$T/v86-ancien/derniere.txt.sig"; then
      ok "derniere.txt et sa signature identiques à l'octet à ceux du script de master (ce que lit la 0.85.0)"
    else
      ko "derniere.txt ou sa signature diffèrent de ceux du script de master"
    fi
  # Le Mac retiré : la même forme, la même clé et le même domaine, une ligne de moins. Jamais une ligne macos à un ou
  # deux champs, que le lecteur de la 0.85.0 refuserait pour tous les systèmes.
  elif grep -q '^macos ' "$T/v86-ancien/derniere.txt" &&
    cmp -s <(grep -v '^macos ' "$T/v86-ancien/derniere.txt") "$T/v86/derniere.txt" &&
    signe "$T/v86/derniere.txt" 'vanguard-versions 1'; then
    ok "derniere.txt : celui du script de master sans sa ligne macos, signé par la même clé et sous le même domaine"
  else
    ko "derniere.txt diffère de celui du script de master autrement que par sa ligne macos, ou est mal signé"
  fi
  pareil=1
  for s in linux-x86_64 windows-x86_64; do
    attendu=$(grep "^$s " "$T/v86/derniere.txt" | cut -d' ' -f2-)
    [[ -n $attendu && $(lu_par_la_0_85 "$T/v86/derniere.txt" "$s") == "$attendu" ]] || pareil=
  done
  [[ -n $pareil ]] && ok "le lecteur de la 0.85.0 lit Linux et Windows dans derniere.txt" ||
    ko "le lecteur de la 0.85.0 ne lit plus derniere.txt"
  ! grep -qE '^macos( |$)' "$T/v86/derniere.txt" && ! lu_par_la_0_85 "$T/v86/derniere.txt" macos >/dev/null &&
    ok "aucune ligne macos : un ancien Mac n'y trouve aucune version, sans erreur pour les autres" ||
    ko "derniere.txt a encore une ligne macos"
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
# La révocation par des programmes qui gardent la principale (un seul suffit, ici celui de Windows, lu en dernier) :
# refusée avant toute signature, la phrase de la clé n'est même pas demandée.
programmes "$T/sans-retrait" 0.88.0+1793100000
RETIREE=false programmes "$T/garde" 0.88.0+1793100000 &&
  cp "$T/garde/vanguard-windows-x86_64.exe" "$T/sans-retrait/"
if signer "$T/nouveau88" "$T/sans-retrait" --secours --revoquer; then
  ko "--revoquer a signé des programmes qui acceptent encore la principale"
elif grep -q "vanguard-windows-x86_64.exe accepte encore la principale" "$T/sans-retrait.log" &&
  [[ ! -e $T/sans-retrait/derniere.txt.sig ]]; then
  ok "--revoquer avec un programme qui garde la principale : refusé, rien n'est signé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/sans-retrait.log")"
fi
# Les deux marques dans un même programme (assemblé de morceaux de compilations différentes) : refusé de même.
programmes "$T/deux-marques" 0.88.0+1793100000
printf 'VANGUARD-PRINCIPALE:GARDEE;' >>"$T/deux-marques/vanguard-windows-x86_64.exe"
if signer "$T/nouveau88" "$T/deux-marques" --secours --revoquer; then
  ko "--revoquer a signé un programme qui porte aussi la marque de la principale gardée"
elif grep -q "vanguard-windows-x86_64.exe accepte encore la principale" "$T/deux-marques.log" &&
  [[ ! -e $T/deux-marques/derniere.txt.sig ]]; then
  ok "--revoquer avec un programme aux deux marques : refusé, rien n'est signé"
else
  ko "refus pour une autre raison : $(tail -n 1 "$T/deux-marques.log")"
fi
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
    for s in linux-x86_64 windows-x86_64; do
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
    { printf 'version 0.87.5+1792999999\nlinux-x86_64 %s 123\nwindows-x86_64 %s 1\n' \
      "$(printf 'f%.0s' {1..64})" "$(printf 'e%.0s' {1..64})"
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
# Les deux marques (un programme dont un morceau la retire) : refusé aussi, sans --secours.
programmes "$T/v102" 0.88.0+1794200000
printf 'VANGUARD-PRINCIPALE:RETIREE;' >>"$T/v102/vanguard-windows-x86_64.exe"
refus "$T/v102" "seule marque de la principale gardée" "principale : un programme aux deux marques est refusé"

# Les nomenclatures publiées : seulement une exécution de master. Un faux gh répond comme GitHub (jq applique les -q),
# avec deux passages réussis du même commit : le plus récent sur une autre branche, l'autre sur master par un envoi.
if command -v jq >/dev/null; then
  mkdir -p "$T/faux-gh"
  cat >"$T/faux-gh/runs.json" <<'JSON'
[{"databaseId": 2, "headSha": "c0ffee", "headBranch": "piege", "event": "workflow_dispatch"},
 {"databaseId": 1, "headSha": "c0ffee", "headBranch": "master", "event": "push"}]
JSON
  cat >"$T/faux-gh/gh" <<'GH'
#!/usr/bin/env bash
q=. branche= vue=
while [[ $# -gt 0 ]]; do
  case $1 in
    -q) q=$2; shift ;;
    --branch) branche=$2; shift ;;
    view) vue=1 ;;
  esac
  shift
done
if [[ -n $vue ]]; then
  # « run view … --json jobs » : les travaux de jobs.json, pareils pour chaque passage.
  jq -r "$q" "$(dirname "$0")/jobs.json"
elif [[ -n $branche ]]; then
  jq -r --arg b "$branche" "[.[] | select(.headBranch == \$b)] | $q" "$(dirname "$0")/runs.json"
else
  # « api …/artifacts » ou « run list » sans branche : chaque passage a ses nomenclatures.
  case $q in
    *artifacts*) echo nomenclatures ;;
    *) jq -r "$q" "$(dirname "$0")/runs.json" ;;
  esac
fi
GH
  chmod +x "$T/faux-gh/gh"
  awk '/^(attestee_et_essayee|avec_nomenclatures)\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh" \
    >"$T/avec_nomenclatures.sh"
  # $1 : conclusion du travail « linux », $2 : celle de « windows » ; « attester » a réussi.
  choix() {
    printf '{"jobs": [{"name": "attester", "conclusion": "success"}, {"name": "linux", "conclusion": "%s"},
      {"name": "windows", "conclusion": "%s"}, {"name": "fuzzing", "conclusion": "failure"}]}' "$1" "$2" \
      >"$T/faux-gh/jobs.json"
    PATH="$T/faux-gh:$PATH" COMMIT=c0ffee HORS_CODE= bash -c "source '$T/avec_nomenclatures.sh'; avec_nomenclatures"
  }
  choisi=$(choix success success)
  [[ $choisi == 1 ]] && ok "publier-version.sh prend les nomenclatures de master, pas celles d'une autre branche" ||
    ko "publier-version.sh a pris les nomenclatures de « ${choisi:-aucune} » (attendu : 1, celles de master)"
  choisi=$(choix success skipped)
  [[ $choisi == 1 ]] && ok "publier-version.sh prend les nomenclatures d'un passage au travail Windows sauté" ||
    ko "nomenclatures d'un passage au travail Windows sauté refusées (« ${choisi:-aucune} »)"
  choisi=$(choix failure success)$(choix success failure)$(choix success cancelled)$(choix skipped skipped)
  [[ -z $choisi ]] && ok "publier-version.sh refuse les nomenclatures d'un passage aux essais Linux ou Windows ratés" ||
    ko "nomenclatures prises malgré des essais Linux ou Windows ratés (« $choisi »)"
  # La relance relit les mêmes travaux.
  grep -q '^  attestee_et_essayee "\$RUN" ||$' "$DEPOT/outils/publier-version.sh" &&
    ok "publier-version.sh relit les essais de la CI qu'il relance" ||
    ko "la CI relancée n'est pas relue (attester, linux, windows)"
  # Relue sur l'exécution même dont les nomenclatures partent : master, par un envoi, la nuit ou à la main ; tout le
  # reste arrête la publication.
  awk '/^case \$BRANCHE_RUN in$/ { c = 1; next }
    c && /^  "master push" \| "master schedule" \| "master workflow_dispatch"\) ;;$/ { m = 1; next }
    c && m && /^  \*\)$/ { a = 1; next } c && a && /^    exit 1$/ { x = 1 } /^esac$/ { c = 0 }
    END { exit !(m && a && x) }' "$DEPOT/outils/publier-version.sh" &&
    ok "publier-version.sh relit la branche de l'exécution dont il publie les nomenclatures" ||
    ko "branche de l'exécution des nomenclatures non relue"
  # L'attestation des nomenclatures : exigée, liée à ci.yml, à master et au commit du passage.
  awk '/gh attestation verify/ { v = 1 } /--signer-workflow "\$DEPOT_CODE\/.github\/workflows\/ci.yml"/ { w = 1 }
    /--source-ref refs\/heads\/master --source-digest "\$SHA_RUN"/ { r = 1 } END { exit !(v && w && r) }' \
    "$DEPOT/outils/publier-version.sh" &&
    ok "publier-version.sh exige l'attestation des nomenclatures (ci.yml, master, commit du passage)" ||
    ko "publier-version.sh publie sans vérifier l'attestation de ci.yml sur master"
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
  awk '/^outils_differents\(\) \{/,/^\}/; /^empreintes_de_la_ci\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh" \
    >"$T/empreintes_de_la_ci.sh"
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
  # Les outils de compilation qui diffèrent, montrés à côté du refus (repère d'ici contre journal de la CI) : ni un
  # outil égal, ni une ligne d'une autre forme (la commande recopiée par GitHub, des caractères de terminal).
  printf 'outil cc=cc (GCC) 16.2.1\noutil mingw-runtime=ucrt\n' >"$T/repere-outils"
  printf '%s\n' "reproductible	Deux compilations	bash outils/chaine-c.sh | sed 's/^/OUTILS-VANGUARD /'" \
    "reproductible	Deux compilations	2026-10-31T08:00:00Z OUTILS-VANGUARD cc=cc (GCC) 16.2.1" \
    "reproductible	Deux compilations	2026-10-31T08:00:00Z OUTILS-VANGUARD mingw-runtime=msvcrt" \
    "reproductible	Deux compilations	2026-10-31T08:00:00Z OUTILS-VANGUARD ld=$(printf '\033]0;titre\007')GNU ld" \
    >>"$F/journal-1.txt"
  r=$(REPERE=$T/repere-outils empreintes_ci)
  [[ $r == *"mingw-runtime : « ucrt » ici, « msvcrt » dans la CI"*"code 1" && $r != *" cc : "* && $r != *"ld :"* ]] &&
    ok "publier : les outils de compilation qui diffèrent de ceux de la CI sont montrés avec le refus" ||
    ko "publier : outils de compilation différents pas montrés, ou mal ($r)"
  # Ce que chaine-c.sh écrit (repère d'ici, journal de la CI) : les mêmes noms dans le même ordre, des valeurs aux
  # seuls caractères sûrs, même d'un outil qui écrit des caractères de terminal ; et compiler-version.sh les garde.
  mkdir -p "$T/faux-cc"
  printf '#!/bin/sh\nprintf "\\033]0;titre\\007cc (essai) 1.0\\n"\n' >"$T/faux-cc/cc"
  chmod +x "$T/faux-cc/cc"
  r=$(PATH="$T/faux-cc:$PATH" bash "$DEPOT/outils/chaine-c.sh")
  [[ $(cut -d= -f1 <<<"$r" | tr '\n' ' ') == "rustc cc ld musl-gcc musl mingw-gcc mingw-fils mingw-ld mingw-w64 mingw-runtime " &&
    -z $(grep -vE '^[a-z0-9-]+=[A-Za-z0-9 ._:+()/,~-]{1,120}$' <<<"$r") && $r == *$'\n'"cc=0titrecc (essai) 1.0"$'\n'* ]] &&
    grep -qF "bash outils/chaine-c.sh | sed 's/^/outil /'" "$DEPOT/outils/compiler-version.sh" &&
    grep -qF "bash outils/chaine-c.sh | sed 's/^/OUTILS-VANGUARD /'" "$DEPOT/.github/workflows/ci.yml" &&
    ok "chaine-c.sh : outils de compilation relevés sous une forme sûre, dans le repère et dans le journal de la CI" ||
    ko "chaine-c.sh : sortie inattendue ($r)"
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

# 6g. L'étiquette de la version d'avant, retirée du dépôt du code à la publication de la suivante : elle seule, une
# fois la nouvelle page en ligne et relue, et notée (retirer_etiquette_precedente, face à un faux gh qui tient les
# pages, les fichiers d'une page et les étiquettes, et note chaque retrait demandé). Sans jq, sauté et dit.
if command -v jq >/dev/null; then
  F=$T/faux-gh-etiquette
  E=$T/depot-etiquette
  mkdir -p "$F" "$E" "$T/dossier-etiquette"
  git -C "$E" init -q
  commit_e() { git -C "$E" -c user.name=essai -c user.email=essai@exemple.invalid commit -q --allow-empty -m "$1" &&
    git -C "$E" rev-parse HEAD; }
  E_AVANT=$(commit_e "version d'avant")
  E_COMPILE=$(commit_e "cette version")
  git -C "$E" checkout -q -b cote "$E_AVANT"
  E_COTE=$(commit_e "à côté")
  git -C "$E" checkout -q -
  D=$T/dossier-etiquette
  printf 'MZ windows' >"$D/vanguard-windows-x86_64.exe"
  printf 'ELF linux' >"$D/vanguard-linux-x86_64"
  printf 'sommes' >"$D/SHA256SUMS.txt"
  printf '{}' >"$D/vanguard-linux-x86_64.cdx.json"
  printf '{ }' >"$D/vanguard-windows-x86_64.cdx.json"
  cat >"$F/gh" <<'GH'
#!/usr/bin/env bash
# release view T → page-T.json ; release list → pages.json ; api …/matching-refs/tags/ → refs.json (ou une panne si
# le fichier panne-refs existe) ; api -X DELETE …/git/refs/tags/X → noté dans appels, X retiré de refs.json.
d=$(dirname "$0") q=. methode=GET chemin= sorte= vue=
case "$1 $2" in
  "release view") sorte=vue vue=$3 ;;
  "release list") sorte=liste ;;
  api*) sorte=api ;;
esac
while [[ $# -gt 0 ]]; do
  case $1 in
    -q) q=$2; shift ;;
    -X) methode=$2; shift ;;
    repos/*) chemin=$1 ;;
  esac
  shift
done
case $sorte in
  vue) [[ -f $d/page-$vue.json ]] || exit 1; jq -r "$q" "$d/page-$vue.json" ;;
  liste) jq -r "$q" "$d/pages.json" ;;
  api)
    if [[ $methode == DELETE ]]; then
      echo "DELETE $chemin" >>"$d/appels"
      jq --arg r "refs/${chemin##*/git/refs/}" '[.[] | select(.ref != $r)]' "$d/refs.json" >"$d/refs.neuf" &&
        mv "$d/refs.neuf" "$d/refs.json"
    else
      [[ ! -f $d/panne-refs ]] || exit 1
      jq -r "$q" "$d/refs.json"
    fi
    ;;
  *) exit 1 ;;
esac
GH
  chmod +x "$F/gh"
  # L'état de GitHub juste après la publication de v0.92.0 : sa page seule (celle de v0.91.0 vient d'être retirée),
  # ses fichiers ceux du dossier, les étiquettes avec-macos, v0.90.1 (oubliée), v0.91.0 et v0.92.0.
  etat_etiquette() {
    rm -f "$F/appels" "$F/panne-refs" "$T/etiquettes-retirees.txt"
    echo '[{"tagName": "v0.92.0"}]' >"$F/pages.json"
    (cd "$D" && for f in *; do printf '%s %s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"; done) |
      jq -Rn '{tagName: "v0.92.0", isDraft: false, isPrerelease: false,
        assets: [inputs | split(" ") | {name: .[0], digest: ("sha256:" + .[1])}]}' >"$F/page-v0.92.0.json"
    jq -n --arg avant "$E_AVANT" --arg compile "$E_COMPILE" '[
      {ref: "refs/tags/avec-macos", object: {type: "commit", sha: $avant}},
      {ref: "refs/tags/v0.90.1", object: {type: "commit", sha: $avant}},
      {ref: "refs/tags/v0.91.0", object: {type: "commit", sha: $avant}},
      {ref: "refs/tags/v0.92.0", object: {type: "commit", sha: $compile}}]' >"$F/refs.json"
  }
  vise() { # étiquette, type, commit : change ce que vise une étiquette du faux dépôt
    jq --arg r "refs/tags/$1" --arg t "$2" --arg s "$3" \
      'map(if .ref == $r then .object = {type: $t, sha: $s} else . end)' "$F/refs.json" >"$F/refs.neuf" &&
      mv "$F/refs.neuf" "$F/refs.json"
  }
  { grep '^ETIQUETTES_RETIREES=' "$DEPOT/outils/publier-version.sh"
    awk '/^etiquettes_du_depot\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh"
    awk '/^retirer_etiquette_precedente\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh"; } >"$T/etiquette.sh"
  etiquette() { # étiquette d'avant relevée [version publiée] : la sortie, puis « code N »
    local code=0 sortie
    sortie=$(cd "$E" && PATH="$F:$PATH" PRECEDENTE=$1 VERSION=${2:-0.92.0} TAG=v${2:-0.92.0} COMPILE=$E_COMPILE \
      DOSSIER=$D DEPOT_CODE=essai/depot VANGUARD_ETIQUETTES_RETIREES=$T/etiquettes-retirees.txt \
      bash -c "source '$T/etiquette.sh'; retirer_etiquette_precedente" 2>&1) || code=$?
    printf '%s\ncode %s\n' "$sortie" "$code"
  }
  aucun_retrait() { [[ ! -s $F/appels ]]; }

  etat_etiquette
  r=$(etiquette v0.91.0)
  [[ $r == *"retirée"*"code 0" && $(cat "$F/appels") == "DELETE repos/essai/depot/git/refs/tags/v0.91.0" ]] &&
    grep -qE "^[0-9T:-]+Z v0\.91\.0 $E_AVANT remplacee-par v0\.92\.0\$" "$T/etiquettes-retirees.txt" &&
    [[ $(jq -r '.[].ref' "$F/refs.json" | tr '\n' ' ') == "refs/tags/avec-macos refs/tags/v0.90.1 refs/tags/v0.92.0 " ]] &&
    ok "publier : l'étiquette de la version d'avant, elle seule, retirée et notée (avec-macos et les autres restent)" ||
    ko "publier : retrait de l'étiquette d'avant ($r ; $(cat "$F/appels" 2>/dev/null))"
  for cas in "avec-macos|avec-macos" "v0.92.0|la version publiée elle-même" "v0.93.0|une version plus récente" \
    "v0.90.1|une version plus vieille que celle d'avant" "|aucune page relevée" "v0.91.0 |une forme inattendue"; do
    etat_etiquette
    r=$(etiquette "${cas%%|*}")
    [[ $r == *"gardée"*"code 1" ]] && aucun_retrait && ok "publier : étiquette gardée, $(cut -d'|' -f2 <<<"$cas")" ||
      ko "publier : étiquette retirée pour $(cut -d'|' -f2 <<<"$cas") ($r)"
  done
  etat_etiquette
  jq '.isDraft = true' "$F/page-v0.92.0.json" >"$F/p" && mv "$F/p" "$F/page-v0.92.0.json"
  r=$(etiquette v0.91.0)
  [[ $r == *"code 1" ]] && aucun_retrait && ok "publier : rien retiré tant que la nouvelle page est un brouillon" ||
    ko "publier : étiquette retirée avec une page en brouillon ($r)"
  etat_etiquette
  rm "$F/page-v0.92.0.json"
  r=$(etiquette v0.91.0)
  [[ $r == *"code 1" ]] && aucun_retrait && ok "publier : rien retiré sans la nouvelle page en ligne" ||
    ko "publier : étiquette retirée sans nouvelle page ($r)"
  etat_etiquette
  jq '.assets[1].digest = "sha256:'"$(printf '0%.0s' {1..64})"'"' "$F/page-v0.92.0.json" >"$F/p" &&
    mv "$F/p" "$F/page-v0.92.0.json"
  r=$(etiquette v0.91.0)
  [[ $r == *"empreintes"*"code 1" ]] && aucun_retrait &&
    ok "publier : rien retiré si un fichier en ligne n'a pas l'empreinte de celui d'ici" ||
    ko "publier : étiquette retirée avec un fichier en ligne différent ($r)"
  etat_etiquette
  jq 'del(.assets[0])' "$F/page-v0.92.0.json" >"$F/p" && mv "$F/p" "$F/page-v0.92.0.json"
  r=$(etiquette v0.91.0)
  [[ $r == *"code 1" ]] && aucun_retrait && ok "publier : rien retiré s'il manque un fichier à la nouvelle page" ||
    ko "publier : étiquette retirée avec un fichier manquant ($r)"
  etat_etiquette
  vise v0.92.0 commit "$E_COTE"
  r=$(etiquette v0.91.0)
  [[ $r == *"commit compilé"*"code 1" ]] && aucun_retrait &&
    ok "publier : rien retiré si la nouvelle étiquette ne vise pas le commit compilé" ||
    ko "publier : étiquette retirée, la nouvelle sur un autre commit ($r)"
  etat_etiquette
  echo '[{"tagName": "v0.92.0"}, {"tagName": "v0.91.0"}]' >"$F/pages.json"
  r=$(etiquette v0.91.0)
  [[ $r == *"encore en ligne"*"code 1" ]] && aucun_retrait &&
    ok "publier : l'étiquette d'une page encore en ligne reste" ||
    ko "publier : étiquette retirée sous une page en ligne ($r)"
  etat_etiquette
  vise v0.91.0 tag "$E_AVANT"
  r=$(etiquette v0.91.0)
  [[ $r == *"légère"*"code 1" ]] && aucun_retrait && ok "publier : une étiquette annotée (pas posée par la publication) reste" ||
    ko "publier : étiquette annotée retirée ($r)"
  etat_etiquette
  vise v0.91.0 commit "$E_COTE"
  r=$(etiquette v0.91.0)
  [[ $r == *"code 1" ]] && aucun_retrait && ok "publier : une étiquette sur un commit hors de la ligne de la version reste" ||
    ko "publier : étiquette d'un commit à côté retirée ($r)"
  etat_etiquette
  touch "$F/panne-refs"
  r=$(etiquette v0.91.0)
  [[ $r == *"code 1" ]] && aucun_retrait && ok "publier : étiquettes illisibles (API muette) : rien retiré" ||
    ko "publier : étiquette retirée sans pouvoir lire les étiquettes ($r)"
  etat_etiquette
  mkdir "$T/etiquettes-retirees.txt"
  r=$(etiquette v0.91.0)
  rmdir "$T/etiquettes-retirees.txt"
  [[ $r == *"noter"*"code 1" ]] && aucun_retrait && ok "publier : rien retiré sans pouvoir le noter" ||
    ko "publier : étiquette retirée sans être notée ($r)"
  # Le passage lui-même : la page d'avant relevée avant la création de la nouvelle, et le retrait de son étiquette
  # après celui des pages, sous la même condition (mise à jour signée en ligne).
  awk '/^PRECEDENTE=\$\(gh release view -R "\$DEPOT_CODE"/ { p = NR } /^gh release create "\$TAG" --target/ { c = NR }
    /^if \[\[ -z \$SIGNEE \|\| -n \$PUBLIEE_SIGNEE \]\]; then$/ { s = NR } s && /gh release delete "\$ancienne" --yes/ { d = NR }
    d && /^  retirer_etiquette_precedente \|\| true$/ { r = NR } s && !f && /^fi$/ { f = NR }
    END { exit !(p && c && p < c && s > c && d > s && r > d && f > r) }' "$DEPOT/outils/publier-version.sh" &&
    ok "publier-version.sh relève la page d'avant avant de publier, et retire son étiquette après sa page" ||
    ko "publier-version.sh : relevé ou retrait de l'étiquette d'avant hors de leur place"
else
  echo "  (sauté : jq absent, pas de faux gh pour l'étiquette d'avant)"
fi

# 6h. La compilation reproductible de la CI faite sur un commit d'après celui de la version (les captures et la page
# des fonctions que deployer.sh committe ensuite, et sur lesquels la CI tourne) : acceptée seulement en ligne droite
# jusqu'à la tête de master, sans fusion, chaque commit entre les deux ne touchant que la liste fermée
# HORS_COMPILATION (descendant_hors_compilation, dans un dépôt git jetable) ; puis empreintes_de_la_ci face à un faux
# gh, et ce qu'en disent les notes. Sans jq, la partie au faux gh est sautée et dite.
H=$T/depot-apres
mkdir -p "$H/src" "$H/docs" "$H/assets/captures" "$H/outils"
commit_h() { git -C "$H" add -A && git -C "$H" -c user.name=essai -c user.email=essai@exemple.invalid commit -qm "$1" &&
  git -C "$H" rev-parse HEAD; }
echo 'fn main() {}' >"$H/src/main.rs"
echo 'pub fn f() {}' >"$H/src/lib.rs"
echo 0.92.0 >"$H/assets/captures/VERSION"
echo page >"$H/docs/index.html"
echo recette >"$H/outils/compiler-version.sh"
git -C "$H" init -q
H_COMPILE=$(commit_h "Vanguard 0.92.0 (v0.92.0)")
printf 'png' >"$H/assets/captures/accueil.png"
printf 'png' >"$H/assets/partage.png"
echo 0.92.0+1 >"$H/assets/captures/VERSION"
H_CAPTURES=$(commit_h "Captures d'écran : v0.92.0")
echo page2 >"$H/docs/index.html"
H_PAGE=$(commit_h "Page des fonctions : v0.92.0")
{ grep -E '^(HORS_COMPILATION|ENTREE_HORS_COMPILATION)=' "$DEPOT/outils/publier-version.sh"
  awk '/^descendant_hors_compilation\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh"; } >"$T/descendant.sh"
apres() { # commit compilé, commit de la CI, tête de master (le dernier commit par défaut) : le code
  (cd "$H" && COMMIT=${3:-$(git rev-parse HEAD)} \
    bash -c "source '$T/descendant.sh'; descendant_hors_compilation '$1' '$2'")
}
# Un commit de plus sur une branche à part, depuis la page des fonctions : le chemin donné, ou une commande qui
# prépare l'arbre (renommage, fusion…). Rend son commit ; la branche principale reste où elle était.
a_part() { # nom de la branche, chemin à changer
  git -C "$H" checkout -q -b "$1" "$H_PAGE"
  mkdir -p "$H/$(dirname "$2")" && printf '%s' "$1" >>"$H/$2"
  commit_h "$1"
  git -C "$H" checkout -q "$H_PAGE" 2>/dev/null
}
apres "$H_COMPILE" "$H_PAGE" && apres "$H_COMPILE" "$H_CAPTURES" &&
  ok "publier : une CI faite après la version, sur les captures puis la page des fonctions, compte" ||
  ko "publier : CI faite sur les captures ou la page des fonctions refusée"
for cas in "md|docs/autre.md" "outils|outils/compiler-version.sh" "ci|.github/workflows/ci.yml" "src|src/main.rs" \
  "sous-dossier|assets/captures/sous/a.png" "autre-extension|assets/captures/a.png.sh" "cargo|Cargo.toml" \
  "assets|assets/oui.tsv" "cachee|assets/captures/.a.png" "attributs|.gitattributes" "ligne|assets/captures/a
b.png"; do
  c=$(a_part "${cas%%|*}" "${cas#*|}")
  [[ $c =~ ^[0-9a-f]{40}$ ]] || { ko "publier : commit d'essai pas fait (${cas#*|})"; continue; }
  apres "$H_COMPILE" "$c" "$c" && ko "publier : CI acceptée après un commit qui touche ${cas#*|}" ||
    ok "publier : CI refusée après un commit qui touche $(head -n 1 <<<"${cas#*|}")…"
done
git -C "$H" checkout -q -b renomme "$H_PAGE"
git -C "$H" mv src/lib.rs assets/captures/lib.png
R=$(commit_h renommage)
git -C "$H" checkout -q "$H_PAGE"
apres "$H_COMPILE" "$R" "$R" && ko "publier : CI acceptée après un renommage depuis src/" ||
  ok "publier : CI refusée après un renommage depuis src/ vers les captures (ses deux chemins comptent)"
# Le nom ne suffit pas : un lien symbolique ou un sous-module nommé comme une capture est refusé ; un fichier
# ordinaire rendu exécutable ou effacé reste accepté.
git -C "$H" checkout -q -b lien "$H_PAGE"
ln -s ../../src/main.rs "$H/assets/captures/lien.png"
LIEN=$(commit_h "lien")
git -C "$H" checkout -q -b sous-module "$H_PAGE"
git -C "$H" update-index --add --cacheinfo "160000,$H_COMPILE,assets/captures/module.png"
git -C "$H" -c user.name=essai -c user.email=essai@exemple.invalid commit -qm "sous-module"
MODULE=$(git -C "$H" rev-parse HEAD)
git -C "$H" checkout -q -b ordinaire "$H_PAGE"
chmod +x "$H/assets/captures/accueil.png"
git -C "$H" rm -q assets/partage.png
ORDINAIRE=$(commit_h "exécutable et effacé")
git -C "$H" checkout -q "$H_PAGE"
[[ $(git -C "$H" ls-tree "$LIEN" assets/captures/lien.png) == 120000* &&
  $(git -C "$H" ls-tree "$MODULE" assets/captures/module.png) == 160000* ]] &&
  ! apres "$H_COMPILE" "$LIEN" "$LIEN" && ! apres "$H_COMPILE" "$MODULE" "$MODULE" &&
  ok "publier : CI refusée après un lien symbolique ou un sous-module nommés comme une capture" ||
  ko "publier : CI acceptée après un lien symbolique ou un sous-module dans les captures (ou essai pas préparé)"
apres "$H_COMPILE" "$ORDINAIRE" "$ORDINAIRE" &&
  ok "publier : CI acceptée après une capture rendue exécutable et l'image de partage effacée" ||
  ko "publier : CI refusée après un changement de mode ou un effacement dans la liste"
git -C "$H" checkout -q -b cote "$H_COMPILE"
printf 'png' >"$H/assets/captures/cote.png"
COTE=$(commit_h "à côté")
git -C "$H" checkout -q -b fusion "$H_PAGE"
git -C "$H" -c user.name=essai -c user.email=essai@exemple.invalid merge -q --no-edit "$COTE"
FUSION=$(git -C "$H" rev-parse HEAD)
git -C "$H" checkout -q "$H_PAGE"
[[ $(git -C "$H" rev-list --merges -n 1 "$FUSION") == "$FUSION" ]] &&
  ! apres "$H_COMPILE" "$FUSION" "$FUSION" && ok "publier : CI refusée sur une fusion, même de captures seulement" ||
  ko "publier : CI acceptée sur une fusion (ou fusion pas faite)"
apres "$H_COMPILE" "$COTE" "$H_PAGE" && ko "publier : CI acceptée sur un commit hors de la ligne de master" ||
  ok "publier : CI refusée sur un commit qui n'est pas dans la ligne de la tête de master"
apres "$H_COMPILE" "$H_PAGE" "$H_CAPTURES" && ko "publier : CI acceptée sur un commit d'après la tête de master" ||
  ok "publier : CI refusée sur un commit d'après la tête de master"
! apres "$H_PAGE" "$H_COMPILE" && ! apres "$H_COMPILE" "$H_COMPILE" && ! apres "$H_COMPILE" "${H_PAGE:0:12}" &&
  ! apres "$H_COMPILE" HEAD && ! apres "$H_COMPILE" "$(printf 'f%.0s' {1..40})" &&
  ok "publier : CI refusée sur un commit d'avant, le même, un nom abrégé ou symbolique, un commit inconnu" ||
  ko "publier : CI d'un commit d'avant, abrégé, symbolique ou inconnu acceptée comme descendant"
# Ce que la liste dit hors de la compilation ne l'est pas : rien de src/, build.rs ni Cargo.toml ne cite ces
# chemins, et build.rs ne parcourt aucun dossier (il ne lit que des fichiers nommés).
cites=$(grep -rnE 'assets/captures|captures/|partage\.png|index\.html|\.\./docs|"/?docs/|/docs"' \
  "$DEPOT/src" "$DEPOT/build.rs" "$DEPOT/Cargo.toml" || true)
parcours=$(grep -nE 'read_dir|glob(::|\()|WalkDir|walkdir' "$DEPOT/build.rs" || true)
[[ -z $cites && -z $parcours ]] &&
  ok "liste hors compilation : ni src/, ni build.rs, ni Cargo.toml ne lisent les captures ou la page des fonctions" ||
  ko "liste hors compilation : un fichier de la liste est lu par la compilation : ${cites#"$DEPOT"/}${parcours}"
# La liste est aussi « hors code » pour outils/date-du-code.sh : la date gravée par la CI sur ce commit d'après est
# celle du commit compilé.
while read -r p; do
  [[ $p =~ $(grep -v '^#' "$DEPOT/.github/hors-code.txt" | head -n 1) ]] || { ko "liste hors compilation : $p pas dans hors-code.txt"; break; }
done <<<$'assets/captures/a.png\nassets/captures/VERSION\nassets/partage.png\ndocs/index.html' &&
  ok "liste hors compilation : comprise dans .github/hors-code.txt (même date gravée)"
if command -v jq >/dev/null; then
  F=$T/faux-gh-apres
  mkdir -p "$F" "$T/dossier-apres"
  cp "$T/faux-gh-ci/gh" "$F/gh"
  printf 'ELF linux' >"$T/dossier-apres/vanguard-linux-x86_64"
  printf 'MZ windows' >"$T/dossier-apres/vanguard-windows-x86_64.exe"
  A_LINUX=$(sha256sum "$T/dossier-apres/vanguard-linux-x86_64" | cut -d' ' -f1)
  A_WINDOWS=$(sha256sum "$T/dossier-apres/vanguard-windows-x86_64.exe" | cut -d' ' -f1)
  printf '%s\n' "reproductible	Deux compilations	2026-11-07T08:00:00Z EMPREINTE-VANGUARD-LINUX $A_LINUX" \
    "reproductible	Deux compilations	2026-11-07T08:00:00Z EMPREINTE-VANGUARD-WINDOWS $A_WINDOWS" >"$F/journal-7.txt"
  echo '{"jobs": [{"databaseId": 70, "name": "reproductible", "conclusion": "success"}]}' >"$F/travaux-7.json"
  { cat "$T/descendant.sh"; cat "$T/empreintes_de_la_ci.sh"; } >"$T/empreintes-apres.sh"
  empreintes_apres() { # commit de la CI, tête de master : la sortie de empreintes_de_la_ci, puis « code N »
    local code=0 sortie
    echo "[{\"databaseId\": 7, \"headSha\": \"$1\", \"headBranch\": \"master\", \"event\": \"push\"}]" >"$F/runs.json"
    sortie=$(cd "$H" && PATH="$F:$PATH" COMPILE=$H_COMPILE COMMIT=$2 HORS_CODE=$(grep -v '^#' "$DEPOT/.github/hors-code.txt" | head -n 1) \
      DOSSIER=$T/dossier-apres bash -c "source '$T/empreintes-apres.sh'; empreintes_de_la_ci" 2>&1) || code=$?
    printf '%s\ncode %s\n' "$sortie" "$code"
  }
  r=$(empreintes_apres "$H_PAGE" "$H_PAGE")
  [[ $r == "exécution 7, ${H_PAGE:0:12}, après ${H_COMPILE:0:12} sans rien de compilé changé"$'\n'"code 0" ]] &&
    ok "publier : empreintes de la CI faite sur la page des fonctions acceptées, et dites « après » la version" ||
    ko "publier : CI faite sur la page des fonctions ($r)"
  c=$(git -C "$H" rev-parse md)
  r=$(empreintes_apres "$c" "$c")
  [[ $r == *"code 2" ]] && ok "publier : CI faite après un commit hors de la liste : aucune ne compte (refus comme avant)" ||
    ko "publier : CI faite après un commit hors de la liste acceptée ($r)"
  r=$(empreintes_apres "$FUSION" "$FUSION")
  [[ $r == *"code 2" ]] && ok "publier : CI faite sur une fusion : aucune ne compte" ||
    ko "publier : CI faite sur une fusion acceptée ($r)"
else
  echo "  (sauté : jq absent, pas de faux gh pour la CI faite après la version)"
fi
# Ce que les notes en disent, et d'où elles le prennent.
r=$(CI_APRES=0123456789ab bash -c "$(awk '/^ci_apres_notes\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh"); ci_apres_notes")
[[ $(grep -c 'commit 0123456789ab' <<<"$r") == 2 && $r == *"captures d'écran, l'image de partage ou la page"* &&
  $r == *"screenshots, the social preview image or the features page"* &&
  -z $(CI_APRES= bash -c "$(awk '/^ci_apres_notes\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh"); ci_apres_notes") ]] &&
  awk '/^notes\(\) \{/ { n = 1 } n && /^  ci_apres_notes$/ { c = 1 } n && /^\}/ { n = 0 }
    /CI_APRES=\$\(sed -nE .*<<<"\$EMPREINTES_CI"\)$/ { e = 1 } END { exit !(c && e) }' "$DEPOT/outils/publier-version.sh" &&
  ok "notes : une CI faite après la version est dite, avec son commit, en français et en anglais" ||
  ko "notes : la CI faite après la version n'est pas dite ($r)"

# 6d. Les passe-droits de publier-version.sh : dans les notes de la page et dans l'historique signé (relecture du lot
# correctifs-c6), pas seulement au terminal.
retirer_point
banc "$T/passe" "$DEPOT/outils/signer-versions.sh" 0.86.0
programmes "$T/v-passe" 0.86.0+1792600000
cp -r "$T/v-passe" "$T/v-sans"
signer "$T/passe" "$T/v-sans" --premier || ko "passe-droit : signature sans passe-droit ($(tail -n 1 "$T/v-sans.log"))"
ZEROS=$(printf '0%.0s' {1..64})
if signer "$T/passe" "$T/v-passe" --premier --passe-droit sans-empreintes-ci --passe-droit sans-vm; then
  grep -qxF "passe-droit-sans-empreintes-ci $ZEROS 0" "$T/v-passe/historique.txt" &&
    grep -qxF "passe-droit-sans-vm $ZEROS 0" "$T/v-passe/historique.txt" &&
    [[ $(sed -n 1p "$T/v-passe/historique.txt") == "version 0.86.0+1792600000" ]] &&
    ok "passe-droit : gardé dans le bloc de sa version de l'historique signé" ||
    ko "passe-droit absent de l'historique : $(cat "$T/v-passe/historique.txt")"
  signe "$T/v-passe/historique.txt" 'vanguard-historique 1' && ok "passe-droit : l'historique qui le porte est signé" ||
    ko "passe-droit : historique mal signé"
  awk 'NR == 1 && !/^version / { exit 1 } /^version / { next } NF != 3 { exit 1 }' "$T/v-passe/historique.txt" &&
    ok "passe-droit : l'historique garde la forme que lit github.rs (les copies installées le lisent encore)" ||
    ko "passe-droit : forme de l'historique cassée"
  cmp -s "$T/v-passe/derniere.txt" "$T/v-sans/derniere.txt" && ok "passe-droit : derniere.txt inchangé, à l'octet" ||
    ko "passe-droit : derniere.txt changé"
  # La version suivante reprend le bloc tel quel : le passe-droit reste dit pour toujours.
  banc "$T/passe87" "$DEPOT/outils/signer-versions.sh" 0.87.0
  programmes "$T/v-passe87" 0.87.0+1792700000
  mkdir -p "$T/v-passe87/avant" && cp "$T/v-passe/historique.txt" "$T/v-passe/historique.txt.sig" "$T/v-passe87/avant/"
  if signer "$T/passe87" "$T/v-passe87"; then
    awk '/^version 0.87/ { b = 87 } /^version 0.86/ { b = 86 } /^passe-droit-/ { p[b]++ } END { exit !(p[86] == 2 && !p[87]) }' \
      "$T/v-passe87/historique.txt" && ok "passe-droit : repris avec son bloc par la version suivante, pas au-delà" ||
      ko "passe-droit : perdu ou recopié dans la version suivante : $(cat "$T/v-passe87/historique.txt")"
  else
    ko "passe-droit : version suivante non signée ($(tail -n 1 "$T/v-passe87.log"))"
  fi
else
  ko "passe-droit : refusé par signer-versions.sh ($(tail -n 2 "$T/v-passe.log"))"
fi
rm -rf "$T/v-inconnu" && programmes "$T/v-inconnu" 0.86.0+1792600000
signer "$T/passe" "$T/v-inconnu" --premier --passe-droit rien && ko "passe-droit inconnu accepté" ||
  ok "passe-droit : un nom inconnu est refusé"
# La CI faite après la version (publier-version.sh, CI_APRES) : « ci-apres-COMMIT » dans le bloc de sa version, à la
# forme que lit github.rs (relecture adverse du lot publier-version, T3) ; derniere.txt inchangé ; un commit qui n'a
# pas la forme d'un sha complet est refusé.
CI_SHA=$(printf 'ab%.0s' {1..20})
rm -rf "$T/v-apres" && programmes "$T/v-apres" 0.86.0+1792600000
if signer "$T/passe" "$T/v-apres" --premier --ci-apres "$CI_SHA"; then
  grep -qxF "ci-apres-$CI_SHA $ZEROS 0" "$T/v-apres/historique.txt" &&
    awk 'NR == 1 && !/^version / { exit 1 } /^version / { next } NF != 3 { exit 1 }' "$T/v-apres/historique.txt" &&
    signe "$T/v-apres/historique.txt" 'vanguard-historique 1' &&
    cmp -s "$T/v-apres/derniere.txt" "$T/v-sans/derniere.txt" &&
    ok "CI faite après la version : gardée dans le bloc de l'historique signé, à la forme lue par github.rs" ||
    ko "CI faite après la version absente de l'historique, ou forme cassée : $(cat "$T/v-apres/historique.txt")"
else
  ko "CI faite après la version : refusée par signer-versions.sh ($(tail -n 2 "$T/v-apres.log"))"
fi
refus=0
for mauvais in "${CI_SHA:0:12}" "${CI_SHA^^}" "$CI_SHA 0" "${CI_SHA}0" "-"; do
  rm -rf "$T/v-apres-mal" && programmes "$T/v-apres-mal" 0.86.0+1792600000
  signer "$T/passe" "$T/v-apres-mal" --premier --ci-apres "$mauvais" || [[ -f $T/v-apres-mal/historique.txt.sig ]] ||
    refus=$((refus + 1))
done
((refus == 5)) && ok "CI faite après la version : un commit abrégé, en majuscules ou d'une autre forme est refusé" ||
  ko "CI faite après la version : $((5 - refus)) forme(s) de commit acceptée(s)"
# Les notes de la page : le passe-droit en tête, en français et en anglais ; aucun sans passe-droit.
mkdir -p "$T/faux-gh-notes"
printf '#!/bin/sh\nexit 1\n' >"$T/faux-gh-notes/gh"
chmod +x "$T/faux-gh-notes/gh"
awk '/^passe_droits_notes\(\) \{/,/^\}/; /^versions\(\) \{/,/^\}/; /^notes\(\) \{/,/^\}/' \
  "$DEPOT/outils/publier-version.sh" >"$T/notes.sh"
notes_avec() { # passe-droits
  PATH="$T/faux-gh-notes:$PATH" NOM=Vanguard VERSION=0.0.0 TAG=v0.0.0 TELECHARGER=téléchargement \
    bash -c "source '$T/notes.sh'; PASSE_DROITS=(\"\$@\"); notes" _ "$@" 2>&1
}
r=$(notes_avec sans-empreintes-ci sans-vm)
[[ $(head -n 1 <<<"$r") == "⚠ **Passe-droit**"*VANGUARD_PUBLIER_SANS_EMPREINTES_CI* ]] &&
  grep -q "Override.*VANGUARD_PUBLIER_SANS_EMPREINTES_CI" <<<"$r" &&
  grep -q "Passe-droit.*VANGUARD_PUBLIER_SANS_VM" <<<"$r" && grep -q "Override.*VANGUARD_PUBLIER_SANS_VM" <<<"$r" &&
  ok "passe-droit : dit en tête des notes de la page, en français et en anglais" ||
  ko "passe-droit absent des notes : $(head -c 400 <<<"$r")"
r=$(notes_avec)
[[ $r != *Passe-droit* && $r != *Override* && $r == *téléchargement* ]] && ok "notes sans passe-droit : rien de tel" ||
  ko "notes sans passe-droit : $(head -c 400 <<<"$r")"
# Chaque passe-droit pris l'ajoute ; la signature le reçoit.
awk '/VANGUARD_PUBLIER_SANS_EMPREINTES_CI:-/ { e = 1 } e && /PASSE_DROITS\+=\(sans-empreintes-ci\)/ { a = 1; e = 0 }
  /VANGUARD_PUBLIER_SANS_VM:-/ { v = 1 } v && /PASSE_DROITS\+=\(sans-vm\)/ { b = 1; v = 0 }
  /PASSES\+=\(--passe-droit "\$p"\)/ { p = 1 } /outils\/signer-versions.sh .*"\$\{PASSES\[@\]\}" "\$DOSSIER"/ { s = 1 }
  END { exit !(a && b && p && s) }' "$DEPOT/outils/publier-version.sh" &&
  ok "publier-version.sh note chaque passe-droit pris et le passe à la signature" ||
  ko "publier-version.sh : un passe-droit pris n'est ni noté ni signé"
# Le commit entier de la CI faite après la version : retrouvé dans la ligne de master à partir de ses 12 premiers
# chiffres, revérifié, puis passé à la signature ; introuvable, ou pas dans la ligne : rien de publié.
awk '/CI_APRES_COMPLET=\$\(git rev-list/,/introuvable ou ambigu/' "$DEPOT/outils/publier-version.sh" >"$T/ci-apres-complet.sh"
complet() { # 12 premiers chiffres, tête de master : le commit entier, ou « refus »
  (cd "$H" && CI_APRES=$1 COMPILE=$H_COMPILE COMMIT=$2 bash -c \
    "set -euo pipefail; source '$T/descendant.sh'; source '$T/ci-apres-complet.sh'; echo \"\$CI_APRES_COMPLET\"" \
    2>/dev/null || echo refus)
}
[[ $(wc -l <"$T/ci-apres-complet.sh") -ge 3 && $(complet "${H_PAGE:0:12}" "$H_PAGE") == "$H_PAGE" &&
  $(complet "${H_CAPTURES:0:12}" "$H_PAGE") == "$H_CAPTURES" && $(complet "${COTE:0:12}" "$H_PAGE") == *refus &&
  $(complet "${H_COMPILE:0:12}" "$H_PAGE") == *refus && $(complet "${LIEN:0:12}" "$LIEN") == *refus ]] &&
  awk '/PASSES\+=\(--ci-apres "\$CI_APRES_COMPLET"\)/ { p = 1 }
    p && /outils\/signer-versions.sh .*"\$\{PASSES\[@\]\}" "\$DOSSIER"/ { s = 1 } END { exit !s }' \
    "$DEPOT/outils/publier-version.sh" &&
  ok "publier-version.sh passe le commit entier de la CI faite après la version à la signature, revérifié" ||
  ko "publier-version.sh : commit de la CI faite après la version mal retrouvé, ou pas signé"

# 6e. Une exécution de GitHub qui ne finit jamais (runner en attente) ne tient pas publier-version.sh ouvert pour
# toujours : attendre_execution abandonne au délai, le dit, et rend 124 ; chaque attente du script passe par elle.
F=$T/faux-gh-attente
mkdir -p "$F"
printf '#!/usr/bin/env bash\n[[ "$1 $2" == "run watch" ]] || exit 9\n[[ -f "$(dirname "$0")/fini" ]] && exit 0\nexec sleep 600\n' \
  >"$F/gh"
chmod +x "$F/gh"
awk '/^attendre_execution\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh" >"$T/attendre_execution.sh"
attente() { # secondes ; la sortie, puis le code
  PATH="$F:$PATH" bash -c "source '$T/attendre_execution.sh'; attendre_execution 42 $1; echo \"code \$?\""
}
debut_attente=$SECONDS
sortie=$(attente 1 2>&1)
[[ $sortie == *"code 124"* && $sortie == *"Exécution 42 de GitHub pas finie"* && $((SECONDS - debut_attente)) -lt 30 ]] &&
  ok "publier-version.sh : une exécution de GitHub qui ne finit jamais est abandonnée au délai, et dite" ||
  ko "publier-version.sh attend sans fin une exécution de GitHub bloquée (${sortie:-rien})"
touch "$F/fini"
[[ $(attente 5 2>&1) == "code 0" ]] && ok "publier-version.sh : une exécution finie à temps rend le code de gh" ||
  ko "publier-version.sh : une exécution finie à temps ne rend pas 0"
# Un gh qui ignore TERM (le seul signal que timeout envoie sans -k) : l'attente doit finir quand même, par KILL.
G=$T/faux-gh-sourd
mkdir -p "$G"
printf '#!/usr/bin/env bash\ntrap "" TERM\nexec sleep 60\n' >"$G/gh"
chmod +x "$G/gh"
attente_sourde() { # script de la fonction, fonction ; la sortie, puis le code
  PATH="$G:$PATH" bash -c "source '$1'; $2 42 1; echo \"code \$?\""
}
debut_attente=$SECONDS
sortie=$(attente_sourde "$T/attendre_execution.sh" attendre_execution 2>&1)
[[ $sortie == *"code 124"* && $sortie == *"pas finie"* && $((SECONDS - debut_attente)) -lt 30 ]] &&
  ok "publier-version.sh : un gh qui ignore TERM est tué au délai" ||
  ko "publier-version.sh attend un gh qui ignore TERM (${sortie:-rien}, $((SECONDS - debut_attente)) s)"
# Aucun « gh run watch » hors d'elle, et ses deux appels avec un délai en secondes.
awk '/^attendre_execution\(\) \{/,/^\}/ { next } /^ *#/ { next } /gh run watch/ { exit 1 } /attendre_execution "\$EN_COURS" [0-9]+/ { c = 1 }
  /attendre_execution "\$RUN" [0-9]+/ { m = 1 } END { exit !(c && m) }' "$DEPOT/outils/publier-version.sh" &&
  ok "publier-version.sh : chaque attente de GitHub (CI) a un délai" ||
  ko "publier-version.sh : un « gh run watch » sans délai"

# 6f. Les protections des programmes qui partent, lues par la copie Linux qui part : verifier_binaires, face à un faux
# programme Linux qui note ce qu'on lui demande, lui passe le système attendu et chaque fichier, et rend son refus.
# Chaque appel arrête tout sur un refus : dans publier-version.sh, Linux et Windows après la relecture de leurs
# empreintes et avant d'attendre GitHub ; dans deployer.sh, le programme Linux et vanguard.exe, avant toute copie. Chacun avec son système (--attendu) : un fichier échangé ou d'une autre
# architecture est refusé. Le nom d'avant (verifier-pe, alias) n'est plus appelé, ni verifier-binaire sans --attendu.
D=$T/faux-verificateur
mkdir -p "$D"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >>"$(dirname "$0")/appels"\n[[ ! -f "$(dirname "$0")/refus" ]]\n' \
  >"$D/vanguard-linux-x86_64"
chmod +x "$D/vanguard-linux-x86_64"
awk '/^verifier_binaires\(\) \{/,/^\}/' "$DEPOT/outils/publier-version.sh" >"$T/verifier_binaires.sh"
verifier_avec() { DOSSIER=$D bash -c "source '$T/verifier_binaires.sh'; verifier_binaires \"\$@\"" _ "$@"; }
if verifier_avec windows "$D/a" "$D/b c.exe" &&
  [[ $(cat "$D/appels") == "deploiement verifier-binaire --attendu windows $D/a $D/b c.exe" ]] &&
  touch "$D/refus" && ! verifier_avec linux "$D/a"; then
  ok "publier-version.sh : verifier_binaires passe le système et chaque fichier à « deploiement verifier-binaire » et rend son refus"
else
  ko "publier-version.sh : verifier_binaires ne passe pas les fichiers tels quels, ou cache un refus ($(cat "$D/appels" 2>/dev/null))"
fi
awk '/Copie des programmes différente de leur compilation/ { e = NR }
  /^\{ verifier_binaires linux "\$DOSSIER\/vanguard-linux-x86_64" &&$/ { v = NR }
  v && NR == v + 1 && /^  verifier_binaires windows "\$DOSSIER\/vanguard-windows-x86_64\.exe"; \} \|\|$/ { w = 1 }
  v && NR == v + 2 && /rien de publié."; exit 1; }$/ { lw = 1 }
  /attendre_execution "\$/ && !a { a = NR }
  END { exit !(e && w && lw && e < v && v < a) }' "$DEPOT/outils/publier-version.sh" &&
  ok "publier-version.sh : Linux et Windows vérifiés là où il faut, chaque refus arrête la publication" ||
  ko "publier-version.sh : un programme publié sans « verifier-binaire », ou vérifié trop tôt, ou refus ignoré"
awk '/^\.\/"\$LINUX" deploiement verifier-binaire --attendu linux "\$LINUX" \|\| \{$/ { l = NR }
  l && !x && NR > l && /^  exit 1$/ { x = NR }
  /^if \[\[ -f \$WINDOWS \]\]; then$/ && !i { i = NR }
  i && NR == i + 1 && /^  \.\/"\$LINUX" deploiement verifier-binaire --attendu windows "\$WINDOWS" \|\| \{$/ { w = NR }
  w && !y && NR > w && /^    exit 1$/ { y = NR } /^copier |^install / && !c { c = NR }
  END { exit !(l && x && x < i && w && y && y < c) }' "$DEPOT/outils/deployer.sh" &&
  ok "deployer.sh : le programme Linux et vanguard.exe vérifiés (verifier-binaire) avant toute copie, sans repli" ||
  ko "deployer.sh : un programme part sans « verifier-binaire », ou après sa copie, ou malgré un refus"
! grep -nE 'deploiement verifier[-]pe' "$DEPOT/outils/"*.sh "$DEPOT/.github/workflows/"*.yml >/dev/null &&
  ok "plus aucun appel à l'ancien nom (verifier-pe)" || ko "un appel à verifier-pe reste : les protections n'y sont lues que par l'alias"
# Un appel sans --attendu ne refuserait pas un .exe qui serait un ELF. Hors commentaires, messages (« ») et essais.
sans_attendu=$(grep -nE 'deploiement verifier[-]binaire( |"|$)' "$DEPOT/outils/"*.sh "$DEPOT/.github/workflows/"*.yml |
  grep -v 'deploiement verifier-binaire --attendu ' | grep -vE '^[^:]+:[0-9]+: *#' | grep -v '«' | grep -v '/outils/essais-')
[[ -z $sans_attendu ]] && ok "chaque appel à verifier-binaire dit le système attendu (--attendu)" ||
  ko "verifier-binaire appelé sans --attendu : $sans_attendu"
# 6c. Au branchement de la clé, un commit de GitHub n'est récupéré et compilé qu'avec une CI verte sur ce commit
# exact (deployer.sh, ci_verte, campagne d'attaque n° 6, F4). Un faux gh filtre les exécutions par --commit comme
# GitHub. Sans jq, sauté et dit.
if command -v jq >/dev/null; then
  F=$T/faux-gh-verte
  mkdir -p "$F"
  cat >"$F/gh" <<'GH'
#!/usr/bin/env bash
q=. commit=
while [[ $# -gt 0 ]]; do
  case $1 in
    -q) q=$2; shift ;;
    --commit) commit=$2; shift ;;
  esac
  shift
done
[[ -f $(dirname "$0")/injoignable ]] && exit 1
# Comme le vrai gh sans compte connecté (sans rien demander à GitHub).
[[ -f $(dirname "$0")/non-connecte ]] && { echo "To get started with GitHub CLI, please run:  gh auth login" >&2; exit 4; }
jq -r --arg c "$commit" "[.[] | select(.headSha == \$c)] | $q" "$(dirname "$0")/runs.json"
GH
  chmod +x "$F/gh"
  awk '/^ci_verte\(\) \{/,/^\}/' "$DEPOT/outils/deployer.sh" >"$T/ci_verte.sh"
  A=$(printf 'a%.0s' {1..40}) B=$(printf 'b%.0s' {1..40})
  verte() { (cd "$T" && PATH="$F:$PATH" bash -c "source '$T/ci_verte.sh'; ci_verte '$1'") >/dev/null 2>&1; }
  passage() { # sha, branche, évènement, état, conclusion
    printf '{"headSha": "%s", "headBranch": "%s", "event": "%s", "status": "%s", "conclusion": "%s"}' "$@"
  }
  echo "[$(passage "$A" master push completed success)]" >"$F/runs.json"
  verte "$A" && ok "branchement : un commit à la CI verte sur master est récupéré" ||
    ko "branchement : un commit à la CI verte refusé"
  verte "$B" && ko "branchement : un commit sans passage de la CI est récupéré" ||
    ok "branchement : un commit sans passage de la CI n'est ni récupéré ni compilé"
  echo "[$(passage "$A" master push completed failure)]" >"$F/runs.json"
  verte "$A" && ko "branchement : un commit à la CI en échec est récupéré" ||
    ok "branchement : un commit à la CI en échec n'est pas récupéré"
  echo "[$(passage "$A" master push in_progress "")]" >"$F/runs.json"
  verte "$A" && ko "branchement : un commit à la CI en cours est récupéré" ||
    ok "branchement : un commit à la CI pas finie attend le branchement suivant"
  echo "[$(passage "$A" piege push completed success), $(passage "$A" master pull_request completed success)]" \
    >"$F/runs.json"
  verte "$A" && ko "branchement : une CI verte d'une autre branche ou d'une demande de fusion suffit" ||
    ok "branchement : seule une CI verte de master compte (pas une autre branche, pas une demande de fusion)"
  echo "[$(passage "$A" master push completed success)]" >"$F/runs.json"
  verte "${A:0:12}" && ko "branchement : un commit abrégé est accepté" ||
    ok "branchement : seul un commit entier (40 caractères) est cherché"
  touch "$F/injoignable"
  verte "$A" && ko "branchement : gh sans réponse vaut CI verte" ||
    ok "branchement : gh sans réponse (hors ligne) ne vaut pas CI verte"
  # Hors ligne n'est pas « pas connecté » : l'un passe au branchement suivant, l'autre jamais sans qu'on le règle.
  code_verte() { (cd "$T" && PATH="$1" "$BASH" -c "source '$T/ci_verte.sh'; ci_verte '$2'") >/dev/null 2>&1; echo $?; }
  [[ $(code_verte "$F:$PATH" "$A") == 1 ]] && ok "branchement : gh sans réponse se dit « pas verte », à réessayer" ||
    ko "branchement : gh sans réponse se dit autrement que « pas verte » ($(code_verte "$F:$PATH" "$A"))"
  rm -f "$F/injoignable"
  touch "$F/non-connecte"
  [[ $(code_verte "$F:$PATH" "$A") == 2 ]] && ok "branchement : gh sans compte connecté se dit à part (code 2)" ||
    ko "branchement : gh sans compte connecté se confond avec une CI en cours ($(code_verte "$F:$PATH" "$A"))"
  rm -f "$F/non-connecte"
  # gh absent du PATH du service : un PATH qui n'a que timeout.
  mkdir -p "$T/sans-gh" && ln -sf "$(command -v timeout)" "$T/sans-gh/timeout"
  [[ $(code_verte "$T/sans-gh" "$A") == 3 ]] && ok "branchement : gh introuvable se dit à part (code 3)" ||
    ko "branchement : gh introuvable se confond avec une CI en cours ($(code_verte "$T/sans-gh" "$A"))"
  awk '/elif git merge-base --is-ancestor HEAD "\$DISTANT"; then/ { e = 1; next }
    e && /ci_verte "\$DISTANT" \|\| VERTE=\$\?/ { c = 1; next } e && c && /if \(\(VERTE == 0\)\); then/ { v = 1; e = 0; next }
    e && /git merge/ { exit 1 }
    v && !m && /git merge -q --ff-only "\$DISTANT"/ { m = 1; next }
    m && /elif \(\(VERTE == 2 \|\| VERTE == 3\)\); then/ { d = 1 } d && /avertir_cle/ { a = 1 }
    END { exit !(v && m && a) }' "$DEPOT/outils/deployer.sh" &&
    ok "deployer.sh --branchement ne fusionne le commit de GitHub qu'après ci_verte, et dit gh pas connecté à part" ||
    ko "deployer.sh --branchement fusionne sans CI verte, ou tait que gh n'est pas connecté"
else
  echo "  (sauté : jq absent, pas de faux gh pour le branchement de la clé)"
fi
# Les travaux de ci.yml dont la page publie le fruit : « nomenclatures » ne reprend aucun cache (un compte GitHub pris
# pourrait en préparer un piégé), « attester », qui tient le jeton OIDC, ne lance rien du dépôt (ni extraction, ni
# run:) et ne vient qu'après lui ; tous deux sur la ref complète de master (une étiquette nommée master n'en a pas).
awk '/^  [a-z-]+:$/ { t = $1; next } /^ *#/ { next }
  t == "nomenclatures:" && /if: github.ref == .refs\/heads\/master./ { ni = 1 }
  t == "nomenclatures:" && /rust-cache|actions\/cache/ { cache = 1 }
  t == "attester:" && /needs: nomenclatures$/ { an = 1 }
  t == "attester:" && /if: github.ref == .refs\/heads\/master.$/ { ai = 1 }
  t == "attester:" && /id-token: write$/ { jeton = 1 }
  t == "attester:" && /actions\/checkout|^ *(- )?run:|rust-cache|actions\/cache/ { lance = 1 }
  t == "attester:" && /subject-path: sbom\/\*\.cdx\.json$/ { sujet = 1 }
  END { exit !(ni && !cache && an && ai && jeton && !lance && sujet) }' "$DEPOT/.github/workflows/ci.yml" &&
  ok "ci.yml : nomenclatures sans cache, attestation à part qui ne lance rien du dépôt, master seulement" ||
  ko "ci.yml : nomenclatures avec un cache, ou attestation qui lance du code du dépôt, ou hors de master"
! grep -q 'id-token' <(awk '/^  [a-z-]+:$/ { t = $1 } /^ *#/ { next } t != "attester:"' \
  "$DEPOT/.github/workflows/ci.yml") &&
  ok "ci.yml : le jeton OIDC (id-token) n'est donné qu'au travail « attester »" ||
  ko "ci.yml : un autre travail que « attester » reçoit le jeton OIDC"
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

# 6i. La signature minisign de zig (outils/chaine-zig.sh --verifier-signature), vérifiée par openssl : une clé d'essai
# Ed25519, des signatures écrites ici à la forme de minisign (« ED » : BLAKE2b-512 du fichier, puis la signature du
# commentaire de confiance). Juste, elle passe ; tout le reste est refusé.
Z=$T/minisign
mkdir -p "$Z"
openssl genpkey -algorithm ed25519 -out "$Z/cle" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$Z/autre" 2>/dev/null
printf '\x11\x22\x33\x44\x55\x66\x77\x88' >"$Z/numero"
cle_publique() { # clé privée, numéro de clé, fichier .pub écrit
  { echo "untrusted comment: clé d'essai"
    { printf 'Ed'; cat "$2"; openssl pkey -in "$1" -pubout -outform DER | tail -c 32; } | base64 -w0; echo; } >"$3"
}
signer_minisign() { # fichier, clé privée, numéro de clé, commentaire de confiance, signature écrite [, forme]
  local f=$1 k=$2 n=$3 c=$4 s=$5 forme=${6:-ED}
  if [[ $forme == ED ]]; then openssl dgst -blake2b512 -binary "$f" >"$Z/a-signer"; else cp "$f" "$Z/a-signer"; fi
  openssl pkeyutl -sign -inkey "$k" -rawin -in "$Z/a-signer" -out "$Z/sig64"
  { printf '%s' "$forme"; cat "$n" "$Z/sig64"; } >"$Z/sig"
  { cat "$Z/sig64"; printf '%s' "$c"; } >"$Z/message"
  openssl pkeyutl -sign -inkey "$k" -rawin -in "$Z/message" -out "$Z/globale"
  { echo "untrusted comment: signature d'essai"; base64 -w0 "$Z/sig"; echo
    echo "trusted comment: $c"; base64 -w0 "$Z/globale"; echo; } >"$s"
}
verifier_zig() { bash "$DEPOT/outils/chaine-zig.sh" --verifier-signature "$1" "$2" "$3" "$4" 2>/dev/null; }
cle_publique "$Z/cle" "$Z/numero" "$Z/cle.pub"
head -c 4096 /dev/urandom >"$Z/zig-x86_64-linux-9.9.9.tar.xz"
F=$Z/zig-x86_64-linux-9.9.9.tar.xz
BON=$(printf 'timestamp:1790965431\tfile:zig-x86_64-linux-9.9.9.tar.xz\thashed')
signer_minisign "$F" "$Z/cle" "$Z/numero" "$BON" "$Z/bonne.minisig"
verifier_zig "$F" "$Z/bonne.minisig" zig-x86_64-linux-9.9.9.tar.xz "$Z/cle.pub" &&
  ok "zig : une signature minisign juste passe" || ko "zig : une signature minisign juste est refusée"
cp "$F" "$Z/change.tar.xz" && printf 'x' | dd of="$Z/change.tar.xz" bs=1 seek=100 conv=notrunc 2>/dev/null
verifier_zig "$Z/change.tar.xz" "$Z/bonne.minisig" zig-x86_64-linux-9.9.9.tar.xz "$Z/cle.pub" &&
  ko "zig : un octet changé dans l'archive passe" || ok "zig : un octet changé dans l'archive est refusé"
verifier_zig "$F" "$Z/bonne.minisig" zig-x86_64-linux-9.9.8.tar.xz "$Z/cle.pub" &&
  ko "zig : une archive signée sous un autre nom passe (retour en arrière)" ||
  ok "zig : une archive signée sous un autre nom est refusée (retour en arrière)"
sed '3s/9\.9\.9/9.9.8/' "$Z/bonne.minisig" >"$Z/commentaire.minisig"
verifier_zig "$F" "$Z/commentaire.minisig" zig-x86_64-linux-9.9.8.tar.xz "$Z/cle.pub" &&
  ko "zig : un commentaire de confiance réécrit passe" || ok "zig : un commentaire de confiance réécrit est refusé"
DEUX=$(printf 'file:zig-x86_64-linux-9.9.8.tar.xz\tfile:zig-x86_64-linux-9.9.9.tar.xz')
signer_minisign "$F" "$Z/cle" "$Z/numero" "$DEUX" "$Z/deux.minisig"
verifier_zig "$F" "$Z/deux.minisig" zig-x86_64-linux-9.9.9.tar.xz "$Z/cle.pub" &&
  ko "zig : un commentaire à deux noms de fichier passe" || ok "zig : un commentaire à deux noms de fichier est refusé"
signer_minisign "$F" "$Z/autre" "$Z/numero" "$BON" "$Z/autre.minisig"
verifier_zig "$F" "$Z/autre.minisig" zig-x86_64-linux-9.9.9.tar.xz "$Z/cle.pub" &&
  ko "zig : une signature d'une autre clé (même numéro) passe" || ok "zig : une signature d'une autre clé est refusée"
verifier_zig "$F" "$Z/bonne.minisig" zig-x86_64-linux-9.9.9.tar.xz "$DEPOT/outils/zig-minisign.pub" &&
  ko "zig : une signature d'essai passe sous la vraie clé de zig" ||
  ok "zig : la vraie clé de zig refuse une signature d'une autre clé (numéro de clé)"
signer_minisign "$F" "$Z/cle" "$Z/numero" "$BON" "$Z/ancienne.minisig" Ed
verifier_zig "$F" "$Z/ancienne.minisig" zig-x86_64-linux-9.9.9.tar.xz "$Z/cle.pub" &&
  ko "zig : une signature de l'ancienne forme (« Ed », sans BLAKE2b) passe" ||
  ok "zig : une signature de l'ancienne forme (« Ed ») est refusée"
awk 'NR == 2 { c = substr($0, 50, 1); $0 = substr($0, 1, 49) (c == "A" ? "B" : "A") substr($0, 51) } 1' \
  "$Z/bonne.minisig" >"$Z/abimee.minisig"
verifier_zig "$F" "$Z/abimee.minisig" zig-x86_64-linux-9.9.9.tar.xz "$Z/cle.pub" &&
  ko "zig : une signature abîmée passe" || ok "zig : une signature abîmée est refusée"
head -n 3 "$Z/bonne.minisig" >"$Z/courte.minisig"
verifier_zig "$F" "$Z/courte.minisig" zig-x86_64-linux-9.9.9.tar.xz "$Z/cle.pub" &&
  ko "zig : une signature sans sa signature globale passe" || ok "zig : une signature sans sa signature globale est refusée"
# Le script garde l'empreinte, la version et la clé ensemble : SHA-256 de 64 chiffres, clé de zig de 42 octets, et
# l'empreinte vérifiée avant la signature, à chaque téléchargement.
grep -qxE 'ZIG_SHA256=[0-9a-f]{64}' "$DEPOT/outils/chaine-zig.sh" &&
  grep -qxE 'ZIGBUILD_SHA256=[0-9a-f]{64}' "$DEPOT/outils/chaine-zig.sh" &&
  [[ $(sed -n 2p "$DEPOT/outils/zig-minisign.pub" | base64 -d | wc -c) -eq 42 ]] &&
  ok "chaine-zig.sh : empreintes de zig et cargo-zigbuild épinglées, clé de zig dans le dépôt" ||
  ko "chaine-zig.sh : empreinte non épinglée ou clé de zig illisible"

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
  ok "date du code : celle du dernier commit qui touche le programme (GitHub et l'auteur gravent la même)" ||
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
