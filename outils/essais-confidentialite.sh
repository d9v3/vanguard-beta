#!/usr/bin/env bash
# Essais de outils/confidentialite.py sur des dépôts git jetables, avec un courriel inventé (jamais un vrai) et
# --generique (rien des détails de cet ordinateur n'est lu). Chaque cas se juge à la fois avant le commit (--commit,
# le crochet pre-commit), après (--envoi, et --plage, ce que relisent le crochet pre-push et la CI) et sur tout le
# dépôt (--depot, l'historique entier) :
#   1. un nom que git met entre guillemets (« " », « \ », tabulation, retour à la ligne, octet hors UTF-8) : son
#      contenu et son nom sont lus quand même ;
#   2. un lien symbolique remplacé par un fichier (changement de type, T) : son contenu est lu ;
#   3. un fichier binaire et un renommage pur (aucune ligne « +++ » dans le diff) : leur nom est lu ;
#   4. dans l'historique seul (--depot) : l'ancien nom d'un fichier renommé, un nom coupé par un retour à la ligne ;
#   5. ce que git ne montre pas ligne à ligne : un caractère qui coupe la ligne (retour chariot, saut de page,
#      U+2028), un fichier dit binaire (.gitattributes, ancienne version binaire, gros fichier), l'UTF-16 ;
#   6. les réglages du dépôt qui changent ce que git affiche (textconv, encodage, sous-modules, signatures,
#      git replace) : l'outil lit ce que git push envoie ;
#   7. l'objet brut d'un commit ou d'une étiquette (en-tête « encoding » menteur, en-tête en plus, message après un
#      NUL), les noms de branches et d'étiquettes, une étiquette posée sur un arbre ;
#   8. les fichiers tiers (courriels permis, rien d'autre), la plage d'une branche neuve, le message (« # », ciseaux) ;
#   9. les crochets pre-push et pre-merge-commit, pour de vrai, vers un dépôt distant jetable ;
#      un module planté dans outils/ ou sur PYTHONPATH n'en désarme aucun (python3 -I) ;
#  10. témoins : un fichier propre passe, un courriel dans un nom ordinaire est trouvé ;
#  11. les erreurs (usage, git en échec, fichier illisible) : code 2, « rien n'est conclu », jamais pris pour une
#      trouvaille ; une trouvaille (code 1) n'est comptée que si l'outil dit ce qu'il a trouvé ;
#  12. l'étape de la CI (.github/workflows/ci.yml, lue telle quelle) : le garde-fou lancé est celui de la base, pas
#      celui de l'arbre jugé (une demande qui le viderait ne se rend pas verte) ; repli dit si la base n'en a pas.
#  13. les sources de cet ordinateur, dans une maison jetable : les deux listes privées (commune et de Vanguard), la
#      base des appareils, nmcli, l'identité Git ; une source présente mais illisible ou en panne : code 2.
#  14. cliquet : chaque Python lancé par le dépôt (scripts, crochets, CI, programmes Python) l'est isolé, en -I.
#  15. --compilation (outils/compiler-version.sh, avant l'empreinte) : un dossier personnel, un nom de compte dans un
#      chemin (UTF-16 et autre casse compris) ou le dossier de compilation (forme brute, nettoyée, par un lien)
#      refusés ; le nom seul hors d'un chemin, un HOME « / » et un programme propre passent ; sans git ; usage faux ou
#      programme absent : code 2 ; et sa place dans la recette (sur les deux fenêtres avant leur empreinte, sur vanguard
#      avant le repère, après le remplacement des chemins ; les quatre programmes nommés) et son bloc des dossiers.
set -uo pipefail
RACINE=$(cd "$(dirname "$0")/.." && pwd)
OUTIL=$RACINE/outils/confidentialite.py
TRAVAIL=$(mktemp -d "${TMPDIR:-/tmp}/essais-confidentialite.XXXXXX")
trap 'rm -rf "$TRAVAIL"' EXIT
# Ni la configuration de cet ordinateur ni ses crochets : un dépôt nu, au compte inventé.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=alice GIT_AUTHOR_EMAIL=alice@example.com GIT_COMMITTER_NAME=alice
export GIT_COMMITTER_EMAIL=alice@example.com
# Coupé en deux : ce fichier-ci ne doit pas se faire refuser par le crochet qu'il essaie.
COURRIEL=$(printf '%s@%s' zacharie.tremblay fournisseur-invente.ca)
MAISON=$(printf '/%s/%s' home zacharie)
U=Users
N9=123456789
SID_A="S-1-5-21-$N9-$N9-$N9-1001"
ECHECS=0
N=0

depot() {
  D=$TRAVAIL/$1
  git init -q -b master "$D" && cd "$D" || exit 1
  printf 'rien de personnel\n' >propre.txt
  git add propre.txt && git commit -q -m depart
}

# juger <attendu 0|1> <cas> : --commit sur l'index, puis le commit fait, --envoi, --plage et --depot.
juger() {
  local attendu=$1 cas=$2 code
  for mode in --commit envoi plage depot; do
    case $mode in
      --commit) garde --generique --commit >/dev/null 2>&1; code=$? ;;
      envoi)
        git commit -q --no-verify -m "$cas" || { echo "✘ $cas : commit impossible"; ECHECS=$((ECHECS + 1)); return; }
        garde --generique --envoi >/dev/null 2>&1; code=$? ;;
      plage) garde --generique --plage "$(git rev-parse HEAD~1)" HEAD >/dev/null 2>&1; code=$? ;;
      depot) garde --generique --depot >/dev/null 2>&1; code=$? ;;
    esac
    noter "$attendu" "$code" "$cas ($mode)"
  done
}

# Le garde-fou lancé, sa sortie rendue (sur la sortie d'erreur) : une trouvaille (code 1) seulement s'il dit ce qu'il
# a trouvé. Un code 1 sans constat (Python qui plante, SystemExit d'un message) devient 3 : jamais pris pour une
# trouvaille. 2 : rien n'est conclu (usage, git en échec, fichier illisible).
garde() {
  local sortie code
  sortie=$(python3 -I "$OUTIL" "$@" 2>&1)
  code=$?
  [[ -z $sortie ]] || printf '%s\n' "$sortie" >&2
  ((code == 1)) && ! constat <<<"$sortie" && code=3
  return "$code"
}
constat() { grep -q 'Confidentialité : [0-9]* détail(s) personnel(s) dans'; }
# Le code d'un crochet de git (git push, git merge) : 1 seulement si le garde-fou y a dit ce qu'il a trouvé.
refus_dit() { if (($1 == 1)) && ! constat <<<"$SORTIE"; then echo "1 sans constat"; else echo "$1"; fi; }

noter() {
  N=$((N + 1))
  if [[ $2 == "$1" ]]; then
    echo "✔ $3"
  else
    echo "✘ $3 : code $2, attendu $1"
    ECHECS=$((ECHECS + 1))
  fi
}

depot temoin-propre
printf 'toujours rien\n' >autre.txt && git add autre.txt
juger 0 "témoin : fichier propre"

depot temoin-courriel
printf 'contact : %s\n' "$COURRIEL" >contact.txt && git add contact.txt
juger 1 "témoin : courriel dans un fichier ordinaire"

for nom in 'a"b.txt' 'a\b.txt' $'a\tb.txt' $'a\nb.txt' $'a\xffb.txt' 'é "x".txt'; do
  depot "guillemets-$N"
  printf 'contact : %s\n' "$COURRIEL" >"$nom" && git add -- "$nom"
  juger 1 "contenu d'un nom entre guillemets ($(printf '%q' "$nom"))"
done

depot nom-entre-guillemets
printf 'rien\n' >"x\"$COURRIEL.txt" && git add -- "x\"$COURRIEL.txt"
juger 1 "courriel dans un nom entre guillemets"

depot type-change
ln -s propre.txt lien && git add lien && git commit -q -m lien
rm lien && printf 'contact : %s\n' "$COURRIEL" >lien && git add lien
juger 1 "lien symbolique remplacé par un fichier (T)"

depot binaire
printf 'x\0y' >"$COURRIEL.bin" && git add -- "$COURRIEL.bin"
juger 1 "courriel dans le nom d'un fichier binaire"

depot renommage
git mv propre.txt "$COURRIEL.txt"
juger 1 "courriel dans un renommage pur"

depot retour-a-la-ligne
printf 'rien\n' >$'x\n'"$COURRIEL.txt" && git add -- $'x\n'"$COURRIEL.txt"
juger 1 "courriel après un retour à la ligne dans un nom"

# Le courriel n'est plus que dans l'ancien nom : seul --depot (tout l'historique) le voit, même contenu sous un autre nom.
depot ancien-nom
printf 'rien\n' >"$COURRIEL.txt" && git add -- "$COURRIEL.txt" && git commit -q --no-verify -m ajout
git mv "$COURRIEL.txt" neutre.txt && git commit -q --no-verify -m renommage
garde --generique --depot >/dev/null 2>&1
noter 1 $? "courriel dans l'ancien nom d'un fichier renommé (depot)"

# Un binaire : son contenu n'est pas lu, son nom l'est, dans les fichiers suivis comme dans l'historique.
depot binaire-suivi
printf 'x\0y' >"$COURRIEL.bin" && git add -- "$COURRIEL.bin" && git commit -q --no-verify -m binaire
# L'outil sort en 1 (il a trouvé) : sa sortie est gardée d'abord, pour que pipefail ne masque pas la recherche.
SORTIE=$(garde --generique --depot 2>&1)
grep -qF -- "  $COURRIEL.bin (nom du fichier)" <<<"$SORTIE"
noter 0 $? "nom d'un binaire suivi, rapporté par --depot"

# --- Ce que git ne montre pas ligne à ligne ---------------------------------------------------------------------------

# apres <attendu> <cas> : le commit est déjà fait ; --envoi, --plage et --depot.
apres() {
  garde --generique --envoi >/dev/null 2>&1
  noter "$1" $? "$2 (envoi)"
  garde --generique --plage "$(git rev-parse HEAD~1)" HEAD >/dev/null 2>&1
  noter "$1" $? "$2 (plage)"
  garde --generique --depot >/dev/null 2>&1
  noter "$1" $? "$2 (depot)"
}

# Un caractère que Python prend pour une fin de ligne : la suite de la ligne ne commence plus par « + ».
for coupe in '\r' '\f' '\xe2\x80\xa8' '\x1c' '\xc2\x85'; do
  depot "coupe-$N"
  # shellcheck disable=SC2059  # la coupe est un échappement de printf, voulu dans le format
  printf "x${coupe}%s\n" "$COURRIEL" >a.txt && git add a.txt
  juger 1 "courriel après une coupure de ligne ($coupe)"
done

depot attributs-suivis
printf '*.txt -diff\n' >.gitattributes && printf 'contact : %s\n' "$COURRIEL" >a.txt && git add .gitattributes a.txt
juger 1 "fichier dit binaire par .gitattributes (-diff)"

depot attributs-locaux
printf 'a.txt -diff\n' >.git/info/attributes && printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt
juger 1 "fichier dit binaire par .git/info/attributes"

depot attributs-non-suivis
printf 'a.txt binary\n' >.gitattributes && printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt
juger 1 "fichier dit binaire par un .gitattributes non suivi"

depot binaire-puis-texte
printf 'x\0y' >notes.txt && git add notes.txt && git commit -q -m binaire
printf 'contact : %s\n' "$COURRIEL" >notes.txt && git add notes.txt
juger 1 "fichier d'abord binaire, puis texte"

depot gros-fichier
git config core.bigFileThreshold 1
printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt
juger 1 "réglage core.bigFileThreshold=1"

depot textconv
printf '*.txt diff=x\n' >.git/info/attributes && git config diff.x.textconv 'tr @ _ <'
printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt
juger 1 "réglage diff.x.textconv"

for forme in utf-16le utf-16be bom; do
  depot "utf16-$forme"
  if [[ $forme == bom ]]; then
    { printf '\xff\xfe' && printf 'contact : %s\r\n' "$COURRIEL" | iconv -f utf-8 -t utf-16le; } >export.reg
  else
    printf 'contact : %s\r\n' "$COURRIEL" | iconv -f utf-8 -t "$forme" >export.reg
  fi
  git add export.reg
  juger 1 "fichier en UTF-16 ($forme)"
done

depot vrai-binaire
head -c 4096 /dev/urandom >image.bin && printf '\0\0\0' >>image.bin && git add image.bin
juger 0 "témoin : un vrai binaire passe"

depot suffixe
printf 'rien\n' >"${COURRIEL}_notes.txt" && git add -- "${COURRIEL}_notes.txt"
juger 1 "courriel suivi de « _ » dans un nom"
depot suffixe-contenu
printf 'u=%s_1 v=%s-2\n' "$COURRIEL" "$COURRIEL" >b.txt && git add b.txt
juger 1 "courriel suivi de « _ » ou « - » dans un contenu"

depot sous-module
git config diff.ignoreSubmodules all
git update-index --add --cacheinfo "160000,$(git rev-parse HEAD),$COURRIEL"
juger 1 "courriel dans le nom d'un sous-module, réglage diff.ignoreSubmodules=all"

# --- L'objet brut d'un commit ou d'une étiquette ----------------------------------------------------------------------

# commit_brut <en-têtes en plus (printf)> <message (printf)> : pose sur HEAD un commit écrit à la main.
commit_brut() {
  local identite='alice <alice@example.com> 1700000000 +0000' sha
  # shellcheck disable=SC2059  # les deux derniers arguments sont des formats de printf, voulus
  sha=$({ printf 'tree %s\nparent %s\nauthor %s\ncommitter %s\n' "$(git rev-parse 'HEAD^{tree}')" \
    "$(git rev-parse HEAD)" "$identite" "$identite" && printf "$1" && printf '\n' && printf "$2"; } |
    git hash-object --literally -t commit -w --stdin) && git update-ref HEAD "$sha"
}

depot en-tete-en-plus
commit_brut "relecteur $COURRIEL\n" 'sujet\n'
apres 1 "en-tête de commit en plus"

depot message-apres-nul
commit_brut '' "sujet\n\0contact $COURRIEL\n"
apres 1 "message de commit : courriel après un NUL"

depot signature
commit_brut 'gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE0123456789abcdefABCDEF+/=\n -----END PGP SIGNATURE-----\n' 'sujet\n'
apres 0 "témoin : une signature de commit passe"
commit_brut "gpgsig -----BEGIN PGP SIGNATURE-----\n Comment: $COURRIEL\n -----END PGP SIGNATURE-----\n" 'sujet\n'
apres 1 "courriel glissé dans l'en-tête de signature"

depot encodage
printf 'x\n' >b.txt && git add b.txt
GIT_AUTHOR_EMAIL=$COURRIEL git -c i18n.commitEncoding=cp037 commit -q --no-verify -m "contact $COURRIEL"
apres 1 "commit à l'en-tête « encoding » menteur (auteur, message)"

depot encodage-de-sortie
git config i18n.logOutputEncoding cp037
printf 'x\n' >b.txt && git add b.txt && GIT_AUTHOR_EMAIL=$COURRIEL git commit -q --no-verify -m "contact $COURRIEL"
apres 1 "réglage i18n.logOutputEncoding=cp037 (auteur, message)"

depot separateur
git commit -q --allow-empty -m $'sujet\x1e suite\x1f fin'
apres 0 "témoin : un message avec U+001E et U+001F passe"

depot remplacement
printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt && git commit -q --no-verify -m vrai
VRAI=$(git rev-parse HEAD)
printf 'rien\n' >a.txt && git add a.txt && git commit -q --amend -m remplacant
git replace "$VRAI" HEAD && git update-ref HEAD "$VRAI"
apres 1 "git replace : le vrai commit est lu, pas son remplaçant"

depot signatures-affichees
git config log.showSignature true
printf 'rien\n' >"$COURRIEL.txt" && git add -- "$COURRIEL.txt" && git commit -q --no-verify -m ajout
git mv "$COURRIEL.txt" neutre.txt && git commit -q --no-verify -m renommage
garde --generique --depot >/dev/null 2>&1
noter 1 $? "ancien nom d'un fichier, réglage log.showSignature (depot)"

ZEROS=0000000000000000000000000000000000000000
depot etiquette
GIT_COMMITTER_EMAIL=$COURRIEL git tag -a v1 -m version
garde --generique --depot >/dev/null 2>&1
noter 1 $? "étiqueteur d'une étiquette annotée (depot)"
garde --generique --plage "$ZEROS" "$(git rev-parse v1)" refs/tags/v1 >/dev/null 2>&1
noter 1 $? "étiqueteur d'une étiquette annotée (plage)"
git tag -d v1 >/dev/null && git tag -a v2 -m "pour $COURRIEL"
garde --generique --depot >/dev/null 2>&1
noter 1 $? "message d'une étiquette annotée (depot)"
garde --generique --plage "$ZEROS" "$(git rev-parse v2)" refs/tags/v2 >/dev/null 2>&1
noter 1 $? "message d'une étiquette annotée (plage)"
git tag -d v2 >/dev/null && git tag -a v3 -m version
garde --generique --plage "$ZEROS" "$(git rev-parse v3)" refs/tags/v3 >/dev/null 2>&1
noter 0 $? "témoin : une étiquette annotée propre passe (plage)"

depot noms-de-refs
git branch "travail/$COURRIEL"
garde --generique --depot >/dev/null 2>&1
noter 1 $? "courriel dans un nom de branche (depot)"
garde --generique --plage "$(git rev-parse HEAD)" HEAD "refs/heads/travail/$COURRIEL" >/dev/null 2>&1
noter 1 $? "courriel dans un nom de branche (plage)"
git checkout -q "travail/$COURRIEL"
garde --generique --envoi >/dev/null 2>&1
noter 1 $? "courriel dans le nom de la branche en cours (envoi)"
git checkout -q master && git branch -q -D "travail/$COURRIEL" && git tag "pour-$COURRIEL"
garde --generique --depot >/dev/null 2>&1
noter 1 $? "courriel dans un nom d'étiquette (depot)"

# Une étiquette posée sur un arbre, sans commit : aucun diff ne montre ses fichiers.
depot etiquette-sur-arbre
printf 'rien\n' >"$COURRIEL.txt" && git add -- "$COURRIEL.txt"
ARBRE=$(git write-tree) && git rm -q --cached -- "$COURRIEL.txt" && rm -- "$COURRIEL.txt"
git tag -a arbre -m arbre "$ARBRE"
garde --generique --depot >/dev/null 2>&1
noter 1 $? "nom de fichier dans un arbre étiqueté (depot)"
garde --generique --plage "$ZEROS" "$(git rev-parse arbre)" refs/tags/arbre >/dev/null 2>&1
noter 1 $? "nom de fichier dans un arbre étiqueté (plage)"

# --- Fichiers tiers, plage, message ----------------------------------------------------------------------------------

depot tiers-courriel
mkdir -p fenetre/supply-chain && printf 'who = "Zacharie <%s>"\n' "$COURRIEL" >fenetre/supply-chain/imports.lock
printf 'Auteur : %s\n' "$COURRIEL" >LICENCES-TIERCES.txt && git add fenetre LICENCES-TIERCES.txt
juger 0 "témoin : courriels publics des fichiers tiers, dans un sous-dossier aussi"

depot tiers-compte
printf 'chemin %s/projet\n' "$MAISON" >LICENCES-TIERCES.txt && git add LICENCES-TIERCES.txt
juger 1 "compte d'un dossier personnel dans un fichier tiers"

depot tiers-sid
mkdir supply-chain && printf '%s\n' "$SID_A" >supply-chain/imports.lock
git add supply-chain
juger 1 "SID dans un fichier tiers"

depot verrou
printf 'contact : %s\n' "$COURRIEL" >Cargo.lock && git add Cargo.lock
juger 1 "courriel dans un Cargo.lock (il n'en porte jamais)"

depot faux-tiers
printf 'contact : %s\n' "$COURRIEL" >imports.lock && git add imports.lock
juger 1 "courriel dans un imports.lock hors de supply-chain/"

# Deux branches neuves, la seconde par-dessus la première : chacune est relue en entier, même si GitHub a déjà l'autre.
depot plage-neuve
git update-ref refs/remotes/origin/master HEAD
git checkout -q -b a && printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt && git commit -q --no-verify -m a
git checkout -q -b b && printf 'x\n' >b.txt && git add b.txt && git commit -q --no-verify -m b
git update-ref refs/remotes/origin/a a && git update-ref refs/remotes/origin/b b
garde --generique --plage "$ZEROS" "$(git rev-parse a)" >/dev/null 2>&1
noter 1 $? "branche neuve, déjà portée par une autre branche de GitHub (plage)"
garde --generique --plage "$ZEROS" "$(git rev-parse b)" >/dev/null 2>&1
noter 1 $? "branche neuve par-dessus une branche non relue (plage)"
garde --generique --plage 1111111111111111111111111111111111111111 "$(git rev-parse a)" >/dev/null 2>&1
noter 1 $? "historique réécrit, commit d'avant disparu (plage)"
# Ce que la branche principale de GitHub a déjà n'est pas relu : une branche neuve et propre par-dessus passe.
git update-ref refs/remotes/origin/master a
git checkout -q -b c a && printf 'x\n' >c.txt && git add c.txt && git commit -q -m c
garde --generique --plage "$ZEROS" "$(git rev-parse c)" >/dev/null 2>&1
noter 0 $? "témoin : branche neuve propre par-dessus la branche principale (plage)"

# E-1 (relecture 0.94) : un clone superficiel (actions/checkout sans fetch-depth: 0) coupe l'histoire. Un AVANT
# absent n'y dit pas « historique réécrit » : seule la tête se lirait, et le courriel d'un message plus ancien, ou d'un
# fichier ajouté puis retiré dans l'envoi, passerait. Rien n'est conclu (code 2) dès qu'un commit lu a ses parents
# coupés par le clone ; ce qui est au-dessus de la coupe, lui, se lit comme avant.
depot superficiel-source
printf 'contact : %s\n' "$COURRIEL" >retire.txt && git add retire.txt
git commit -q --no-verify -m "contact $COURRIEL"
git rm -q retire.txt && git commit -q --no-verify -m retrait
printf 'x\n' >fin.txt && git add fin.txt && git commit -q --no-verify -m fin
SOURCE=$D
garde --generique --plage 1111111111111111111111111111111111111111 HEAD >/dev/null 2>&1
noter 1 $? "témoin : clone complet, commit d'avant disparu, tout relu (plage)"
git clone -q --depth 1 "file://$SOURCE" "$TRAVAIL/superficiel" && cd "$TRAVAIL/superficiel" || exit 1
garde --generique --plage 1111111111111111111111111111111111111111 HEAD >/dev/null 2>&1
noter 2 $? "clone superficiel, commit d'avant absent (plage)"
garde --generique --plage "$ZEROS" HEAD >/dev/null 2>&1
noter 2 $? "clone superficiel, branche neuve dont l'histoire est coupée (plage)"
printf 'y\n' >suite.txt && git add suite.txt && git commit -q --no-verify -m suite
garde --generique --plage "$(git rev-parse HEAD~1)" HEAD >/dev/null 2>&1
noter 0 $? "témoin : clone superficiel, un commit au-dessus de la coupe (plage)"
garde --generique --plage "$ZEROS" HEAD >/dev/null 2>&1
noter 0 $? "témoin : clone superficiel, branche neuve au-dessus de la branche principale (plage)"

depot messages
printf 'sujet\n\n# contact %s\n' "$COURRIEL" >"$TRAVAIL/m1"
printf 'sujet\n\n# ------------------------ >8 ------------------------\ncontact %s\n' "$COURRIEL" >"$TRAVAIL/m2"
printf 'sujet\n# ------------------------ >8 ------------------------\n# Ne pas toucher la ligne ci-dessus.\n' >"$TRAVAIL/m3"
printf 'diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-contact %s\n+rien\n' "$COURRIEL" >>"$TRAVAIL/m3"
garde --generique --message "$TRAVAIL/m1" >/dev/null 2>&1
noter 1 $? "message : courriel dans une ligne « # » (gardée par git commit -F)"
garde --generique --message "$TRAVAIL/m2" >/dev/null 2>&1
noter 1 $? "message : courriel après la ligne des ciseaux"
garde --generique --message "$TRAVAIL/m3" >/dev/null 2>&1
noter 0 $? "témoin : le diff de git commit -v, que git retire toujours"

# --- Trouvés par la campagne d'attaque ---------------------------------------------------------------------------------

# Un contenu à octets NUL n'est jamais dit sain sans être lu : ses textes lisibles sont fouillés.
depot nul-dans-un-journal
printf 'contact : %s\n\0' "$COURRIEL" >journal.log && git add journal.log
juger 1 "un octet NUL dans un fichier de texte"

# Le « >> » de PowerShell 5.1 sur un journal commencé en ASCII : la suite est en UTF-16.
for taille in 200 9000; do
  depot "ascii-puis-utf16-$taille"
  { head -c "$taille" /dev/zero | tr '\0' 'x' && printf '\nUtilisateur : %s\r\n' "$COURRIEL" | iconv -f utf-8 -t utf-16le; } >journal.log
  git add journal.log
  juger 1 "journal ASCII ($taille octets) continué en UTF-16"
done

depot utf32
printf 'contact : %s\n' "$COURRIEL" | iconv -f utf-8 -t utf-32le >a.txt && git add a.txt
juger 1 "fichier en UTF-32"

depot utf16-dit-texte
printf '*.reg diff\n' >.gitattributes
{ printf '\xff\xfe' && printf 'contact : %s\r\n' "$COURRIEL" | iconv -f utf-8 -t utf-16le; } >export.reg
git add .gitattributes export.reg
juger 1 "UTF-16 forcé en texte par l'attribut « diff »"

depot chemins-de-recherche
printf 'PATH=/usr/local/bin:%s/.cargo/bin\n' "$MAISON" >env.txt && git add env.txt
juger 1 "dossier personnel après « : » (PATH, scp, rsync)"

depot dossier-a-la-racine
mkdir -p home/zacharie && printf 'rien\n' >home/zacharie/notes.txt && git add home
juger 1 "dossier personnel posé à la racine du dépôt"

# Chaque forme, seule dans un fichier : toutes doivent être trouvées.
N_FORME=0
while IFS= read -r forme; do
  N_FORME=$((N_FORME + 1))
  depot "forme-$N_FORME"
  printf '%s\n' "$forme" >a.txt && git add a.txt
  garde --generique --commit >/dev/null 2>&1
  noter 1 $? "forme $N_FORME : $(printf '%s' "$forme" | cut -c1-16)…"
done <<FORMES
vu par ${COURRIEL}2026-11-10
https://exemple.org/?a=${COURRIEL/@/%40}
<a>${COURRIEL/@/\&#64;}</a>
${COURRIEL%.ca}.local
${COURRIEL/invente/inventé}
"C:\\\\\\\\Users\\\\\\\\zacharie\\\\\\\\Documents"
C:\\${U}\\ZACHAR~1\\AppData
\\Device\\HarddiskVolume3\\${U}\\zacharie\\x
%SystemDrive%\\${U}\\zacharie\\x
C:\\${U}/zacharie/x
S-1-12-1-$N9-$N9-$N9-$N9
s-1-5-21-$N9-$N9-$N9-1001
FORMES

# Fausses alertes trouvées dans le vrai dépôt : permises, chacune au plus étroit (les formes voisines plus haut
# restent refusées : ZACHAR~1, un domaine en .local).
depot permis-etroits
N_PERMIS=0
while IFS= read -r forme; do
  N_PERMIS=$((N_PERMIS + 1))
  printf '%s\n' "$forme" >p$N_PERMIS.txt && git add p$N_PERMIS.txt
  garde --generique --commit >/dev/null 2>&1
  noter 0 $? "permis $N_PERMIS : $(printf '%s' "$forme" | cut -c1-24)…"
  git rm -q --cached p$N_PERMIS.txt
done <<PERMIS
systemctl restart wg-quick@wg0.service
Unit=getty@tty_1.service
C:\\Users\\RUNNER~1\\AppData\\Local\\Temp
C:\\Users\\BOB~12\\x
PERMIS

depot etiquette-imbriquee
git tag -a dedans -m "pour $COURRIEL" && git tag -a dehors -m propre dedans 2>/dev/null && git tag -d dedans >/dev/null
garde --generique --plage "$ZEROS" "$(git rev-parse dehors)" refs/tags/dehors >/dev/null 2>&1
noter 1 $? "étiquette qui étiquette une étiquette (plage)"

depot signature-fausse
commit_brut "gpgsig $MAISON/Documents\\n" 'sujet\n'
apres 1 "dossier personnel à la place d'une signature"
commit_brut 'encoding UTF-16LE\n' "$(printf 'contact %s\n' "$COURRIEL" | iconv -f utf-8 -t utf-16le | sed 's/\x00/\\0/g')"
apres 1 "message de commit en UTF-16"

depot fausse-principale
git update-ref refs/remotes/origin/main/essai HEAD
printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt && git commit -q --no-verify -m a
git update-ref refs/remotes/origin/main/essai HEAD
printf 'x\n' >b.txt && git add b.txt && git commit -q -m b
garde --generique --plage "$ZEROS" "$(git rev-parse HEAD)" >/dev/null 2>&1
noter 1 $? "« origin/main/essai » n'est pas la branche principale (plage)"

depot lien-illisible
ln -s /nulle/part/secret lien && git add lien && git commit -q -m lien
garde --generique --depot >/dev/null 2>&1
noter 0 $? "témoin : un lien symbolique vers un fichier absent ne fait pas planter (depot)"

# --- Les crochets, pour de vrai ---------------------------------------------------------------------------------------

# Les vrais crochets, dans un dépôt jetable et vers un dépôt distant jetable. Le crochet lance
# « <racine>/outils/confidentialite.py » : ici un relais vers l'outil essayé, en --generique (l'identité inventée des
# essais n'est pas celle de cet ordinateur). Le relais fait tourner l'outil dans l'interpréteur que le crochet a lancé,
# comme le vrai : ce que cet interpréteur irait importer du dossier outils/ du dépôt jugé atteint aussi l'outil.
crochets() {
  depot "$1"
  git init -q --bare "$D.git" && git remote add origin "$D.git" && git push -q origin master 2>/dev/null
  mkdir outils && printf 'outils/\n' >>.git/info/exclude
  printf 'import runpy, sys\nsys.argv = [%s, "--generique", *sys.argv[1:]]\nrunpy.run_path(sys.argv[0], run_name="__main__")\n' \
    "$(printf '%s' "$OUTIL" | python3 -I -c 'import sys; print(repr(sys.stdin.read()))')" >outils/confidentialite.py
  git config core.hooksPath "$RACINE/outils/hooks"
}

crochets pousser
git checkout -q -b propre && printf 'x\n' >x.txt && git add x.txt && git commit -q -m propre
git push -q origin propre >/dev/null 2>&1
noter 0 $? "témoin : pre-push laisse partir une branche propre"
git push -q origin :propre >/dev/null 2>&1
noter 0 $? "témoin : pre-push laisse supprimer une branche"
# cherry-pick ne lance ni pre-commit ni commit-msg : seul pre-push peut l'arrêter.
git checkout -q -b source master && printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt
git commit -q --no-verify -m source
git checkout -q -b cueilli master && git cherry-pick source >/dev/null 2>&1
SORTIE=$(git push -q origin cueilli 2>&1)
noter 1 "$(refus_dit $?)" "pre-push refuse un commit venu de cherry-pick"
git --git-dir="$D.git" rev-parse -q --verify refs/heads/cueilli >/dev/null 2>&1
noter 1 $? "rien n'est parti : la branche refusée n'est pas sur le dépôt distant"
SORTIE=$(git push -q origin "master:refs/heads/travail/$COURRIEL" 2>&1)
noter 1 "$(refus_dit $?)" "pre-push refuse un nom de branche avec un courriel"
git checkout -q master && git tag -a v1 -m "pour $COURRIEL"
SORTIE=$(git push -q origin v1 2>&1)
noter 1 "$(refus_dit $?)" "pre-push refuse une étiquette au message personnel"
git push -q origin 'master@{0 seconds ago}:refs/heads/datee' >/dev/null 2>&1
noter 0 $? "témoin : pre-push lit une source qui contient des espaces"

crochets fusionner
git checkout -q -b a && printf 'contact : %s\n' "$COURRIEL" >a.txt && git add a.txt && git commit -q --no-verify -m a
git checkout -q master && SORTIE=$(git merge -q --no-ff -m fusion a 2>&1)
noter 1 "$(refus_dit $?)" "pre-merge-commit refuse une fusion qui amène un courriel"
git merge --abort 2>/dev/null
git checkout -q -b b master && printf 'x\n' >b.txt && git add b.txt && git commit -q -m b
git checkout -q master && git merge -q --no-ff -m fusion b >/dev/null 2>&1
noter 0 $? "témoin : pre-merge-commit laisse passer une fusion propre"

# Un module planté dans outils/ (re.py, que confidentialite.py importe) ou mis sur PYTHONPATH ne désarme aucun
# crochet : lancé en python3 -I, l'interpréteur ne met ni le dossier du script ni PYTHONPATH en tête des imports.
crochets piege
# Chaque cas repart de BASE : un crochet désarmé (avant le correctif) laisse passer un commit qui fausserait la suite.
BASE=$(git rev-parse HEAD)
printf 'import os\nos._exit(0)\n' >outils/re.py
printf 'contact : %s\n' "$COURRIEL" >p.txt && git add p.txt
python3 outils/confidentialite.py --commit >/dev/null 2>&1  # sans -I : voulu (le témoin du piège)
noter 0 $? "témoin : sans -I, le re.py planté désarme le garde-fou (le piège est réel)"
SORTIE=$(git commit -q -m piege 2>&1)
noter 1 "$(refus_dit $?)" "pre-commit : un re.py planté dans outils/ ne désarme pas le garde-fou"
git reset -q --soft "$BASE"
mkdir chemin && mv outils/re.py chemin/re.py && printf 'chemin/\n' >>.git/info/exclude
SORTIE=$(PYTHONPATH="$D/chemin" git commit -q -m piege 2>&1)
noter 1 "$(refus_dit $?)" "pre-commit : un re.py mis sur PYTHONPATH ne désarme pas le garde-fou"
git reset -q --soft "$BASE"
mv chemin/re.py outils/re.py && git rm -q --cached p.txt && rm p.txt
SORTIE=$(git commit -q --allow-empty -m "pour $COURRIEL" 2>&1)
noter 1 "$(refus_dit $?)" "commit-msg : un re.py planté dans outils/ ne désarme pas le garde-fou"
git reset -q --soft "$BASE"
git checkout -q -b piegee && printf 'contact : %s\n' "$COURRIEL" >m.txt && git add m.txt
git commit -q --no-verify -m piegee && git checkout -q master
SORTIE=$(git merge -q --no-ff -m fusion piegee 2>&1)
noter 1 "$(refus_dit $?)" "pre-merge-commit : un re.py planté dans outils/ ne désarme pas le garde-fou"
git merge --abort 2>/dev/null
git reset -q --hard "$BASE"
SORTIE=$(git push -q origin piegee 2>&1)
noter 1 "$(refus_dit $?)" "pre-push : un re.py planté dans outils/ ne désarme pas le garde-fou"

# Rien n'est conclu (code 2) : jamais pris pour une trouvaille (1), ni pour un vert (0).
depot erreurs
garde --generique --plage HEAD >/dev/null 2>&1
noter 2 $? "usage : --plage sans APRÈS"
garde --generique --tout >/dev/null 2>&1
noter 2 $? "usage : option inconnue"
# (Un AVANT inconnu, lui, est un historique réécrit, lu comme tel : voir plus haut.)
garde --generique --plage HEAD nexistepas >/dev/null 2>&1
noter 2 $? "--plage vers un APRÈS inconnu, AVANT connu"
# APRÈS introuvable par le chemin d'un historique réécrit (AVANT fait de zéros, vide ou inconnu) : rien lu, jamais 0.
# Le dépôt contient un courriel inventé : un « 0 commit relu » passerait pour sain.
printf 'contact : %s\n' "$COURRIEL" >contact.txt && git add contact.txt && git commit -q --no-verify -m contact
garde --generique --plage 0000000000000000000000000000000000000000 nexistepas >/dev/null 2>&1
noter 2 $? "--plage vers un APRÈS inconnu, AVANT fait de zéros"
garde --generique --plage '' deadbeefdeadbeefdeadbeefdeadbeefdeadbeef >/dev/null 2>&1
noter 2 $? "--plage vers un APRÈS inconnu, AVANT vide"
garde --generique --plage absent absent2 >/dev/null 2>&1
noter 2 $? "--plage vers un APRÈS inconnu, AVANT inconnu"
garde --generique --plage absent '' >/dev/null 2>&1
noter 2 $? "--plage vers un APRÈS vide"
garde --generique --plage 0000000000000000000000000000000000000000 HEAD >/dev/null 2>&1
noter 1 $? "témoin : --plage AVANT fait de zéros vers HEAD trouve le courriel"
git reset -q --hard HEAD~1
garde --generique --message "$TRAVAIL/absent" >/dev/null 2>&1
noter 2 $? "message de commit illisible"
garde --generique --binaire "$TRAVAIL/absent" >/dev/null 2>&1
noter 2 $? "programme illisible"
printf 'x\n' >ferme.txt && git add ferme.txt && git commit -q --no-verify -m ferme && chmod 000 ferme.txt
if cat ferme.txt >/dev/null 2>&1; then
  echo "  (sauté : fichier fermé lisible quand même ici, administrateur ou espace de noms : --depot illisible pas essayé)"
else
  garde --generique --depot >/dev/null 2>&1
  noter 2 $? "fichier suivi illisible (--depot)"
fi
chmod 644 ferme.txt

# L'étape de la CI, telle que GitHub la lance (bash -eo pipefail, AVANT, APRES et RUNNER_TEMP dans l'environnement).
ETAPE_CI=$TRAVAIL/etape-ci.sh
python3 -I - "$RACINE/.github/workflows/ci.yml" >"$ETAPE_CI" <<'PY'
import sys
lignes = open(sys.argv[1], encoding="utf-8").read().split("\n")
i = next(k for k, l in enumerate(lignes) if l.strip() == "- name: Rien de personnel dans les commits envoyés")
j = next(k for k in range(i, len(lignes)) if lignes[k].strip().startswith("run:"))
if lignes[j].strip() != "run: |":
    print(lignes[j].strip()[len("run:"):].strip())
    sys.exit()
retrait = len(lignes[j]) - len(lignes[j].lstrip()) + 2
for ligne in lignes[j + 1:]:
    if ligne.strip() and len(ligne) - len(ligne.lstrip()) < retrait:
        break
    print(ligne[retrait:])
PY
[[ -s $ETAPE_CI ]] || { echo "✘ étape « Rien de personnel » introuvable dans ci.yml"; ECHECS=$((ECHECS + 1)); }
etape_ci() {
  SORTIE=$(AVANT=$1 APRES=$2 RUNNER_TEMP=$(mktemp -d "$TRAVAIL/runner.XXXX") CI=true \
    bash --noprofile --norc -eo pipefail "$ETAPE_CI" 2>&1)
}
garde_de_la_base() { mkdir -p outils && cp "$OUTIL" outils/ && git add outils && git commit -q --no-verify -m base; }
# Vidé, mais avec les mots des options : le repli ne se déclenche pas sur leur seule absence.
vider_le_garde() { printf 'import sys  # "--generique" "--plage"\nsys.exit(0)\n' >outils/confidentialite.py && git add outils; }

depot ci-garde-vide
garde_de_la_base
vider_le_garde
printf 'contact : %s\n' "$COURRIEL" >contact.txt && git add contact.txt && git commit -q --no-verify -m vide
etape_ci "$(git rev-parse HEAD~1)" HEAD
noter 1 "$(refus_dit $?)" "CI : une demande qui vide le garde-fou est jugée par celui de la base"

depot ci-temoin
garde_de_la_base
vider_le_garde
printf 'rien\n' >x.txt && git add x.txt && git commit -q --no-verify -m propre
etape_ci "$(git rev-parse HEAD~1)" HEAD
code=$?
grep -q '^Garde-fou de la base' <<<"$SORTIE" || code="$code, sans « Garde-fou de la base »"
noter 0 "$code" "témoin CI : une demande propre passe, jugée par le garde-fou de la base"

depot ci-branche-neuve
garde_de_la_base
git update-ref refs/remotes/origin/master HEAD
git checkout -q -b neuve
vider_le_garde
printf 'contact : %s\n' "$COURRIEL" >contact.txt && git add contact.txt && git commit -q --no-verify -m vide
etape_ci 0000000000000000000000000000000000000000 HEAD
noter 1 "$(refus_dit $?)" "CI : branche neuve (AVANT fait de zéros), le garde-fou de master"
git update-ref refs/remotes/origin/master HEAD
etape_ci 0000000000000000000000000000000000000000 HEAD
code=$?
grep -q '^::warning::Garde-fou de confidentialité pris dans l.arbre jugé' <<<"$SORTIE" || code="$code, repli pas dit"
# Le garde-fou de l'arbre jugé, vidé, laisse passer : seul l'avertissement le dit (limite connue, rare : AVANT de
# zéros sur master même).
noter 0 "$code" "CI : base qui est le commit jugé lui-même, repli dit en avertissement"

depot ci-repli
mkdir -p outils && cp "$OUTIL" outils/ && git add outils
printf 'contact : %s\n' "$COURRIEL" >contact.txt && git add contact.txt && git commit -q --no-verify -m repli
etape_ci "$(git rev-parse HEAD~1)" HEAD
code=$(refus_dit $?)
grep -q '^::warning::Garde-fou de confidentialité pris dans l.arbre jugé' <<<"$SORTIE" || code="$code, repli pas dit"
noter 1 "$code" "CI : base sans garde-fou, repli sur celui de l'arbre jugé, dit en avertissement"
cd "$TRAVAIL" || exit 1

# 13. Les sources de cet ordinateur (sans --generique), dans une maison jetable : les deux listes privées (la commune
# et celle de Vanguard) sont lues ; une source présente mais illisible, abîmée ou en panne (liste, base des
# appareils, nmcli, réglages de git) arrête tout (code 2), jamais une liste de termes plus courte sans le dire.
MAISON_J=$TRAVAIL/maison
FAUX=$TRAVAIL/faux-chemin
mkdir -p "$MAISON_J/.config" "$MAISON_J/.local/share/vanguard" "$FAUX"
# Le chemin des programmes : python3, git et grep (garde) seulement, plus un nmcli inventé quand l'essai en pose un.
for programme in python3 git grep; do ln -s "$(command -v "$programme")" "$FAUX/$programme"; done
GLOBAL_J=$TRAVAIL/gitconfig-jetable
: >"$GLOBAL_J"
INVENTE=$(printf '%s %s' Gaspard Invente-Lavoie)
# machine <texte> : --texte lu avec les sources de la maison jetable (compte « alice »).
machine() {
  printf '%s\n' "$1" | HOME=$MAISON_J XDG_CONFIG_HOME=$MAISON_J/.config XDG_DATA_HOME=$MAISON_J/.local/share \
    USER=alice LOGNAME=alice PATH=$FAUX GIT_CONFIG_GLOBAL=$GLOBAL_J garde --texte
}
# nmcli_faux <code> [sortie] : un nmcli qui rend ce code, ou qui écrit cette sortie.
nmcli_faux() {
  printf '#!/bin/sh\nprintf "%%s" %q\nexit %s\n' "${2:-}" "$1" >"$FAUX/nmcli"
  chmod +x "$FAUX/nmcli"
}
depot sources-machine
machine "rien d'ici"
noter 0 $? "témoin : sans nmcli, sans liste ni base, un texte propre passe"
mkdir -p "$MAISON_J/.config/confidentialite"
printf '# un commentaire\n%s\n' "$INVENTE" >"$MAISON_J/.config/confidentialite/confidentiel.txt"
SORTIE=$(machine "signé $INVENTE" 2>&1)
code=$(refus_dit $?)
grep -q 'liste commune' <<<"$SORTIE" || code="$code, origine pas dite"
noter 1 "$code" "la liste commune (~/.config/confidentialite) est lue"
mkdir -p "$MAISON_J/.config/vanguard-dev"
printf '%s\n' "Rue des Inventés" >"$MAISON_J/.config/vanguard-dev/confidentiel.txt"
SORTIE=$(machine "au 12 Rue des Inventés" 2>&1)
noter 1 "$(refus_dit $?)" "la liste de Vanguard (~/.config/vanguard-dev) est toujours lue"
rm "$MAISON_J/.config/confidentialite/confidentiel.txt"
mkdir "$MAISON_J/.config/confidentialite/confidentiel.txt"
machine "rien d'ici" 2>/dev/null
noter 2 $? "liste commune illisible (un dossier) : rien n'est conclu"
rmdir "$MAISON_J/.config/confidentialite/confidentiel.txt"
BASE_J=$MAISON_J/.local/share/vanguard/appareils.json
printf '{"reseaux": {"r1": {"nom": "Chez Gaspard", "appareils": {}}}}\n' >"$BASE_J"
SORTIE=$(machine "réseau Chez Gaspard" 2>&1)
noter 1 "$(refus_dit $?)" "témoin : un réseau de la base des appareils est cherché"
printf '{"reseaux": ' >"$BASE_J"
machine "rien d'ici" 2>/dev/null
noter 2 $? "base des appareils abîmée : rien n'est conclu"
printf '["pas", "une", "base"]\n' >"$BASE_J"
machine "rien d'ici" 2>/dev/null
noter 2 $? "base des appareils d'une autre forme : rien n'est conclu"
rm "$BASE_J" && mkdir "$BASE_J"
machine "rien d'ici" 2>/dev/null
noter 2 $? "base des appareils illisible (un dossier) : rien n'est conclu"
rmdir "$BASE_J"
# Présente mais injoignable (relecture 0.95, V-1) : Path.exists() et is_dir() disent « absente » pour toute erreur ;
# seule l'absence vraie (FileNotFoundError) est « rien à lire ». Lien mort, en boucle, dossier fermé : code 2.
# sans_trace <code> <quoi> : le code attendu, et une phrase, jamais une trace Python.
sans_trace() {
  local code=$?
  grep -q '^Traceback' <<<"$SORTIE" && code="$code, trace Python"
  grep -q '^confidentialité : ' <<<"$SORTIE" || code="$code, pas de phrase"
  noter "$1" "$code" "$2"
}
LISTE_J=$MAISON_J/.config/confidentialite/confidentiel.txt
ln -s "$TRAVAIL/cible-demontee/confidentiel.txt" "$LISTE_J"
SORTIE=$(machine "rien d'ici" 2>&1)
sans_trace 2 "liste commune en lien mort (cible démontée) : rien n'est conclu"
rm "$LISTE_J" && ln -s confidentiel.txt "$LISTE_J"
SORTIE=$(machine "rien d'ici" 2>&1)
sans_trace 2 "liste commune en lien qui boucle : rien n'est conclu"
rm "$LISTE_J" && rmdir "$MAISON_J/.config/confidentialite"
ln -s "$TRAVAIL/cle-retiree" "$MAISON_J/.config/confidentialite"
SORTIE=$(machine "rien d'ici" 2>&1)
sans_trace 2 "dossier de la liste commune en lien mort : rien n'est conclu"
rm "$MAISON_J/.config/confidentialite" && mkdir "$MAISON_J/.config/confidentialite"
printf 'Gaspard\n\xe9t\xe9\n' >"$LISTE_J"
SORTIE=$(machine "rien d'ici" 2>&1)
sans_trace 2 "liste commune pas en UTF-8 : rien n'est conclu, avec une phrase"
rm "$LISTE_J"
ln -s "$TRAVAIL/cible-demontee/appareils.json" "$BASE_J"
SORTIE=$(machine "rien d'ici" 2>&1)
sans_trace 2 "base des appareils en lien mort : rien n'est conclu"
rm "$BASE_J"
printf '{"reseaux": {"r1": {"nom": 42, "appareils": {}}}}\n' >"$BASE_J"
SORTIE=$(machine "rien d'ici" 2>&1)
sans_trace 2 "base des appareils, un nom qui n'est pas du texte : rien n'est conclu, avec une phrase"
rm "$BASE_J"
chmod 000 "$MAISON_J/.config/confidentialite" "$MAISON_J/.local/share/vanguard"
if ls "$MAISON_J/.config/confidentialite" >/dev/null 2>&1; then
  echo "  (sauté : dossier fermé lisible quand même ici, administrateur ou espace de noms : dossiers 000 pas essayés)"
else
  SORTIE=$(machine "rien d'ici" 2>&1)
  sans_trace 2 "dossier de la liste commune fermé (000) : rien n'est conclu"
  chmod 755 "$MAISON_J/.config/confidentialite"
  SORTIE=$(machine "rien d'ici" 2>&1)
  sans_trace 2 "dossier des données de Vanguard fermé (000) : rien n'est conclu"
fi
chmod 755 "$MAISON_J/.config/confidentialite" "$MAISON_J/.local/share/vanguard"
machine "rien d'ici" 2>/dev/null
noter 0 $? "témoin : dossiers rouverts, sans liste ni base, un texte propre passe"
nmcli_faux 0 "$(printf 'Chez Lavoie:802-11-wireless\n')"
SORTIE=$(machine "branché sur Chez Lavoie" 2>&1)
noter 1 "$(refus_dit $?)" "témoin : un réseau enregistré dans NetworkManager est cherché"
nmcli_faux 8
machine "rien d'ici" 2>/dev/null
noter 2 $? "nmcli en échec (NetworkManager arrêté) : rien n'est conclu"
rm "$FAUX/nmcli"
printf '[user]\n\tname = %s\n' "$INVENTE" >"$GLOBAL_J"
SORTIE=$(machine "de $INVENTE" 2>&1)
noter 1 "$(refus_dit $?)" "témoin : le nom de l'identité Git est cherché"
# Des réglages abîmés font échouer tout git (rev-parse d'abord) : seul un git inventé échoue sur l'identité seule.
rm "$FAUX/git"
printf '#!/bin/sh\n[ "$1 $2" = "config --global" ] && exit 3\nexec %q "$@"\n' "$(command -v git)" >"$FAUX/git"
chmod +x "$FAUX/git"
machine "rien d'ici" 2>/dev/null
noter 2 $? "git config --global en échec (code 3) : rien n'est conclu"
rm "$FAUX/git" && ln -s "$(command -v git)" "$FAUX/git"
: >"$GLOBAL_J"
cd "$TRAVAIL" || exit 1

# --- Cliquet : chaque Python lancé par le dépôt l'est isolé (-I) -------------------------------------------------------

# Sans -I, Python met le dossier du script lancé (ou le dossier courant, pour -c et -) en tête des chemins d'import et
# lit PYTHONPATH : un module planté là (re.py…) passe avant le sien. Le cliquet relit les fichiers suivis (scripts,
# crochets, CI, programmes Python) : « python3 » suivi d'une option, d'un chemin, d'un .py ou d'une variable, et les
# listes [sys.executable, …] ou ["python3", …], doivent passer -I. Une exception voulue porte « # sans -I : voulu ».
cliquet_isole() {
  python3 -I - "$1" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

racine = Path(sys.argv[1])
suivis = subprocess.run(["git", "-C", str(racine), "ls-files", "-z"], capture_output=True, check=True).stdout
COMMANDE = re.compile(r"(?:^|(?<=[\s(`|;&]))python3?[ \t]+(\S+)")
LISTE = re.compile(r"""\[\s*(?:sys\.executable|["']python3?["'])\s*,(?!\s*["']-I["'])""")
ENTETE = re.compile(r"#!\{sys\.executable\}(?! -I)")
fautes = []
for nom in filter(None, suivis.decode("utf-8", "surrogateescape").split("\0")):
    if not (nom.endswith((".sh", ".bash", ".yml", ".yaml", ".py")) or nom.startswith("outils/hooks/")):
        continue
    try:
        texte = (racine / nom).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"{nom} : illisible ({e}) : rien n'est conclu", file=sys.stderr)
        sys.exit(2)
    for n, ligne in enumerate(texte.splitlines(), 1):
        if ligne.lstrip().startswith("#") or "# sans -I : voulu" in ligne:
            continue
        lancements = [m.group(1).strip("\"'`,.;:)»") for m in COMMANDE.finditer(ligne)]
        if any(t != "-I" and (t.startswith("-") or "/" in t or ".py" in t or "$" in t) for t in lancements) \
                or LISTE.search(ligne) or ENTETE.search(ligne):
            fautes.append(f"{nom}:{n}: {ligne.strip()}")
for faute in fautes:
    print(f"Python lancé sans -I : {faute}", file=sys.stderr)
sys.exit(1 if fautes else 0)
PY
}
cliquet_isole "$RACINE" 2>&1 | head -20 >&2
noter 0 "${PIPESTATUS[0]}" "cliquet : chaque Python lancé par le dépôt l'est en -I"
depot cliquet
printf '%s %s\n' "timeout 5 python3" "outils/x.py" >a.sh && git add a.sh
cliquet_isole "$D" 2>/dev/null
noter 1 $? "témoin : le cliquet voit un script lancé par python3 sans -I"
printf '%s %s\n' "timeout 5 python3 -I" "outils/x.py" >a.sh && printf 'r = subprocess.run([%s, %s])\n' sys.executable '"x.py"' >b.py
git add a.sh b.py
cliquet_isole "$D" 2>/dev/null
noter 1 $? "témoin : le cliquet voit une liste de lancement sans -I"
printf 'r = subprocess.run([sys.executable, "-I", %s])\n' '"x.py"' >b.py
printf '%s %s  # sans -I : voulu\n' "python3" "outils/y.py" >>a.sh && git add a.sh b.py
cliquet_isole "$D" 2>/dev/null
noter 0 $? "témoin : le cliquet laisse passer -I et une exception dite"
# --compilation : compte, maison et dossier de compilation inventés ; lancé hors de tout dépôt git.
P=$TRAVAIL/compilation && mkdir -p "$P" && cd "$P" || exit 1
CIBLES_I=/srv/cibles-inventees/vg
compile() { # nom, puis le texte des octets (printf)
  local f=$P/$1
  shift
  { printf '\177ELF\0octets-inventes\0'; printf "$@"; printf '\0'; } >"$f"
}
compilation() { SORTIE=$(HOME=/home/alice USER=alice garde --compilation "$@" 2>&1); }
compile propre '/vanguard/target/release/build/glutin_egl_sys-0123/out/egl_bindings.rs\0/cargo/registry/src/x/y.rs'
compilation "$CIBLES_I" "$P/propre"
noter 0 $? "--compilation : un programme aux chemins remplacés passe"
compile maison '/home/alice/.cargo/registry/src/x/y.rs'
compilation "$CIBLES_I" "$P/maison"
noter 1 "$(refus_dit $?)" "--compilation : le dossier personnel (HOME) est refusé"
compile disque '/run/media/alice/disque/cibles/release/build/out/egl_bindings.rs'
compilation "$CIBLES_I" "$P/disque"
noter 1 "$(refus_dit $?)" "--compilation : le nom du compte dans un chemin hors de HOME est refusé"
printf '\177ELF\0' >"$P/large" && printf 'C:\\Users\\alice\\cibles\0' | iconv -t UTF-16LE >>"$P/large"
compilation "$CIBLES_I" "$P/large"
noter 1 "$(refus_dit $?)" "--compilation : le nom du compte dans un chemin Windows en UTF-16 est refusé"
compile cibles '/srv/cibles-inventees/vg/fenetre/x86_64-unknown-linux-gnu/release/build/out/glx_bindings.rs'
compilation "$CIBLES_I" "$P/cibles"
noter 1 "$(refus_dit $?)" "--compilation : le dossier de compilation (CARGO_TARGET_DIR) est refusé"
compilation "$CIBLES_I/" "$P/cibles"
noter 1 "$(refus_dit $?)" "--compilation : le dossier de compilation donné avec « / » final est refusé aussi"
# Trois écritures d'un même dossier : brute (avec « .. », telle que cargo la passe à rustc), logique, physique.
compile brut '/srv/cibles-inventees/x/../vg/fenetre/x86_64-unknown-linux-gnu/release/build/out/glx_bindings.rs'
compilation /srv/cibles-inventees/x/../vg "$P/brut"
noter 1 "$(refus_dit $?)" "--compilation : le dossier de compilation dans sa forme brute (avec « .. ») est refusé"
mkdir -p "$P/rel" && compile relatif "$P/rel/../cibles-rel/release/build/out/glx_bindings.rs"
compilation rel/../cibles-rel "$P/relatif"
noter 1 "$(refus_dit $?)" "--compilation : un dossier relatif avec « .. », joint au dossier courant, est refusé"
# Par un lien : le programme garde le chemin physique, que seul le vrai chemin (realpath) du dossier donné écrit.
mkdir -p "$P/physique" && ln -sfn physique "$P/logique"
compile par-lien "$(cd "$P/physique" && pwd -P)/release/build/out/glx_bindings.rs"
compilation "$P/logique" "$P/par-lien"
noter 1 "$(refus_dit $?)" "--compilation : le dossier de compilation par un lien, lu par son vrai chemin, est refusé"
# Majuscules : un système de fichiers qui les ignore (Windows, macOS) garde le même dossier sous une autre casse.
compile casse '/HOME/ALICE/.cargo/registry/src/x/y.rs'
compilation "$CIBLES_I" "$P/casse"
noter 1 "$(refus_dit $?)" "--compilation : le dossier personnel en majuscules est refusé"
compile casse-w 'C:\\USERS\\Alice\\cibles\\release'
compilation "$CIBLES_I" "$P/casse-w"
noter 1 "$(refus_dit $?)" "--compilation : le nom du compte dans un chemin Windows d'une autre casse est refusé"
compile mot 'chez alice, aliceville et /srv/cibles-inventees/vg2/x et /opt/alice.txt'
compilation "$CIBLES_I" "$P/mot"
noter 0 $? "--compilation : le nom seul, un dossier voisin et un fichier du même nom passent"
# Des « / » suivis de rien ou d'un blanc : un motif « / » tout seul les prendrait.
compile racine '/usr/lib/ et / puis C:/'
SORTIE=$(HOME=/ USER=alice garde --compilation / "$P/racine" 2>&1)
noter 0 $? "--compilation : HOME et dossier de compilation « / » ne cherchent pas tout chemin"
compilation "$CIBLES_I" "$P/propre" "$P/absent"
sans_trace 2 "--compilation : un programme absent, rien n'est conclu"
compilation "$CIBLES_I"
sans_trace 2 "--compilation : sans programme, rien n'est conclu"
# Sa place dans la recette : les lignes (hors commentaires) qui comptent, dans l'ordre.
R=$RACINE/outils/compiler-version.sh
ligne_de() { grep -nF -- "$1" "$R" | grep -v '^[0-9]*:[[:space:]]*#' | head -1 | cut -d: -f1; }
remplace=$(ligne_de 'REMPLACE_RUST+=" --remap-path-prefix=$CIBLES=/vanguard/target')
exporte=$(ligne_de 'export RUSTFLAGS=$REMPLACE_RUST')
fenetre=$(ligne_de 'manifest-path fenetre/Cargo.toml')
garde_f=$(ligne_de 'confidentialite.py --compilation "$CIBLES_DONNEES" "$FENETRE_LINUX" "$FENETRE_WINDOWS" ||')
empreinte=$(ligne_de 'VANGUARD_FENETRE_SHA256_LINUX=$(sha256sum')
vanguard=$(ligne_de '--target x86_64-unknown-linux-musl --target x86_64-pc-windows-gnu "$@"')
garde_v=$(ligne_de 'confidentialite.py --compilation "$CIBLES_DONNEES" "$CIBLES/x86_64-unknown-linux-musl/release/vanguard"')
repere=$(ligne_de '>"$REPERE.nouveau"')
ordre="$remplace $exporte $fenetre $garde_f $empreinte $vanguard $garde_v $repere"
if [[ $(wc -w <<<"$ordre") == 8 && $(tr ' ' '\n' <<<"$ordre" | sort -n | paste -sd' ') == "$ordre" ]] &&
  sed -n "$((garde_f + 1))p;$((garde_v + 2))p" "$R" | grep -c 'exit 1; }' | grep -qx 2; then
  noter 0 0 "--compilation dans la recette : chemins remplacés, puis fenêtres avant l'empreinte, vanguard avant le repère"
else
  noter 0 1 "--compilation dans la recette : absente, mal placée ou sans arrêt (lignes : $ordre)"
fi
# Les quatre programmes publiés, chacun nommé dans un des deux appels de la garde (lignes continuées par « \ »
# jointes, commentaires retirés) : un programme oublié partirait sans être relu.
appels=$(awk '/^[[:space:]]*#/ { next } { if (sub(/\\$/, "")) { l = l $0; next } print l $0; l = "" }' "$R" |
  grep -F 'confidentialite.py --compilation')
appel_f=$(sed -n 1p <<<"$appels")
appel_v=$(sed -n 2p <<<"$appels")
if [[ $(wc -l <<<"$appels") == 2 && $appel_f == *'"$FENETRE_LINUX" "$FENETRE_WINDOWS"'* &&
  $appel_v == *'"$CIBLES/x86_64-unknown-linux-musl/release/vanguard"'* &&
  $appel_v == *'"$CIBLES/x86_64-pc-windows-gnu/release/vanguard.exe"'* ]]; then
  noter 0 0 "--compilation dans la recette : les quatre programmes publiés sont relus"
else
  noter 0 1 "--compilation dans la recette : un des quatre programmes n'est pas relu ($(wc -l <<<"$appels") appel(s))"
fi
# Les dossiers de la recette, rejoués pour de vrai (le bloc entre ses deux repères, sans rien compiler) : une seule
# écriture, physique, du dossier de compilation (lien et « .. » dans celui qui est donné), CARGO_HOME par le lien de
# nom fixe sous lui, et les remplacements, celui de ce lien après celui du dossier (la dernière correspondance gagne).
DOSSIERS=$(sed -n '/^# >>> dossiers de la compilation/,/^# <<< dossiers de la compilation/p' "$R")
dossiers() { # CARGO_TARGET_DIR donné ; écrit dans SORTIE ce que le bloc exporte
  SORTIE=$(cd "$P" && CARGO_TARGET_DIR=$1 RACINE=/srv/depot-invente CARGO_DOSSIER=$P/cargo-invente bash -c \
    "set -euo pipefail; $DOSSIERS"$'\nprintf "%s\\n" "$CARGO_TARGET_DIR" "$CARGO_HOME" "$(readlink "$CARGO_HOME")" '\
'"$RUSTFLAGS" "$CFLAGS_x86_64_unknown_linux_musl" "$CFLAGS_x86_64_unknown_linux_gnu" "$CFLAGS_x86_64_pc_windows_gnu"' 2>&1)
}
mkdir -p "$P/vraies-cibles" "$P/cargo-invente" && ln -sfn vraies-cibles "$P/lien-cibles"
V=$P/vraies-cibles
attendu=$(printf '%s\n' "$V" "$V/.cargo-home" "$P/cargo-invente" \
  "--remap-path-prefix=/srv/depot-invente=/vanguard --remap-path-prefix=$P/cargo-invente=/cargo --remap-path-prefix=$V=/vanguard/target --remap-path-prefix=$V/.cargo-home=/cargo")
c="-ffile-prefix-map=/srv/depot-invente=/vanguard -ffile-prefix-map=$P/cargo-invente=/cargo -ffile-prefix-map=$V=/vanguard/target -ffile-prefix-map=$V/.cargo-home=/cargo"
attendu+=$'\n'"$c"$'\n'"$c"$'\n'"$c"
if [[ -n $DOSSIERS ]]; then
  dossiers "$P/lien-cibles/../lien-cibles"
  noter "$attendu" "$SORTIE" "recette : CARGO_TARGET_DIR physique (lien et « .. » retirés), CARGO_HOME par son lien fixe, remplacements dans l'ordre"
  dossiers lien-cibles
  noter "$attendu" "$SORTIE" "recette : un dossier de compilation relatif devient le même chemin physique"
  rm "$V/.cargo-home" && mkdir "$V/.cargo-home"
  dossiers "$V"
  noter "1 1" "$? $(grep -c 'pas un lien' <<<"$SORTIE")" "recette : un vrai dossier à la place du lien de CARGO_HOME est refusé"
  rmdir "$V/.cargo-home"
  mkdir -p "$P/a b"
  dossiers "$P/a b"
  noter "1 1" "$? $(grep -c 'un blanc' <<<"$SORTIE")" "recette : un blanc dans le dossier de compilation est refusé"
else
  noter 0 1 "recette : le bloc des dossiers de la compilation (repères « >>> » et « <<< ») est introuvable"
fi
cd "$TRAVAIL" || exit 1

if ((ECHECS)); then
  echo "Confidentialité : $ECHECS essai(s) sur $N en échec."
  exit 1
fi
echo "Confidentialité : $N essais, tous verts."
