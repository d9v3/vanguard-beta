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
#  10. témoins : un fichier propre passe, un courriel dans un nom ordinaire est trouvé ;
#  11. les erreurs (usage, git en échec, fichier illisible) : code 2, « rien n'est conclu », jamais pris pour une
#      trouvaille ; une trouvaille (code 1) n'est comptée que si l'outil dit ce qu'il a trouvé ;
#  12. l'étape de la CI (.github/workflows/ci.yml, lue telle quelle) : le garde-fou lancé est celui de la base, pas
#      celui de l'arbre jugé (une demande qui le viderait ne se rend pas verte) ; repli dit si la base n'en a pas.
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
  sortie=$(python3 "$OUTIL" "$@" 2>&1)
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
# essais n'est pas celle de cet ordinateur).
crochets() {
  depot "$1"
  git init -q --bare "$D.git" && git remote add origin "$D.git" && git push -q origin master 2>/dev/null
  mkdir outils && printf 'outils/\n' >>.git/info/exclude
  printf 'import os, sys\nos.execvp("python3", ["python3", %s, "--generique", *sys.argv[1:]])\n' \
    "$(printf '%s' "$OUTIL" | python3 -c 'import sys; print(repr(sys.stdin.read()))')" >outils/confidentialite.py
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

# Rien n'est conclu (code 2) : jamais pris pour une trouvaille (1), ni pour un vert (0).
depot erreurs
garde --generique --plage HEAD >/dev/null 2>&1
noter 2 $? "usage : --plage sans APRÈS"
garde --generique --tout >/dev/null 2>&1
noter 2 $? "usage : option inconnue"
# (Un AVANT inconnu, lui, est un historique réécrit, lu comme tel : voir plus haut.)
garde --generique --plage HEAD nexistepas >/dev/null 2>&1
noter 2 $? "git en échec (--plage vers un commit inconnu)"
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
python3 - "$RACINE/.github/workflows/ci.yml" >"$ETAPE_CI" <<'PY'
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
noter 1 $? "CI : une demande qui vide le garde-fou est jugée par celui de la base"

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
noter 1 $? "CI : branche neuve (AVANT fait de zéros), le garde-fou de master"
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
code=$?
grep -q '^::warning::Garde-fou de confidentialité pris dans l.arbre jugé' <<<"$SORTIE" || code="$code, repli pas dit"
noter 1 "$code" "CI : base sans garde-fou, repli sur celui de l'arbre jugé, dit en avertissement"
cd "$TRAVAIL" || exit 1

if ((ECHECS)); then
  echo "Confidentialité : $ECHECS essai(s) sur $N en échec."
  exit 1
fi
echo "Confidentialité : $N essais, tous verts."
