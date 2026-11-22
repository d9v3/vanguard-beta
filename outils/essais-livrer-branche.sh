#!/usr/bin/env bash
# Essais de outils/livrer-branche.sh dans des dépôts git jetables (un par cas, au compte inventé), où verifier.sh,
# deployer.sh et confidentialite.py sont des faux qui notent ce qu'ils voient : rien n'est compilé, envoyé ni lu de
# cet ordinateur (HOME jetable aussi, pour les journaux).
#   1. Une livraison ordinaire, master avancé entre-temps (rebase) : le commit vérifié est celui fusionné et déployé,
#      worktree et branche retirés après.
#   2. Un commit posé sur la branche pendant la vérification : refus, rien fusionné ni déployé.
#   3. Le worktree sali pendant la vérification : refus, rien fusionné.
#   4. Un journal de vérification sans « Tout est vert » (code 0 quand même), puis une vérification en échec : refus.
#   5. Le ménage raté (worktree verrouillé) : le déploiement est fait quand même, le ménage à finir est dit.
#   6. Le déploiement en échec : worktree et branche gardés, échec dit.
#   7. Les arguments : inversés, en nombre faux, le worktree qui est l'arbre principal, un worktree sur une autre
#      branche : refus (code 2) avant toute vérification.
#   8. L'arbre principal pas prêt : sali avant, un fichier non suivi, sali pendant la vérification, pas sur master :
#      refus, rien fusionné.
#   9. Master qui dépasse le commit vérifié (une autre fenêtre l'a fusionné puis a commité pendant la vérification) :
#      rien n'est déployé.
#  10. La branche déplacée seule (worktree détaché, HEAD inchangé) pendant la vérification : refus, rien fusionné.
#  11. La branche déplacée pendant le déploiement : livré, la branche gardée, dit.
#  12. Le garde-fou de confidentialité en panne (code 2, ou une trace de Python en code 1 sans constat) : refus, dit
#      comme une panne, pas comme un détail trouvé ; un vrai constat (code 1, « détail(s) personnel(s) ») : refus dit.
#  13. git status qui échoue (index abîmé), dans l'arbre principal ou dans le worktree : refus avant la vérification,
#      jamais un arbre pris pour propre.
#  14. Le garde-fou vidé par le lot même : c'est celui de master qui juge (refus) ; master sans garde-fou, ou avec un
#      garde-fou vide, muet ou qui n'a relu aucun commit (code 0 sans témoin) : refus.
#  15. deployer.sh (envoi_borne, lue telle quelle) : n'envoie que ce que GitHub a déjà, le commit vérifié (noté) et
#      ses propres commits (liste des fabricants, captures, page des fonctions) ; un commit d'ailleurs, une fusion,
#      un master réécrit : refus, et encore au déploiement suivant tant que le commit est là ; il refuse de partir
#      d'un autre commit que celui que livrer-branche.sh a vérifié.
#  16. deployer.sh (l'envoi, lu tel quel) : la tête notée est jugée puis poussée, jamais un commit posé sur master
#      pendant les vérifications (garde-fou, liens) ; une tête illisible ou un envoi refusé par la borne : rien
#      d'envoyé, c'est dit, code 8 (un autre échec garde son code).
#  17. deployer.sh qui finit bien sans rien envoyer sur GitHub (lien mort, refus, sans Internet), ou en code 8 (la
#      borne a refusé l'envoi) : la raison est montrée, pas de « ✔ livré », worktree et branche gardés, code 3 ; un
#      code 8 sans raison dans le journal : échec (code 1). Le texte dit comment régler : relancer deployer.sh
#      seulement si rien n'est à committer ; un commit passe par une branche livrée (W-2).
# Lancé par outils/verifier.sh.
#   outils/essais-livrer-branche.sh
set -uo pipefail
RACINE=$(cd "$(dirname "$0")/.." && pwd)
TRAVAIL=$(mktemp -d "${TMPDIR:-/tmp}/essais-livrer.XXXXXX")
trap 'rm -rf "$TRAVAIL"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=alice GIT_AUTHOR_EMAIL=alice@example.com GIT_COMMITTER_NAME=alice
export GIT_COMMITTER_EMAIL=alice@example.com
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

# Un dépôt neuf : master avec le vrai livrer-branche.sh et les faux, un worktree « lot » sur la branche lot avec un
# commit à livrer. Les faux lisent ce qu'ils doivent faire dans $CAS/consigne-*, et notent ce qu'ils voient dans
# $CAS/vu-*.
monter() {
  CAS=$TRAVAIL/$1
  DEPOT=$CAS/depot
  LOT=$CAS/lot
  mkdir -p "$DEPOT/outils" "$CAS/maison/.cache/vanguard-dev"
  cp "$RACINE/outils/livrer-branche.sh" "$DEPOT/outils/"
  cat >"$DEPOT/outils/verifier.sh" <<'FAUX'
#!/usr/bin/env bash
CAS=$ESSAI_CAS
git rev-parse HEAD >"$CAS/vu-verifie"
case $(cat "$CAS/consigne-verif" 2>/dev/null) in
  commit) echo plus >>a; git commit -qam "pendant la vérification" ;;
  sale) echo sale >>a ;;
  depot-sale) echo sale >>"$CAS/depot/b" ;;
  master-avance)
    git -C "$CAS/depot" merge -q --ff-only "$(git rev-parse HEAD)"
    echo d >"$CAS/depot/d"
    git -C "$CAS/depot" add d
    git -C "$CAS/depot" commit -qm "après la fusion, jamais vérifié"
    ;;
  branche-seule)
    git checkout -q --detach
    git branch -f lot "$(git commit-tree "HEAD^{tree}" -p HEAD -m ailleurs)"
    ;;
  muet) echo "Passage partiel"; exit 0 ;;
  echec) echo "✖ tests Linux"; exit 1 ;;
esac
echo "Tout est vert (faux)"
FAUX
  cat >"$DEPOT/outils/deployer.sh" <<'FAUX'
#!/usr/bin/env bash
git rev-parse HEAD >"$ESSAI_CAS/vu-deploye"
printf '%s' "${VANGUARD_COMMIT_VERIFIE:-}" >"$ESSAI_CAS/vu-commit-verifie"
if [[ -e $ESSAI_CAS/consigne-deploi-branche ]]; then
  git update-ref refs/heads/lot "$(git commit-tree "HEAD^{tree}" -p HEAD -m "pendant le déploiement")"
fi
cat "$ESSAI_CAS/consigne-deploi-sortie" 2>/dev/null
exit "$(cat "$ESSAI_CAS/consigne-deploi" 2>/dev/null || echo 0)"
FAUX
  printf '%s\n' 'import os, sys' 'cas = os.environ["ESSAI_CAS"]' \
    'open(cas + "/vu-plage", "w").write(" ".join(sys.argv[1:]))' \
    'c = open(cas + "/consigne-conf").read().strip() if os.path.exists(cas + "/consigne-conf") else "0"' \
    'if c not in ("muet", "zero"): print("Confidentialité : 1 commit(s) relu(s).", file=sys.stderr)' \
    'if c == "zero": print("Confidentialité : 0 commit(s) relu(s).", file=sys.stderr)' \
    'if c == "trouve": print("Confidentialité : 1 détail(s) personnel(s) dans les commits envoyés.", file=sys.stderr)' \
    'if c == "trace": raise RuntimeError("plantage du garde-fou")' \
    'sys.exit(1 if c == "trouve" else 0 if c in ("muet", "zero") else int(c))' \
    >"$DEPOT/outils/confidentialite.py"
  chmod +x "$DEPOT"/outils/*.sh
  echo b >"$DEPOT/b"
  git -C "$DEPOT" init -q -b master
  git -C "$DEPOT" add -A
  git -C "$DEPOT" commit -qm départ
  git -C "$DEPOT" update-ref refs/remotes/origin/master master
  git -C "$DEPOT" worktree add -q -b lot "$LOT"
  echo a >"$LOT/a"
  git -C "$LOT" add a
  git -C "$LOT" commit -qm "le lot (v0.0.1)"
}

# livrer-branche.sh lancé depuis l'arbre principal, comme le fait l'auteur ; sa sortie et son code gardés.
livrer() {
  SORTIE=$(cd "$DEPOT" && ESSAI_CAS=$CAS HOME=$CAS/maison bash outils/livrer-branche.sh "$@" 2>&1)
  CODE=$?
}
tete() { git -C "$DEPOT" rev-parse "$1" 2>/dev/null; }
# Rien fusionné ni déployé : master à son commit de départ, deployer.sh jamais lancé.
rien_livre() { [[ $(tete master) == "$1" && ! -e $CAS/vu-deploye ]]; }

# 1. Livraison ordinaire, master avancé entre-temps : le rebase fait un nouveau commit, c'est lui qui est vérifié.
monter ordinaire
echo c >"$DEPOT/c"
git -C "$DEPOT" add c && git -C "$DEPOT" commit -qm "fusion du jour"
livrer lot "$LOT"
VERIFIE=$(cat "$CAS/vu-verifie" 2>/dev/null)
if ((CODE == 0)) && [[ -n $VERIFIE && $(tete master) == "$VERIFIE" && $(cat "$CAS/vu-deploye") == "$VERIFIE" ]] &&
  [[ $(git -C "$DEPOT" log --format=%s master | tr '\n' '|') == "le lot (v0.0.1)|fusion du jour|départ|" ]] && [[ ! -d $LOT ]] && ! tete refs/heads/lot >/dev/null &&
  [[ $(cat "$CAS/vu-plage") == "--plage origin/master $VERIFIE" && $(cat "$CAS/vu-commit-verifie") == "$VERIFIE" ]]; then
  ok "livraison ordinaire : le commit vérifié (après rebase) est fusionné et déployé (et donné à deployer.sh), puis le ménage"
else
  ko "livraison ordinaire (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi

# 2. Un commit arrive sur la branche pendant la vérification (une autre fenêtre).
monter commit-pendant
DEPART=$(tete master)
echo commit >"$CAS/consigne-verif"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && grep -q 'a bougé pendant la vérification' <<<"$SORTIE" && [[ -d $LOT ]]; then
  ok "commit posé pendant la vérification : refus, rien fusionné ni déployé"
else
  ko "commit posé pendant la vérification (code $CODE, master $(tete master)) : $(tail -n 3 <<<"$SORTIE")"
fi

# 3. Le worktree sali pendant la vérification.
monter sale-pendant
DEPART=$(tete master)
echo sale >"$CAS/consigne-verif"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && grep -q 'a changé pendant la vérification' <<<"$SORTIE"; then
  ok "worktree sali pendant la vérification : refus, rien fusionné"
else
  ko "worktree sali pendant la vérification (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi

# 4. Une vérification qui rend 0 sans dire « Tout est vert », puis une vérification en échec.
monter journal-muet
DEPART=$(tete master)
echo muet >"$CAS/consigne-verif"
livrer lot "$LOT"
MUET=$CODE
SORTIE_MUET=$SORTIE
echo echec >"$CAS/consigne-verif"
livrer lot "$LOT"
if ((MUET != 0 && CODE != 0)) && rien_livre "$DEPART" && grep -q 'ne dit pas « Tout est vert »' <<<"$SORTIE_MUET" &&
  grep -q 'vérification en échec' <<<"$SORTIE"; then
  ok "journal sans « Tout est vert », vérification en échec : refus, rien fusionné"
else
  ko "journal sans « Tout est vert » (code $MUET) ou vérification en échec (code $CODE) : $(tail -n 2 <<<"$SORTIE_MUET")"
fi

# 5. Le ménage raté : un worktree verrouillé, que git worktree remove refuse.
monter menage-rate
git -C "$DEPOT" worktree lock "$LOT"
livrer lot "$LOT"
VERIFIE=$(cat "$CAS/vu-verifie" 2>/dev/null)
if ((CODE == 0)) && [[ -n $VERIFIE && $(tete master) == "$VERIFIE" && $(cat "$CAS/vu-deploye" 2>/dev/null) == "$VERIFIE" ]] &&
  grep -q 'ménage à finir à la main' <<<"$SORTIE" && grep -q "worktree .* gardé" <<<"$SORTIE" && [[ -d $LOT ]]; then
  ok "ménage raté : le déploiement est fait quand même, le ménage à finir est dit"
else
  ko "ménage raté (code $CODE, déployé : $(cat "$CAS/vu-deploye" 2>/dev/null || echo rien)) : $(tail -n 3 <<<"$SORTIE")"
fi

# 6. Le déploiement en échec : rien n'est retiré, l'échec est dit.
monter deploiement-rate
echo 1 >"$CAS/consigne-deploi"
livrer lot "$LOT"
if ((CODE != 0)) && [[ -d $LOT ]] && tete refs/heads/lot >/dev/null && grep -q 'déploiement en échec' <<<"$SORTIE"; then
  ok "déploiement en échec : worktree et branche gardés, échec dit"
else
  ko "déploiement en échec (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi

# 7. Les arguments : refusés avant toute vérification, code 2.
monter arguments
DEPART=$(tete master)
refus=()
livrer "$LOT" lot
((CODE == 2)) || refus+=("inversés : code $CODE")
livrer lot
((CODE == 2)) || refus+=("un seul argument : code $CODE")
livrer lot "$LOT" en-trop
((CODE == 2)) || refus+=("argument en trop : code $CODE")
livrer lot "$DEPOT"
((CODE == 2)) || refus+=("worktree = arbre principal : code $CODE")
livrer master "$DEPOT"
((CODE == 2)) || refus+=("master : code $CODE")
git -C "$DEPOT" worktree add -q -b autre "$CAS/autre"
livrer lot "$CAS/autre"
((CODE == 2)) && grep -q "n'est pas sur lot" <<<"$SORTIE" || refus+=("worktree sur une autre branche : code $CODE")
if ((${#refus[@]} == 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]]; then
  ok "arguments inversés, en nombre faux, arbre principal, autre branche : refus avant toute vérification"
else
  ko "arguments : ${refus[*]:-vérification lancée ou master changé}"
fi

# 8. L'arbre principal pas prêt : sali avant, sali pendant la vérification, sur une autre branche que master.
monter depot-pas-pret
DEPART=$(tete master)
refus=()
echo sale >>"$DEPOT/b"
livrer lot "$LOT"
((CODE != 0)) && [[ ! -e $CAS/vu-verifie ]] && grep -q 'changements non commités' <<<"$SORTIE" ||
  refus+=("sali avant (code $CODE)")
git -C "$DEPOT" checkout -q -- b
echo non-suivi >"$DEPOT/nouveau"
livrer lot "$LOT"
((CODE != 0)) && [[ ! -e $CAS/vu-verifie ]] && grep -q 'fichiers non suivis' <<<"$SORTIE" &&
  grep -q '^    ?? nouveau$' <<<"$SORTIE" ||
  refus+=("fichier non suivi, nommé (code $CODE)")
rm -f "$DEPOT/nouveau"
echo depot-sale >"$CAS/consigne-verif"
livrer lot "$LOT"
((CODE != 0)) && [[ -e $CAS/vu-verifie ]] && grep -q "l'arbre principal .* a des changements" <<<"$SORTIE" ||
  refus+=("sali pendant (code $CODE)")
git -C "$DEPOT" checkout -q -- b
rm -f "$CAS/consigne-verif" "$CAS/vu-verifie"
git -C "$DEPOT" checkout -q -b ailleurs
livrer lot "$LOT"
((CODE != 0)) && [[ ! -e $CAS/vu-verifie ]] && grep -q "n'est pas sur master" <<<"$SORTIE" ||
  refus+=("pas sur master (code $CODE)")
git -C "$DEPOT" checkout -q master
if ((${#refus[@]} == 0)) && rien_livre "$DEPART"; then
  ok "arbre principal sali avant ou pendant, ou pas sur master : refus, rien fusionné"
else
  ko "arbre principal pas prêt : ${refus[*]:-master changé ou déployé}"
fi

# 9. Master dépasse le commit vérifié : une autre fenêtre l'a fusionné, puis a commité sur master.
monter master-avance
echo master-avance >"$CAS/consigne-verif"
livrer lot "$LOT"
VERIFIE=$(cat "$CAS/vu-verifie" 2>/dev/null)
if ((CODE != 0)) && [[ -n $VERIFIE && ! -e $CAS/vu-deploye ]] && grep -q 'dépasse le commit vérifié' <<<"$SORTIE" &&
  [[ -d $LOT ]] && tete refs/heads/lot >/dev/null; then
  ok "master qui dépasse le commit vérifié : rien n'est déployé, worktree et branche gardés"
else
  ko "master qui dépasse le commit vérifié (code $CODE, déployé : $(cat "$CAS/vu-deploye" 2>/dev/null || echo rien)) : $(tail -n 3 <<<"$SORTIE")"
fi

# 10. La branche déplacée seule pendant la vérification : le worktree détaché garde HEAD au commit vérifié.
monter branche-seule
DEPART=$(tete master)
echo branche-seule >"$CAS/consigne-verif"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && grep -q 'a bougé pendant la vérification' <<<"$SORTIE"; then
  ok "branche déplacée seule, HEAD inchangé : refus, rien fusionné ni déployé"
else
  ko "branche déplacée seule (code $CODE, master $(tete master)) : $(tail -n 3 <<<"$SORTIE")"
fi

# 11. La branche déplacée pendant le déploiement : le ménage la garde (elle n'est plus au commit livré).
monter branche-deplacee
touch "$CAS/consigne-deploi-branche"
livrer lot "$LOT"
VERIFIE=$(cat "$CAS/vu-verifie" 2>/dev/null)
if ((CODE == 0)) && [[ -n $VERIFIE && $(cat "$CAS/vu-deploye" 2>/dev/null) == "$VERIFIE" ]] &&
  tete refs/heads/lot >/dev/null && [[ $(tete refs/heads/lot) != "$VERIFIE" ]] &&
  grep -q "branche lot gardée (elle n'est plus au commit livré)" <<<"$SORTIE"; then
  ok "branche déplacée pendant le déploiement : livré, branche gardée, dit"
else
  ko "branche déplacée pendant le déploiement (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi

# 12. Le garde-fou de confidentialité en panne (code 2, rien conclu).
monter garde-en-panne
DEPART=$(tete master)
echo 2 >"$CAS/consigne-conf"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]] &&
  grep -q 'garde-fou de confidentialité en panne (code 2)' <<<"$SORTIE" && ! grep -q 'détail personnel' <<<"$SORTIE"; then
  ok "garde-fou en panne : refus, dit comme une panne"
else
  ko "garde-fou en panne (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi

# 12 bis. Python qui plante (trace, code 1) n'est pas un détail trouvé ; un vrai constat, si (relecture 0.94, N-1).
monter garde-qui-plante
DEPART=$(tete master)
echo trace >"$CAS/consigne-conf"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]] &&
  grep -q 'garde-fou de confidentialité en panne (code 1)' <<<"$SORTIE" && ! grep -q 'détail personnel' <<<"$SORTIE"; then
  ok "garde-fou qui plante (trace, code 1) : refus, dit comme une panne"
else
  ko "garde-fou qui plante (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi
monter garde-qui-trouve
DEPART=$(tete master)
echo trouve >"$CAS/consigne-conf"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]] &&
  grep -q 'détail personnel : rien n.est fusionné' <<<"$SORTIE" && ! grep -q 'en panne' <<<"$SORTIE"; then
  ok "témoin : un vrai constat (code 1) est dit « détail personnel »"
else
  ko "constat du garde-fou (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi

# 13. git status qui échoue : son silence n'est pas un arbre propre (relecture 0.94, N-2).
for ou in principal worktree; do
  monter "status-$ou"
  DEPART=$(tete master)
  if [[ $ou == principal ]]; then INDEX=$(git -C "$DEPOT" rev-parse --git-path index); INDEX=$DEPOT/$INDEX
  else INDEX=$(git -C "$LOT" rev-parse --path-format=absolute --git-path index); fi
  printf 'abîmé' >"$INDEX"
  livrer lot "$LOT"
  if ((CODE != 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]] && grep -q 'git status a échoué' <<<"$SORTIE"; then
    ok "git status en échec ($ou) : refus avant la vérification"
  else
    ko "git status en échec ($ou) (code $CODE, vérifié : $([[ -e $CAS/vu-verifie ]] && echo oui || echo non)) : $(tail -n 3 <<<"$SORTIE")"
  fi
done

# 14. Le lot vide son propre garde-fou (il rend toujours 0) : c'est celui de master qui juge, et il trouve ; puis
# master sans garde-fou : refus, jamais un repli sur celui du lot.
monter garde-du-lot-vide
DEPART=$(tete master)
echo trouve >"$CAS/consigne-conf"
printf 'import sys\nsys.exit(0)\n' >"$LOT/outils/confidentialite.py"
git -C "$LOT" commit -qam "le lot vide le garde-fou"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]] &&
  grep -q 'détail personnel : rien n.est fusionné' <<<"$SORTIE" && [[ -z $(ls "$CAS/maison/.cache/vanguard-dev") ]]; then
  ok "garde-fou vidé par le lot : celui de master juge et refuse (copie effacée)"
else
  ko "garde-fou vidé par le lot (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi
monter master-sans-garde
DEPART=$(tete master)
git -C "$DEPOT" rm -q outils/confidentialite.py && git -C "$DEPOT" commit -qm "sans garde-fou"
DEPART=$(tete master)
git -C "$LOT" rebase -q master
printf 'import sys\nsys.exit(0)\n' >"$LOT/outils/confidentialite.py"
git -C "$LOT" add outils/confidentialite.py && git -C "$LOT" commit -qm "le lot apporte un garde-fou vide"
livrer lot "$LOT"
if ((CODE != 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]] &&
  grep -q "master n'a pas de outils/confidentialite.py" <<<"$SORTIE"; then
  ok "master sans garde-fou : refus, pas de repli sur celui du lot"
else
  ko "master sans garde-fou (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
fi
# Code 0 sans le témoin « N commit(s) relu(s) », N ≥ 1 : un garde-fou vide dans master, un muet, un qui n'a rien lu
# (relecture 0.95, V-5).
for juge in vide muet zero; do
  monter "garde-$juge"
  DEPART=$(tete master)
  if [[ $juge == vide ]]; then
    : >"$DEPOT/outils/confidentialite.py" && git -C "$DEPOT" commit -qam "garde-fou vide"
    DEPART=$(tete master) && git -C "$LOT" rebase -q master
  else
    echo "$juge" >"$CAS/consigne-conf"
  fi
  livrer lot "$LOT"
  if ((CODE != 0)) && rien_livre "$DEPART" && [[ ! -e $CAS/vu-verifie ]] &&
    grep -q "ne dit pas avoir relu le lot" <<<"$SORTIE"; then
    ok "garde-fou de master $juge (code 0 sans témoin) : refus, rien fusionné"
  else
    ko "garde-fou de master $juge (code $CODE) : $(tail -n 3 <<<"$SORTIE")"
  fi
done

# 15. deployer.sh : ce qui part sur GitHub est borné à ce que GitHub a, au commit vérifié et à ses propres commits
# (envoi_borne, lue telle quelle dans le vrai deployer.sh, avec la garde du commit vérifié), dans un dépôt jetable.
BORNE=$(awk '/^FICHIERS_DU_DEPLOIEMENT=/,/^VENU_DE_GITHUB=""$/' "$RACINE/outils/deployer.sh")
grep -q '^envoi_borne()' <<<"$BORNE" || ko "envoi_borne introuvable dans outils/deployer.sh"
D=$TRAVAIL/deployer-borne
git init -q -b master "$D"
mkdir -p "$D/src" "$D/docs" "$D/assets/captures"
echo un >"$D/src/main.rs" && git -C "$D" add -A && git -C "$D" commit -qm départ
DEPART_B=$(git -C "$D" rev-parse HEAD)
# borne [départ] : envoi_borne lancée dans le dépôt jetable, du départ (DEPART_B sinon) à la tête ; sa sortie dans
# SORTIE. garde_verifie : la garde du commit vérifié, telle quelle (VANGUARD_COMMIT_VERIFIE), son code dans CODE_V.
borne() {
  SORTIE=$(cd "$D" && set -euo pipefail && eval "$(sed '/^DEPART=/,$d' <<<"$BORNE")" &&
    envoi_borne "${1:-$DEPART_B}" "$(git rev-parse HEAD)" 2>&1)
}
garde_verifie() { CODE_V=$(cd "$D" && (set -euo pipefail && VANGUARD_COMMIT_VERIFIE=$1 eval "$BORNE") >/dev/null 2>&1; echo $?); }
note_ref() { git -C "$D" rev-parse -q --verify refs/vanguard/verifie; }
engager() { # message fichier…
  local m=$1
  shift
  for f in "$@"; do mkdir -p "$D/$(dirname "$f")" && echo "$m" >>"$D/$f"; done
  git -C "$D" add -A && git -C "$D" commit -qm "$m"
}
refus=()
# Rien de noté, rien sur GitHub : le premier commit n'a été vérifié par personne.
borne && refus+=("départ jamais vérifié ni sur GitHub accepté")
git -C "$D" update-ref refs/remotes/origin/master "$DEPART_B"
borne || refus+=("départ déjà sur GitHub refusé : $SORTIE")
git -C "$D" update-ref -d refs/remotes/origin/master
garde_verifie "$DEPART_B"
((CODE_V == 0)) && [[ $(note_ref) == "$DEPART_B" ]] || refus+=("commit vérifié pas noté (code $CODE_V)")
borne || refus+=("départ = tête refusé : $SORTIE")
engager fabricants assets/oui.tsv
engager captures assets/captures/menu.png assets/partage.png
engager page docs/index.html
borne || refus+=("commits de deployer.sh refusés : $SORTIE")
FIN_PROPRE=$(git -C "$D" rev-parse HEAD)
engager "une autre fenêtre" src/main.rs
borne && refus+=("commit sur src accepté")
grep -q '^    src/main.rs$' <<<"$SORTIE" || refus+=("src/main.rs pas nommé")
git -C "$D" reset -q --hard "$FIN_PROPRE"
engager "ajouté" src/neuf.rs
git -C "$D" rm -q src/neuf.rs && git -C "$D" commit -qm "retiré"
borne && refus+=("fichier ajouté puis retiré accepté")
git -C "$D" reset -q --hard "$FIN_PROPRE"
engager "à côté" assets/oui.tsv.bak docs/index.html.orig
borne && refus+=("nom qui commence comme un fichier permis accepté")
git -C "$D" reset -q --hard "$FIN_PROPRE"
engager "coupé" $'src/a\nassets/oui.tsv'
borne && refus+=("nom coupé par un retour à la ligne accepté")
git -C "$D" reset -q --hard "$FIN_PROPRE"
git -C "$D" checkout -q -b cote "$DEPART_B" && engager "à côté" assets/captures/autre.png && git -C "$D" checkout -q master
git -C "$D" merge -q --no-ff -m fusion cote
borne && refus+=("fusion acceptée")
git -C "$D" reset -q --hard "$DEPART_B~0" && git -C "$D" commit -q --amend -m "départ réécrit"
borne && refus+=("master qui ne descend plus du départ accepté")
git -C "$D" reset -q --hard "$FIN_PROPRE"
garde_verifie "$DEPART_B"
((CODE_V != 0)) || refus+=("départ autre que le commit vérifié accepté")
[[ $(note_ref) == "$DEPART_B" ]] || refus+=("commit noté alors que le départ est refusé")
# Un commit d'une autre fenêtre reste refusé au déploiement suivant (branchement de la clé), dont le départ est le
# master du moment, commit étranger compris (relecture 0.95, V-3) ; livré par livrer-branche.sh, il part.
engager "une autre fenêtre" src/main.rs
ETRANGER=$(git -C "$D" rev-parse HEAD)
borne "$ETRANGER" && refus+=("commit étranger accepté au déploiement suivant")
grep -q '^    src/main.rs$' <<<"$SORTIE" || refus+=("src/main.rs pas nommé au déploiement suivant")
garde_verifie "$ETRANGER"
((CODE_V == 0)) && [[ $(note_ref) == "$ETRANGER" ]] || refus+=("commit livré pas noté (code $CODE_V)")
borne "$ETRANGER" || refus+=("commit livré refusé : $SORTIE")
if ((${#refus[@]} == 0)); then
  ok "deployer.sh : envoi borné à GitHub, au commit vérifié et à ses propres commits, refus durable ; départ = commit vérifié"
else
  ko "deployer.sh, envoi borné : ${refus[*]}"
fi

# 16. deployer.sh : l'envoi, lu tel quel (de T_ENVOI à la durée), dans un dépôt jetable avec un « GitHub » local. Le
# faux liens.py joue l'autre fenêtre : il committe sur master pendant les vérifications. Ce qui part est la tête
# notée avant (jugée par le garde-fou, qui la reçoit), jamais ce commit (relecture 0.95, V-2).
ENVOI_BLOC=$(awk '/^T_ENVOI=\$SECONDS$/ { p = 1 } /^\[\[ -n \$LOCAL \]\] \|\| duree/ { p = 0 } p' "$RACINE/outils/deployer.sh")
grep -q 'git push' <<<"$ENVOI_BLOC" || ko "l'envoi de outils/deployer.sh est introuvable"
E=$TRAVAIL/deployer-envoi
git init -q --bare "$E/github.git"
git init -q -b master "$E/depot"
mkdir -p "$E/depot/src" "$E/depot/outils"
echo un >"$E/depot/src/main.rs" && git -C "$E/depot" add src && git -C "$E/depot" commit -qm départ
git -C "$E/depot" remote add origin "$E/github.git" && git -C "$E/depot" push -q origin master
echo lot >"$E/depot/src/lot.rs" && git -C "$E/depot" add src && git -C "$E/depot" commit -qm livré
LIVRE=$(git -C "$E/depot" rev-parse HEAD)
git -C "$E/depot" update-ref refs/vanguard/verifie "$LIVRE"
cat >"$E/depot/outils/confidentialite.py" <<'FAUX'
import sys
open(sys.argv[0] + ".vu", "w").write(" ".join(sys.argv[1:]))
print("Confidentialité : 1 commit(s) relu(s).", file=sys.stderr)
FAUX
cat >"$E/depot/outils/liens.py" <<'FAUX'
import subprocess
open("src/autre.rs", "w").write("jamais vérifié\n")
subprocess.run(["git", "add", "src/autre.rs"], check=True)
subprocess.run(["git", "commit", "-qm", "une autre fenêtre"], check=True)
FAUX
: >"$E/depot/outils/github.py"
# shellcheck disable=SC2034 # lues par l'envoi, évalué juste après
SORTIE=$(cd "$E/depot" && LOCAL='' MODE=--branchement A_PUBLIER='' VERSION=0 DEPART=$LIVRE &&
  eval "$(sed '/^DEPART=/,$d' <<<"$BORNE")" && eval "$ENVOI_BLOC" 2>&1)
refus=()
grep -q "^Code envoyé sur GitHub" <<<"$SORTIE" || refus+=("rien d'envoyé : $(tail -n 3 <<<"$SORTIE")")
[[ $(git -C "$E/github.git" rev-parse master 2>&1) == "$LIVRE" ]] || refus+=("GitHub n'a pas la tête notée")
git -C "$E/github.git" log --format= --name-only master 2>/dev/null | grep -q '^src/autre.rs$' &&
  refus+=("le commit posé pendant les vérifications est parti")
[[ $(git -C "$E/depot" log -1 --format=%s) == "une autre fenêtre" ]] || refus+=("la doublure de l'autre fenêtre n'a pas committé")
[[ $(cat "$E/depot/outils/confidentialite.py.vu" 2>&1) == "--plage $(git -C "$E/github.git" rev-parse master~1) $LIVRE refs/heads/master" ]] ||
  refus+=("le garde-fou n'a pas jugé la tête notée : $(cat "$E/depot/outils/confidentialite.py.vu" 2>&1)")
if ((${#refus[@]} == 0)); then
  ok "deployer.sh : la tête notée est jugée puis poussée, pas un commit posé pendant les vérifications"
else
  ko "deployer.sh, envoi : ${refus[*]}"
fi

# … et une tête qui ne se lit pas (dépôt sans commit, git en panne) : rien n'est jugé, rien ne part, c'est dit.
git init -q --bare "$E/github-vide.git"
git init -q -b master "$E/vide"
git -C "$E/vide" remote add origin "$E/github-vide.git"
# shellcheck disable=SC2034 # lues par l'envoi, évalué juste après
SORTIE=$(cd "$E/vide" && LOCAL='' MODE=--branchement A_PUBLIER='' VERSION=0 DEPART='' &&
  eval "$(sed '/^DEPART=/,$d' <<<"$BORNE")" && eval "$ENVOI_BLOC" 2>&1)
CODE=$?
if ((CODE == 8)) && grep -q "^Rien n'est envoyé sur GitHub : la tête du dépôt ne se lit pas" <<<"$SORTIE" &&
  [[ $(tail -n 1 <<<"$SORTIE") == "✖ Rien n'est parti sur GitHub : envoi refusé"* ]] &&
  [[ -z $(git -C "$E/github-vide.git" for-each-ref) ]]; then
  ok "deployer.sh : tête illisible, rien n'est jugé ni envoyé, c'est dit, code 8"
else
  ko "deployer.sh, tête illisible (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi
# … et le passage suivant sur le dépôt où l'autre fenêtre a committé : la borne refuse, le script finit en code 8 et
# sa dernière ligne le dit, pour qu'un livrer-branche.sh d'avant 0.95 voie un échec, pas un « livré » (W-1). Un
# autre échec garde son code.
# shellcheck disable=SC2034 # lues par l'envoi, évalué juste après
SORTIE=$(cd "$E/depot" && LOCAL='' MODE=--branchement A_PUBLIER='' VERSION=0 DEPART=$(git rev-parse HEAD) &&
  eval "$(sed '/^DEPART=/,$d' <<<"$BORNE")" && eval "$ENVOI_BLOC" 2>&1)
CODE=$?
# shellcheck disable=SC2034 # lues par l'envoi, évalué juste après
(cd "$E/depot" && LOCAL='' MODE=--branchement A_PUBLIER='' VERSION=0 DEPART=$(git rev-parse HEAD) &&
  eval "$(sed '/^DEPART=/,$d' <<<"$BORNE")" && eval "$ENVOI_BLOC" && exit 1) >/dev/null 2>&1
CODE_ECHEC=$?
if ((CODE == 8 && CODE_ECHEC == 1)) && grep -q "^Rien n'est envoyé sur GitHub : master porte plus" <<<"$SORTIE" &&
  [[ $(tail -n 1 <<<"$SORTIE") == "✖ Rien n'est parti sur GitHub : envoi refusé"* ]] &&
  [[ $(git -C "$E/github.git" rev-parse master) == "$LIVRE" ]]; then
  ok "deployer.sh : envoi refusé par la borne, code 8 et dernière ligne qui le dit ; un autre échec garde son code"
else
  ko "deployer.sh, envoi refusé (code $CODE, autre échec $CODE_ECHEC) : $(tail -n 2 <<<"$SORTIE")"
fi

# 17. Déployé ici, rien de parti sur GitHub : dit, worktree et branche gardés (relecture 0.95, V-4). Une ligne par
# raison que deployer.sh donne, chacune avec ses lignes en retrait.
for raison in "Rien n'est envoyé sur GitHub : un lien est mort (voir ci-dessus)." \
  "GitHub refuse l'envoi de master :" "GitHub injoignable : le code partira au prochain déploiement."; do
  grep -qF "$raison" "$RACINE/outils/deployer.sh" || ko "« $raison » n'est plus dit par outils/deployer.sh"
  monter "pas-envoye-${#raison}"
  printf 'Clé VANGUARD absente\n%s\n  https://exemple.invalid/mort\nDurées : 1 s\n' "$raison" >"$CAS/consigne-deploi-sortie"
  livrer lot "$LOT"
  if ((CODE == 3)) && [[ $(tete master) == "$(cat "$CAS/vu-deploye" 2>/dev/null)" && -d $LOT ]] && tete refs/heads/lot >/dev/null &&
    grep -qF "$raison" <<<"$SORTIE" && grep -q "^  https://exemple.invalid/mort" <<<"$SORTIE" &&
    grep -q "rien n'est parti sur GitHub" <<<"$SORTIE" && ! grep -q "✔ livré" <<<"$SORTIE" &&
    grep -q "sans commit (Internet ou lien revenu) : relancer outils/deployer.sh" <<<"$SORTIE" &&
    grep -q "demande un commit" <<<"$SORTIE" && grep -q "livrée par outils/livrer-branche.sh" <<<"$SORTIE"; then
    ok "rien d'envoyé sur GitHub (« ${raison:0:30}… ») : dit, code 3, worktree et branche gardés"
  else
    ko "rien d'envoyé sur GitHub (« ${raison:0:30}… », code $CODE) : $(tail -n 3 <<<"$SORTIE")"
  fi
done

# deployer.sh en code 8 (la borne a refusé l'envoi, W-1) : avec sa raison, « rien n'est parti », code 3, comme
# ci-dessus ; sans raison dans le journal, un échec comme un autre (code 1), jamais un « livré ».
monter borne-code-8
printf '%s\n' "Rien n'est envoyé sur GitHub : master porte plus que le commit vérifié et les commits de deployer.sh." \
  "  commit(s) sur master que GitHub n'a pas, ni vérifiés ni de deployer.sh :" "    src/autre.rs" \
  "✖ Rien n'est parti sur GitHub : envoi refusé par la borne (raison plus haut), déployé ici seulement." \
  >"$CAS/consigne-deploi-sortie"
echo 8 >"$CAS/consigne-deploi"
livrer lot "$LOT"
code_raison=$CODE sortie_raison=$SORTIE
monter borne-code-8-muet
echo 8 >"$CAS/consigne-deploi"
livrer lot "$LOT"
if ((code_raison == 3 && CODE == 1)) && [[ -d $LOT ]] && grep -q "^    src/autre.rs" <<<"$sortie_raison" &&
  grep -q "rien n'est parti sur GitHub" <<<"$sortie_raison" && ! grep -q "✔ livré" <<<"$sortie_raison$SORTIE" &&
  grep -q "déploiement en échec (code 8)" <<<"$SORTIE"; then
  ok "deployer.sh en code 8 : avec sa raison, code 3 et dit ; sans raison, échec (code 1) ; jamais « livré »"
else
  ko "deployer.sh en code 8 (avec raison $code_raison, sans raison $CODE) : $(tail -n 2 <<<"$sortie_raison")"
fi

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "livrer-branche.sh : tout est juste."
