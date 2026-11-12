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
#  12. Le garde-fou de confidentialité en panne (code 2) : refus, dit comme une panne, pas comme un détail trouvé.
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
if [[ -e $ESSAI_CAS/consigne-deploi-branche ]]; then
  git update-ref refs/heads/lot "$(git commit-tree "HEAD^{tree}" -p HEAD -m "pendant le déploiement")"
fi
exit "$(cat "$ESSAI_CAS/consigne-deploi" 2>/dev/null || echo 0)"
FAUX
  printf '%s\n' 'import os, sys' 'cas = os.environ["ESSAI_CAS"]' \
    'open(cas + "/vu-plage", "w").write(" ".join(sys.argv[1:]))' \
    'sys.exit(int(open(cas + "/consigne-conf").read()) if os.path.exists(cas + "/consigne-conf") else 0)' \
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
  [[ $(cat "$CAS/vu-plage") == "--plage origin/master $VERIFIE" ]]; then
  ok "livraison ordinaire : le commit vérifié (après rebase) est fusionné et déployé, puis le ménage"
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
((CODE != 0)) && [[ ! -e $CAS/vu-verifie ]] && grep -q 'fichiers non suivis' <<<"$SORTIE" ||
  refus+=("fichier non suivi (code $CODE)")
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

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "livrer-branche.sh : tout est juste."
