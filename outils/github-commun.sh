#!/usr/bin/env bash
# Ce que les outils demandent à GitHub (gh), lu de la même façon partout. Sourcé (outils/publier-version.sh,
# outils/deployer.sh).

# La page de version d'une étiquette est-elle en ligne ? Arguments : ceux de « gh release view » (étiquette, -R dépôt).
# Rend 0 (en ligne), 1 (absente : gh le dit, mot pour mot), 2 (rien conclu : réseau, compte, délai, réponse
# illisible… dit sur la sortie d'erreurs) ou 3 (brouillon : personne ne la voit, une création interrompue en laisse un).
# gh rend 1 pour une absence comme pour une panne : prise pour une absence, une panne ferait recréer, puis effacer, une
# page déjà en ligne ; un brouillon pris pour une page ferait croire la version publiée.
page_en_ligne() {
  local dit code=0
  dit=$(timeout 60 gh release view "$@" --json isDraft -q .isDraft 2>&1) || code=$?
  case $code:$dit in
    0:false) return 0 ;;
    0:true) return 3 ;;
  esac
  [[ $code == 1 && $dit == "release not found" ]] && return 1
  echo "✖ GitHub n'a pas répondu pour la page de $1 (code $code) : ${dit:-sans message}" >&2
  return 2
}

# Le dépôt de ce nom existe-t-il ? Mêmes codes ; 1 : GitHub dit qu'aucun dépôt de ce nom ne se résout (gh sans droit de
# le voir rend le même message : sans connexion, gh rend 4, donc 2 ici).
depot_en_ligne() {
  local dit code=0
  dit=$(timeout 60 gh repo view "$1" 2>&1 >/dev/null) || code=$?
  ((code != 0)) || return 0
  [[ $code == 1 && $dit == "GraphQL: Could not resolve to a Repository with the name '$1'."* ]] && return 1
  echo "✖ GitHub n'a pas répondu pour le dépôt $1 (code $code) : ${dit:-sans message}" >&2
  return 2
}
