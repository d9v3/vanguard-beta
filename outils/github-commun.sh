#!/usr/bin/env bash
# Ce que les outils demandent à GitHub (gh), lu de la même façon partout. Sourcé (outils/publier-version.sh).

# La page de version d'une étiquette est-elle en ligne ? Arguments : ceux de « gh release view » (étiquette, -R dépôt).
# Rend 0 (en ligne, brouillon compris), 1 (absente : gh le dit, mot pour mot) ou 2 (rien conclu : réseau, compte,
# délai… dit sur la sortie d'erreurs). gh rend 1 pour les deux derniers : une panne prise pour une absence ferait
# recréer, puis effacer, une page déjà en ligne.
page_en_ligne() {
  local dit code=0
  dit=$(timeout 60 gh release view "$@" 2>&1 >/dev/null) || code=$?
  ((code != 0)) || return 0
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
