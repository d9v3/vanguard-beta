#!/bin/sh
# Le fil d'un ticket ou d'une demande de fusion (PR) n'a-t-il que le propriétaire du dépôt pour auteur ? Lancé par
# .github/workflows/claude.yml deux fois : au garde, puis juste avant Claude, le fil verrouillé (des minutes passent
# entre les deux : machine, Rust, apt-get). Chaque commentaire, et pour une demande chaque revue et commentaire de
# revue, doit être du propriétaire ou des robots de Claude et de GitHub Actions, que personne d'autre ne fait écrire
# ici. Code 0 : rien que lui ; 1 : un autre a écrit ; 2 : fil illisible (panne de l'API), jamais supposé propre.
# Lit NUMERO (ticket ou demande), DEMANDE (vide pour un ticket) et GITHUB_REPOSITORY ; gh lit GH_TOKEN.
#   outils/fil-du-proprietaire.sh
set -u
chemins="repos/$GITHUB_REPOSITORY/issues/$NUMERO/comments"
if [ -n "${DEMANDE:-}" ]; then
  chemins="$chemins repos/$GITHUB_REPOSITORY/pulls/$DEMANDE/reviews repos/$GITHUB_REPOSITORY/pulls/$DEMANDE/comments"
fi
for chemin in $chemins; do
  if ! autres=$(gh api "$chemin" --paginate --jq '.[] | select(.author_association != "OWNER" and .user.login != "claude[bot]" and .user.login != "github-actions[bot]") | .id'); then
    echo "::warning::Fil illisible ($chemin) : Claude n'y est pas lancé."
    exit 2
  fi
  if [ -n "$autres" ]; then
    echo "::warning::Ce fil a des commentaires d'un autre que le propriétaire : Claude n'y est pas lancé."
    exit 1
  fi
done
exit 0
