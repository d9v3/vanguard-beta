# shellcheck shell=bash
# La clé VANGUARD de cet ordinateur et sa partition des journaux, reconnues comme le programme les reconnaît (lu par
# source : outils/deployer.sh, outils/publier-version.sh, outils/images-cle.sh, outils/cle-secours.sh ; des fonctions
# seulement, rien n'est lancé). Le témoin vanguard.cle dit qu'un volume est fait comme une clé, pas que c'est la
# sienne : n'importe quel volume étiqueté VANGUARD le porte si quelqu'un l'y a posé. Seul compte le jeton
# (vanguard.jeton) connu de cet ordinateur (src/protection/cles_connues.rs), que `vanguard deploiement cle` vérifie.
# Un volume inconnu ne reçoit rien (ni programme, ni code source avec .git, ni journal rapatrié) : sa première
# adoption est un geste de l'auteur (outils/deployer.sh --accepter-cle <dossier>).

# Le programme qui reconnaît la clé : celui que le dépôt vient de compiler, sinon celui que deployer.sh installe.
# VANGUARD_PROGRAMME en désigne un autre, dans les essais seulement (VANGUARD_ESSAI, outils/essais-cle.sh) : rien
# d'autre n'y est pris, pour qu'un essai ne dépende pas de ce qui a été compilé ici.
programme_cle() {
  if [[ -n ${VANGUARD_ESSAI:-} ]]; then
    [[ -n ${VANGUARD_PROGRAMME:-} && -x ${VANGUARD_PROGRAMME:-} ]] && echo "$VANGUARD_PROGRAMME"
    return 0
  fi
  local p
  for p in "${CLE_COMMUN_DEPOT:-.}/target/x86_64-unknown-linux-musl/release/vanguard" "$HOME/.cargo/bin/vanguard"; do
    [[ -x $p ]] && { echo "$p"; return 0; }
  done
  command -v vanguard || true
}

# La racine de la clé connue de cet ordinateur sur la sortie, ou rien. Code 0 : trouvée, ou aucun volume au témoin ;
# 3 : des volumes portent le témoin sans jeton connu ; 4 : plusieurs portent le même jeton connu, une copie de la clé
# (le programme les nomme sur la sortie d'erreur) ; autre : pas de programme qui sache la chercher (dit), rien n'est
# écrit nulle part.
cle_connue() { # [programme]
  local programme=${1:-}
  [[ -n $programme ]] || programme=$(programme_cle)
  if [[ -z $programme || ! -x $programme ]]; then
    echo "· vanguard introuvable : la clé VANGUARD n'est pas cherchée (rien n'y est écrit)." >&2
    return 2
  fi
  "$programme" deploiement cle
}

# Le jeton d'un volume, en minuscules, s'il a la forme attendue (32 caractères hexadécimaux) ; rien sinon.
jeton_du_volume() { # racine
  local j
  [[ -f $1/vanguard.jeton && ! -L $1/vanguard.jeton ]] || return 0
  j=$(head -c 64 "$1/vanguard.jeton" 2>/dev/null | tr -d '[:space:]' | tr 'A-F' 'a-f')
  [[ $j =~ ^[0-9a-f]{32}$ ]] && echo "$j"
  return 0
}

# La partition VANGUARDLOG de la clé `racine` : celle du même disque (pas n'importe quel volume à cette étiquette,
# que n'importe qui peut poser), montée, dont le jeton est celui de la clé (ou absent : deployer.sh le lui recopie).
# Son point de montage sur la sortie, ou rien ; code 1 quand elle porte un autre jeton (dit).
journal_de_la_cle() { # racine
  local source disque nom label point jeton jeton_log
  source=$(findmnt -nvo SOURCE -T "$1" 2>/dev/null | tail -1 || true)
  [[ -n $source ]] || return 0
  disque=$(lsblk -dno PKNAME "$source" 2>/dev/null || true)
  [[ -n $disque ]] || return 0
  jeton=$(jeton_du_volume "$1")
  while read -r nom label; do
    [[ $label == VANGUARDLOG ]] || continue
    point=$(findmnt -nro TARGET -S "$nom" 2>/dev/null | head -1 || true)
    [[ -n $point && -d $point ]] || continue
    jeton_log=$(jeton_du_volume "$point")
    if [[ -n $jeton_log && $jeton_log != "$jeton" ]]; then
      echo "✖ Partition VANGUARDLOG de la clé ($point) au jeton d'une autre clé : rien n'y est lu ni écrit." >&2
      return 1
    fi
    echo "$point"
    return 0
  done < <(lsblk -lnpo NAME,LABEL "/dev/$disque" 2>/dev/null || true)
  return 0
}
