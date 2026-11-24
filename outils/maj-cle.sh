#!/usr/bin/env bash
# La clé VANGUARD au complet, remise à jour même quand elle reste branchée : sans débranchement, rien ne lui arrive
# sinon (les unités du branchement ne repartent qu'au montage suivant). Chaque jour (vanguard-cle-maj.timer, rattrapé
# au démarrage si l'ordinateur était éteint), seulement si la clé est montée ; à la main : outils/maj-cle.sh.
#   1. le programme : deployer.sh --branchement (la dernière version de GitHub, compilée si elle est nouvelle) ;
#   2. les images : images-cle.sh --cle (celles du cache, vérifiées, à la place des anciennes de la clé) ;
#   3. le démarrage : cle-secours.sh --a-jour (Ventoy plus ancien que celui épinglé : sa mise à jour, qui n'efface
#      rien, est proposée par une notification, et faite sur accord).
# Les étapes 2 et 3 partout, sauf sur un ordinateur dont le réglage local coupe la clé de secours (CLE_SECOURS=non,
# voir images-cle.sh) : là, la clé ne porte que le programme.
# deployer.sh et images-cle.sh prennent le même verrou : jamais deux écritures de la clé à la fois, même avec un
# déploiement lancé à la main ou un branchement en même temps. Une étape ratée n'empêche pas la suivante ; la
# notification dit laquelle (sauf des programmes refusés, que deployer.sh a déjà dits), et le code de sortie aussi.
# Clé absente : rien à faire, sans erreur.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=outils/cle-commun.sh
source outils/cle-commun.sh || exit 1

avertir() { # titre texte
  command -v notify-send >/dev/null && notify-send -a Vanguard -i vanguard -- "$1" "$2" || true
}

# La clé de cet ordinateur (son jeton), jamais « le premier volume au témoin » : avec deux clés branchées, la lecture
# seule et le reste se jugeaient sur celle d'un autre.
CODE_CLE=0
CLE=$(cle_connue) || CODE_CLE=$?
if [[ -z $CLE ]]; then
  if ((CODE_CLE == 0)) || [[ -z $(find "/run/media/$USER" -maxdepth 2 -name vanguard.cle 2>/dev/null) ]]; then
    echo "Clé VANGUARD non branchée : rien à faire."
    exit 0
  fi
  # Un volume au témoin, pas reconnu (jeton inconnu, en double, ou pas de programme pour le dire) : deployer.sh le juge
  # et le dit ; rien d'autre n'y est fait, et rien n'est dit « à jour ».
  outils/deployer.sh --branchement
  CODE_CLE=$?
  echo "Clé VANGUARD pas reconnue : ni programme, ni images, ni démarrage mis à jour."
  exit "$CODE_CLE"
fi
# Montée en lecture seule (un exFAT abîmé par un arrêt brutal, que le noyau remonte ainsi) : rien ne s'y écrirait, et
# chaque étape échouerait sans dire pourquoi.
if [[ ! -w $CLE ]]; then
  echo "Clé VANGUARD en lecture seule ($CLE) : rien n'y est copié."
  avertir "Clé VANGUARD en lecture seule" "Son système de fichiers est peut-être abîmé (arrêt brutal) : rien n'y est \
copié. À vérifier puis réparer, et la rebrancher."
  exit 1
fi

RATEES=() DEJA_DITES=()
etape() { # libellé commande…
  local libelle=$1
  shift
  echo "== $libelle"
  "$@"
}
# Des programmes refusés pour une faille connue : deployer.sh le dit déjà par sa notification (refuser), et note son
# repère à ce moment-là ; il ne la redonne pas pendant 5 minutes. Un repère de moins de 5 minutes après l'échec : la
# notification est partie, la redire ici ferait deux notifications pour une seule cause.
REFUS=${XDG_RUNTIME_DIR:-/tmp}/vanguard-refus.empreinte
if ! etape "programme" outils/deployer.sh --branchement; then
  if [[ -n $(find "$REFUS" -mmin -5 2>/dev/null) ]]; then
    DEJA_DITES+=("programme (refusé)")
  else
    RATEES+=(programme)
  fi
fi
TENU="programme, images et démarrage"
# « non » seulement : images-cle.sh en panne n'est pas un réglage qui dit non, la clé de secours n'en serait plus
# tenue à jour en silence.
SECOURS=$(outils/images-cle.sh --secours 2>/dev/null) || true
if [[ $SECOURS == non ]]; then
  TENU="programme (clé de secours coupée sur cet ordinateur : ni images ni démarrage)"
else
  CODE_IMAGES=0
  etape "images" outils/images-cle.sh --cle || CODE_IMAGES=$?
  # 5 : rien de raté, mais les images n'ont pas été vues (dit par images-cle.sh) ; jamais dites à jour.
  case $CODE_IMAGES in
    0) ;;
    5) TENU="programme et démarrage (images pas vues : le détail au-dessus)" ;;
    *) RATEES+=(images) ;;
  esac
  etape "démarrage" outils/cle-secours.sh --a-jour || RATEES+=("démarrage")
fi
if ((${#RATEES[@]})); then
  avertir "Clé VANGUARD : mise à jour du jour incomplète" "Raté : ${RATEES[*]}${DEJA_DITES[*]:+ ; déjà dit : \
${DEJA_DITES[*]}}. Le détail : journalctl --user -u vanguard-cle-maj"
  exit 1
fi
if ((${#DEJA_DITES[@]})); then
  echo "Clé VANGUARD pas tout à fait à jour : ${DEJA_DITES[*]}, déjà dit par sa notification."
  exit 1
fi
echo "Clé VANGUARD à jour : $TENU."
