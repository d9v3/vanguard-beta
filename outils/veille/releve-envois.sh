#!/usr/bin/env bash
# La relève des lots envoyés par les ordinateurs (outils/veille/LISEZMOI.md, « Envois ») : GET /v1/releve du relais,
# les réponses gardées telles quelles, octets bruts, dans retours/envois/AAAA-MM-JJ.jsonl (une réponse par ligne).
# Rien n'y est lu ni interprété ici : la lecture stricte est celle du programme (vanguard compte-rendu flotte). Ce
# dossier est une quarantaine : ni l'IA ni le rapport ne l'ouvrent.
#   ~/.config/vanguard-dev/relais-adresse   l'origine du relais, https://hote[:port] (rien d'autre sur la ligne)
#   ~/.config/vanguard-dev/relais-secret    le secret de relève (32 caractères ou plus, [A-Za-z0-9_-]), mode 600
# Codes : 0 relevé ; 77 sautée (pas configuré, relais injoignable ou occupé : la raison sur la première ligne) ;
# 1 refusé (droits du secret, adresse qui n'est pas https, secret refusé, redirection, réponse illisible ou trop
# grosse). Le relais efface ce qu'il rend : une réponse reçue est toujours gardée avant d'en demander une autre.
set -uo pipefail
umask 077
# L'adresse et le secret jugés en octets : une plage comme [a-z] dépend sinon de la langue du système.
export LC_ALL=C

CONFIG=${XDG_CONFIG_HOME:-$HOME/.config}/vanguard-dev
RETOURS=${VANGUARD_VEILLE_RETOURS:-${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/retours}
ENVOIS=$RETOURS/envois
JOUR=${VANGUARD_VEILLE_JOUR:-$(date +%F)}
# Ce que la nuit garde, au plus, par jour (8 Mio) ; une réponse du relais fait 4 Mio de lots au plus (RELEVE_OCTETS
# de relais/worker.js) plus leurs enveloppes : 5 Mio, comme la ligne que lit le programme (LIGNE_MAX de flotte.rs).
JOUR_MAX=$((8 * 1024 * 1024))
REPONSE_MAX=$((5 * 1024 * 1024))
APPELS_MAX=20
GARDE_JOURS=90

dire() { printf '%s\n' "$1"; }
# Un chemin pour le résumé de la nuit : sous le dossier personnel, en « ~/… » (le nom du compte n'y paraît pas).
court() { if [[ $1 == "$HOME"/* ]]; then printf '%s/%s' '~' "${1#"$HOME"/}"; else printf '%s' "$1"; fi; }
sautee() { dire "$1"; exit 77; }
refus() { dire "$1"; exit 1; }

[[ $JOUR =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || refus "jour illisible"
ADRESSE_F=$CONFIG/relais-adresse
SECRET_F=$CONFIG/relais-secret
[[ -e $ADRESSE_F ]] || sautee "relais pas configuré ($(court "$ADRESSE_F") absent)"
[[ -e $SECRET_F ]] || sautee "secret de relève absent ($(court "$SECRET_F")), adresse pourtant configurée"

# L'adresse : une origine https, sans chemin, sans identifiants ni requête ; jamais http (le secret partirait en
# clair). La ligne est lue sans jamais être recopiée dans le journal.
adresse=$(head -c 300 "$ADRESSE_F" | head -n1 | tr -d '\r')
[[ $adresse =~ ^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?/?$ ]] ||
  refus "adresse du relais refusée : une origine https://hote[:port], rien d'autre ($(court "$ADRESSE_F"))"
adresse=${adresse%/}/v1/releve

# Le secret : un fichier ordinaire à soi, lisible par soi seul ; jamais en argument (ps le montrerait) ni affiché.
[[ -f $SECRET_F && ! -L $SECRET_F && -O $SECRET_F ]] || refus "secret de relève refusé : pas un fichier ordinaire à soi"
droits=$(stat -c %a "$SECRET_F")
[[ $droits == 600 || $droits == 400 ]] || refus "secret de relève refusé : droits $droits (600 attendu : chmod 600 $(court "$SECRET_F"))"
secret=$(head -c 300 "$SECRET_F" | head -n1 | tr -d '\r')
[[ $secret =~ ^[A-Za-z0-9_-]{32,256}$ ]] || { unset secret; refus "secret de relève refusé : hors motif ([A-Za-z0-9_-], 32 à 256)"; }

mkdir -p "$ENVOIS" && chmod 700 "$ENVOIS" || refus "dossier des envois impossible à créer"
SORTIE=$ENVOIS/$JOUR.jsonl
[[ -L $SORTIE ]] && refus "le fichier du jour est un lien : refusé"

# Les fichiers de plus de 90 jours, par leur nom (une date ISO se compare comme un texte).
limite=$(date -d "$JOUR - $GARDE_JOURS days" +%F)
for f in "$ENVOIS"/????-??-??.jsonl; do
  [[ -f $f ]] || continue
  n=${f##*/}
  [[ ${n%.jsonl} < $limite ]] && rm -f -- "$f"
done

TMP=$(mktemp "$ENVOIS/.releve.XXXXXX") || refus "fichier temporaire impossible"
trap 'rm -f -- "$TMP" "$TMP.l"' EXIT

relever() {
  # -q d'abord : aucun ~/.curlrc. Le secret passe par --config sur l'entrée standard. HTTPS seulement, aucune
  # redirection suivie ni permise, taille et durée bornées.
  printf 'header = "Authorization: Bearer %s"\n' "$secret" |
    curl -q --config - --silent --show-error --proto =https --proto-redir =https --max-redirs 0 --tlsv1.2 \
      --connect-timeout 20 --max-time 120 --max-filesize "$REPONSE_MAX" -H 'Accept: application/json' \
      --output "$TMP" --write-out '%{http_code}' -- "$adresse" 2>/dev/null
}

appels=0 lots=0
while :; do
  deja=0
  [[ -f $SORTIE ]] && deja=$(stat -c %s "$SORTIE")
  if ((deja + REPONSE_MAX > JOUR_MAX)); then
    dire "relevé : $appels appel(s), $lots lot(s) ; plafond du jour atteint, le reste attend demain au relais"
    exit 0
  fi
  : >"$TMP"
  code_http=$(relever)
  code=$?
  appels=$((appels + 1))
  # Le relais efface ce qu'il rend avant de répondre : une réponse commencée puis coupée est perdue, et dite.
  case $code in
    0) ;;
    6 | 7 | 28)
      [[ $appels == 1 && ${code_http:-000} == 000 ]] && sautee "relais injoignable (pas d'Internet ?) : curl $code"
      refus "relève coupée (curl $code) : la réponse, déjà effacée au relais, est perdue" ;;
    63) refus "réponse du relais trop grosse (plus de $REPONSE_MAX octets) : refusée, perdue (déjà effacée au relais)" ;;
    *) refus "relève coupée (curl $code) : la réponse, déjà effacée au relais, est perdue" ;;
  esac
  case $code_http in
    200) ;;
    401) refus "secret de relève refusé par le relais (401)" ;;
    429) sautee "relais : trop de relèves (429), reprise la nuit prochaine" ;;
    3??) refus "redirection refusée ($code_http)" ;;
    5??) sautee "relais indisponible ($code_http)" ;;
    *) refus "réponse inattendue du relais (${code_http:0:3})" ;;
  esac
  # Une réponse par ligne : les sauts de ligne entre les éléments d'un JSON ne changent rien à sa valeur (dans une
  # chaîne, il serait déjà invalide). Puis la forme minimale, pour ne pas garder ce qui n'est pas une relève.
  tr -d '\r\n' <"$TMP" >"$TMP.l" && mv -f -- "$TMP.l" "$TMP" || refus "réponse impossible à recopier"
  taille=$(stat -c %s "$TMP")
  ((taille > 0 && taille <= REPONSE_MAX)) || refus "réponse vide ou trop grosse : refusée"
  forme=$(jq -r 'if type == "object" and .releve == 1 and (.lots | type) == "array" and (.reste | type) == "boolean"
                 then "\(.lots | length) \(.reste)" else "non" end' "$TMP" 2>/dev/null)
  # Gardée même illisible : le relais l'a déjà effacée, et le programme la comptera « illisible » sans la montrer.
  { cat -- "$TMP"; printf '\n'; } >>"$SORTIE"
  chmod 600 "$SORTIE"
  [[ $forme =~ ^[0-9]+\ (true|false)$ ]] || refus "réponse du relais illisible : gardée en quarantaine, relève arrêtée"
  lots=$((lots + ${forme% *}))
  if [[ ${forme#* } == false ]]; then
    dire "relevé : $appels appel(s), $lots lot(s)"
    exit 0
  fi
  if ((appels >= APPELS_MAX)); then
    dire "relevé : $appels appel(s), $lots lot(s) ; il en reste au relais (demain)"
    exit 0
  fi
done
