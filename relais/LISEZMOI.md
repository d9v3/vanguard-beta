# Le relais des lots d'amélioration

Un Worker de Cloudflare (`worker.js`) et sa base D1 (`schema.sql`). Chaque ordinateur où l'envoi est allumé y dépose
son lot du jour ; l'ordinateur de l'auteur vient les relever, puis les relit en Rust, et c'est cette lecture-là qui
fait foi. Le relais n'agrège rien et ne garde rien plus de 14 jours.

Rien n'est déployé par le dépôt : ce dossier est le code, et les étapes ci-dessous sont celles que l'auteur fait
lui-même, une fois, avec son propre compte.

## Ce que l'auteur crée (plan de l'envoi, §10)

1. **Un compte Cloudflare** gratuit, avec la double authentification.
2. **Un sous-domaine workers.dev neutre**, sans son nom ni rien qui le désigne : l'adresse
   `https://relais.<sous-domaine>.workers.dev` sera écrite dans le programme, donc publique.
3. **wrangler** sur son ordinateur (`npm install -g wrangler`, ou `npx wrangler` à chaque commande), puis
   `wrangler login`.
4. **La base D1** :

   ```sh
   wrangler d1 create relais
   ```

   recopier l'identifiant affiché dans `database_id` de `wrangler.toml` (à la place de « A-REMPLACER… »), puis créer
   les tables :

   ```sh
   wrangler d1 execute relais --remote --file relais/schema.sql
   ```

5. **Le limiteur** : `namespace_id` de `wrangler.toml` est un nombre libre, propre au compte ; le garder ou en
   choisir un autre.
6. **Le secret de relève**, tiré au hasard, 32 caractères au moins (un plus court est refusé comme absent) :

   ```sh
   head -c 48 /dev/urandom | base64 | tr -d '+/=' | cut -c1-48
   wrangler secret put SECRET_RELEVE      # coller le secret quand wrangler le demande
   ```

   Le ranger aussi dans `~/.config/vanguard-dev/`, pour l'outil de relève. **Jamais** dans le dépôt, jamais sur la clé
   de secours, jamais dans `wrangler.toml`.
7. **Déployer** depuis `relais/` : `wrangler deploy`. Aucun autre réglage : les journaux du Worker sont coupés dans
   `wrangler.toml` (`[observability] enabled = false`, `logpush = false`) et le Worker n'écrit rien dans la console.

Rien d'autre : aucun jeton GitHub, aucun `account_id` dans le dépôt (wrangler le prend du compte connecté).

## Mise à jour du relais

`schema.sql` est aussi sa propre migration : tout y est `IF NOT EXISTS` ou `OR IGNORE`, il ajoute ce qui manque à une
base déjà créée sans rien effacer. À chaque mise à jour du Worker, dans cet ordre :

```sh
wrangler d1 execute relais --remote --file relais/schema.sql   # avant : le nouveau Worker trouve ses tables
wrangler deploy                                                 # depuis relais/
wrangler d1 execute relais --remote --file relais/schema.sql   # après : marque les lots reçus entre-temps
```

Le second passage marque comme déjà reçus les lots que l'ancien Worker a gardés pendant la bascule (table `vus`,
ci-dessous) : sans lui, un renvoi de l'un d'eux serait gardé deux fois. Un nouveau Worker déployé sans le premier
passage répond 503 aux lots qui portent un identifiant d'installation ; le programme réessaie le lendemain, rien
n'est perdu.

## Ce que fait le relais

| Requête | Réponse |
|---|---|
| `POST /v1/lot`, corps JSON | `200` gardé, ou déjà reçu ; `400` JSON illisible ; `413` plus de 128 Kio ; `415` pas `application/json` ; `422` hors du schéma, un secret ou un jour hors des bornes ; `429` trop de lots ; `503` base injoignable |
| `GET /v1/releve`, `Authorization: Bearer <secret>` | `200` et les lots ; `401` secret faux ou absent ; `429` trop d'essais ratés |
| tout autre chemin, ou un paramètre | `404` ; une autre méthode sur ces deux chemins : `405` |

Les réponses à `POST /v1/lot` n'ont aucun corps : le programme ne lit que le code, et un relais piraté ne peut rien
lui faire faire. Aucune redirection, jamais.

**Vérification d'un lot**, dans l'ordre : limiteur, type, taille annoncée, lecture bornée à 128 Kio, UTF-8 et JSON,
puis le schéma de `outils/veille/schema-envoi.json` (recopié dans `worker.js`, entre les lignes
`DÉBUT DU SCHÉMA DU LOT` et `FIN DU SCHÉMA DU LOT`) : une clé de trop, une clé en double, un entier écrit `1.0`, un
lot réécrit de plus de 96 Kio, et tout le lot est refusé. Les champs de la voie ouverte (textes d'erreur, noms de
logiciels, versions tierces) passent ensuite par une copie du détecteur de secrets de `src/amelioration/texte.rs` :
la deuxième des trois couches. Un lot qui sonne est refusé (`422`), compté « secret », jamais gardé. Un champ de la
voie ouverte plus long que sa borne est refusé avant le détecteur. Viennent ensuite le jour du lot (12 jours avant
celui de réception au plus, le lendemain au plus, sinon `422`, compté « jour »), le doublon, le quota de la source,
puis le plafond de tous : un lot refusé par son quota ne compte pas dans le plafond.

**Doublons** : le programme renvoie le même lot s'il est arrêté entre le `200` et le retrait de sa file. Un lot dont
l'identifiant d'installation et le jour (`installation`, `jour`) ont déjà été reçus répond `200`, pour que le
programme le retire, mais n'est ni gardé ni compté dans les quotas (compté « doublon » avec les refus). Le premier
reçu reste : le relais ne sait pas qui envoie (l'identifiant n'est pas une preuve, n'importe qui peut poster), donc
aucun envoi ne remplace un lot déjà gardé. Revers assumé : quelqu'un qui connaîtrait l'identifiant d'un ordinateur
pourrait faire passer son lot avant le vrai, pour aujourd'hui ou demain seulement ; il ne peut ni l'effacer ni le
réécrire une fois reçu. Deux envois simultanés sont tranchés par la clé primaire de `vus`, dans la même transaction
que le lot. Un lot sans identifiant d'installation n'est jamais pris pour un doublon.

**Limites** : 10 requêtes par minute et par source (limiteur de Cloudflare) ; 50 lots par jour et par source ;
5 000 lots par jour en tout. Une source est l'empreinte HMAC du préfixe /24 (IPv4) ou /48 (IPv6), avec un sel tiré
chaque jour et effacé le lendemain : l'adresse IP n'est jamais gardée. Le sel du jour dort dans la même base D1 que
les empreintes : pendant la journée, quelqu'un qui lirait D1 pourrait retrouver un préfixe en les essayant tous.
Passé minuit, le sel est effacé et ce n'est plus possible.

**Base D1** : `lots` (les lots acceptés, le JSON réécrit par le Worker), `vus` (installation et jour de chaque lot
reçu : elle survit à la relève, pour reconnaître un doublon même relevé), `quotas` (les comptes du jour), `refus` (les
refus comptés par jour et par raison, jamais leur contenu), `sels` (le sel du jour).

**Relève** : au plus 1 000 lots ou 4 Mio par appel, lus puis effacés dans la même transaction, avec les compteurs de
refus (une panne au milieu n'efface rien) ; `"reste": true` dit qu'il faut rappeler. Forme :
`{"releve":1,"lots":[{"id","jour","source","source_large","lot"}],"refus":[{"jour","raison","n"}],"reste":false}`.

**Purge** : chaque jour à 0 h UTC (déclencheur de `wrangler.toml`), au premier lot du jour et avant chaque relève :
lots, marques de `vus` et refus reçus il y a 14 jours et plus, quotas et sels des jours passés. La borne de 12 jours
sur le jour du lot fait qu'un renvoi venu après l'effacement de sa marque est refusé, jamais gardé une seconde fois.

## Essais

```sh
node --test relais/essais/               # Node 22.13 ou plus, sans wrangler ni paquet npm
python3 outils/relais-schema.py          # détecteur face à texte.rs, schéma face à schema-envoi.json
```

Les essais chargent `worker.js` tel quel, avec une fausse base D1 (`essais/faux-d1.mjs`, sur `node:sqlite`, qui lit
le vrai `schema.sql`) et un faux limiteur. `outils/verifier.sh` lance les deux (étapes `relais` et `relais-schema`).

Plus tard, avant le premier déploiement, l'auteur peut essayer le vrai Worker sur son ordinateur, sans rien envoyer à
Cloudflare : `wrangler dev --local` (puis `curl` vers `http://localhost:8787/v1/lot`).

**Quand le schéma change** (lot A3, `outils/veille/schema-envoi.json`) : `python3 outils/relais-schema.py --ecrire`
le recopie dans `worker.js`, puis les essais disent si `lotValide()` le suit encore. Ne jamais modifier le bloc à la
main.

**Quand le détecteur change** (`src/amelioration/texte.rs`) : recopier ses listes dans le bloc
`MOTIFS DU DÉTECTEUR` de `worker.js` (`outils/relais-schema.py` dit lesquelles diffèrent), porter le changement de
code dans les fonctions du même nom, puis régénérer le corpus commun :

```sh
VANGUARD_CORPUS_RELAIS=relais/essais/corpus-detecteur.json \
  cargo test --locked --bin vanguard corpus_du_relais_identique
node --test relais/essais/
```

Le test Rust exige ce corpus du détecteur en Rust, l'essai Node l'exige du Worker : les deux sonnent pareil.
