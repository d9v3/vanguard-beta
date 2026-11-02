-- La base D1 du relais (plan auto-amélioration, §3 et §4 ; plan de l'envoi, §5). Une fois, chez l'auteur :
--   wrangler d1 execute relais --remote --file relais/schema.sql
-- Ce fichier est aussi sa propre migration : tout y est « IF NOT EXISTS » ou « OR IGNORE », le relancer sur une base
-- déjà créée ajoute ce qui manque sans rien effacer ni rien changer à ce qui est là (relais/LISEZMOI.md, « Mise à
-- jour du relais »).
-- Aucune adresse IP n'y entre : seulement des empreintes HMAC de préfixes, avec un sel effacé chaque jour.
-- `jour` est le jour de réception (UTC, AAAA-MM-JJ) : c'est lui qui borne la garde de 14 jours (P8).

-- Les lots acceptés, en attendant la relève (qui les rend puis les efface). `corps` est le JSON réécrit par le
-- Worker après validation, jamais les octets reçus. `source` : empreinte du /24 (IPv4) ou du /48 (IPv6) ;
-- `source_large` : du /16 ou du /32, pour le seuil des « préfixes distincts » de la lecture chez l'auteur.
CREATE TABLE IF NOT EXISTS lots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  jour TEXT NOT NULL,
  source TEXT NOT NULL,
  source_large TEXT NOT NULL,
  taille INTEGER NOT NULL,
  corps TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS lots_jour ON lots (jour);

-- Les lots déjà reçus, par identifiant d'installation et jour du lot (les champs `installation` et `jour` du lot,
-- pas le jour de réception) : le programme renvoie le même lot s'il est arrêté entre la réponse 2xx et le retrait de
-- sa file. Le second envoi répond 200 sans rien garder ni compter dans les quotas : le premier reçu reste, aucun
-- envoi ne remplace un lot (le relais ne sait pas qui envoie : l'identifiant n'est pas une preuve). La clé primaire
-- est l'index UNIQUE qui tranche entre deux envois simultanés. Ces marques survivent à la relève (qui efface les
-- lots) et partent avec la garde de 14 jours, comptée comme pour les lots depuis le jour de réception (`jour`).
-- Un lot sans identifiant d'installation n'y entre pas : rien ne le distingue d'un autre.
CREATE TABLE IF NOT EXISTS vus (
  installation TEXT NOT NULL,
  jour_lot TEXT NOT NULL,
  jour TEXT NOT NULL,
  PRIMARY KEY (installation, jour_lot)
) STRICT;
CREATE INDEX IF NOT EXISTS vus_jour ON vus (jour);
-- Migration d'une base créée avant `vus` : les lots encore là, reçus par l'ancien Worker, sont marqués (le plus
-- ancien jour de réception d'un doublon déjà gardé). Sur une base neuve ou déjà marquée, cela n'ajoute rien.
INSERT OR IGNORE INTO vus (installation, jour_lot, jour)
  SELECT json_extract(corps, '$.installation'), json_extract(corps, '$.jour'), MIN(jour)
  FROM lots
  WHERE json_type(corps, '$.installation') = 'text' AND json_type(corps, '$.jour') = 'text'
  GROUP BY 1, 2;

-- Lots acceptés du jour par source (« * » : tous) ; effacés le lendemain.
CREATE TABLE IF NOT EXISTS quotas (
  jour TEXT NOT NULL,
  source TEXT NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (jour, source)
) STRICT;

-- Refus comptés par raison et par jour (type, taille, limite, json, schema, secret, jour, plafond, quota, releve),
-- rendus et effacés à la relève : le rapport du matin de l'auteur. « doublon » y compte aussi les lots déjà reçus,
-- répondus 200 mais pas gardés.
CREATE TABLE IF NOT EXISTS refus (
  jour TEXT NOT NULL,
  raison TEXT NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (jour, raison)
) STRICT;

-- Le sel du jour des empreintes ; celui d'hier est effacé au premier lot du jour et par le déclencheur quotidien.
CREATE TABLE IF NOT EXISTS sels (
  jour TEXT PRIMARY KEY,
  sel TEXT NOT NULL
) STRICT;
