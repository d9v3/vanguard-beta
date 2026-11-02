-- La base D1 du relais (plan auto-amélioration, §3 et §4 ; plan de l'envoi, §5). Une fois, chez l'auteur :
--   wrangler d1 execute relais --remote --file relais/schema.sql
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

-- Lots acceptés du jour par source (« * » : tous) ; effacés le lendemain.
CREATE TABLE IF NOT EXISTS quotas (
  jour TEXT NOT NULL,
  source TEXT NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (jour, source)
) STRICT;

-- Refus comptés par raison et par jour (type, taille, limite, json, schema, secret, plafond, quota, releve), rendus
-- et effacés à la relève : le rapport du matin de l'auteur.
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
