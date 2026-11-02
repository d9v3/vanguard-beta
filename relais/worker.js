// Le relais des lots d'amélioration (plan auto-amélioration, §3 et A7 ; plan de l'envoi, §5 et §6) : un Worker de
// Cloudflare qui reçoit le lot du jour de chaque ordinateur, le vérifie, le plafonne et le range dans une base D1,
// jusqu'à ce que l'ordinateur de l'auteur vienne le relever. Il n'agrège rien : la lecture en Rust chez l'auteur
// refait tout et fait foi.
//
// Tout ce qui arrive ici est une donnée hostile. D'où :
// - deux chemins seulement, `POST /v1/lot` et `GET /v1/releve` ; aucune redirection, jamais ;
// - le corps borné à 128 Kio avant d'être lu, le schéma strict (une clé de trop et le lot entier est refusé), puis
//   une copie du détecteur de secrets de `src/amelioration/texte.rs` (deuxième des trois couches) : un lot qui sonne
//   est refusé (422) et compté, jamais gardé ;
// - une clé en double ou un nombre à décimales est refusé, comme en Rust, et le lot gardé est celui que ce Worker
//   réécrit (`JSON.stringify` de ce qu'il a validé), jamais les octets reçus ;
// - aucune réponse au programme ne porte de corps : il ne lit que le code, un relais piraté ne lui fait rien faire ;
// - l'adresse IP n'est jamais gardée : seule une empreinte HMAC de son préfixe (/24 ou /48, et /16 ou /32 pour le
//   seuil des « préfixes distincts » de l'auteur), avec un sel tiré chaque jour et effacé au jour suivant ;
// - aucune ligne de journal (`console`), et les journaux du Worker sont coupés dans wrangler.toml.
//
// Les essais : relais/essais/ (node --test, sans wrangler) ; outils/relais-schema.py compare les motifs du détecteur
// à texte.rs et le schéma à outils/veille/schema-envoi.json.

const TAILLE_MAX = 128 * 1024;
// Lots acceptés par jour, tous ordinateurs confondus (plan, §3) : au-delà, 429 et la raison « plafond » comptée.
const PLAFOND_JOUR = 5000;
// Lots acceptés par jour d'une même source (préfixe /24 ou /48) : un lot par jour et par ordinateur, et une marge
// pour les réseaux partagés. Le limiteur de Cloudflare (10 par minute, wrangler.toml) arrête les rafales avant.
const QUOTA_SOURCE_JOUR = 50;
// Les lots non relevés sont effacés après 14 jours (P8) : un relais piraté n'en détient jamais plus.
const GARDE_JOURS = 14;
// Le jour d'un lot, par rapport au jour de réception (UTC) : 12 jours avant au plus, le lendemain au plus, sinon 422
// (« jour »). Le programme ne garde un lot que 7 jours (src/envoi) et n'envoie que des jours clos de son fuseau. La
// borne d'avant fait tenir le dédoublonnage : la marque d'un lot (`vus`) part 14 jours après sa réception, quand son
// jour est au plus réception + 1, donc 13 jours avant : un renvoi venu après est refusé par cette borne. Celle
// d'après empêche de marquer d'avance les jours à venir d'un identifiant.
const LOT_JOURS_AVANT = 12;
const LOT_JOURS_APRES = 1;
// Un compteur de refus cesse de monter à cette valeur : un déluge de lots refusés n'écrit plus rien dans D1.
const REFUS_MAX = 10000;
// Une relève rend au plus ceci, puis dit qu'il en reste : la mémoire d'un Worker est de 128 Mio.
const RELEVE_OCTETS = 4 * 1024 * 1024;
const RELEVE_LOTS = 1000;
// Un secret de relève plus court est refusé comme absent : il se devinerait.
const SECRET_MIN = 32;

const encodeur = new TextEncoder();

export default {
  async fetch(requete, env) {
    try {
      return await traiter(requete, env);
    } catch {
      // D1 injoignable ou quota de Cloudflare atteint : le programme réessaie dans 24 h (plan de l'envoi, §4).
      return reponse(503);
    }
  },

  // Déclencheur quotidien (wrangler.toml) : les lots de plus de 14 jours, les quotas et le sel d'hier.
  async scheduled(_evenement, env) {
    await purger(env, jourUtc(Date.now()));
  },
};

async function traiter(requete, env) {
  const url = new URL(requete.url);
  // Rien d'autre que les deux chemins exacts, sans paramètre : pas de « / » final toléré, pas de redirection.
  if (url.search !== "" || (url.pathname !== "/v1/lot" && url.pathname !== "/v1/releve")) {
    return reponse(404);
  }
  if (url.pathname === "/v1/lot") {
    return requete.method === "POST" ? recevoir(requete, env) : reponse(405);
  }
  return requete.method === "GET" ? relever(requete, env) : reponse(405);
}

/// Une réponse sans corps : le programme ne lit que le code (plan de l'envoi, §4).
function reponse(statut) {
  return new Response(null, {
    status: statut,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

// --- Réception d'un lot -------------------------------------------------------------------------------------------

async function recevoir(requete, env) {
  const jour = jourUtc(Date.now());
  // Le limiteur avant tout le reste : une rafale de requêtes mal formées s'arrête là comme les autres.
  const { source, large } = await sources(env, requete.headers.get("cf-connecting-ip") ?? "", jour);
  if (env.LIMITEUR && !(await env.LIMITEUR.limit({ key: `lot:${source}` })).success) {
    return refuser(env, jour, "limite", 429);
  }
  const type = (requete.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (type !== "application/json") {
    return refuser(env, jour, "type", 415);
  }
  // Annoncé trop gros : refusé sans rien lire. Sans longueur annoncée, la lecture s'arrête au-delà de la borne.
  const annonce = requete.headers.get("content-length");
  if (annonce !== null && !(/^[0-9]{1,9}$/.test(annonce) && Number(annonce) <= TAILLE_MAX)) {
    return refuser(env, jour, "taille", 413);
  }
  const octets = await lireBorne(requete, TAILLE_MAX);
  if (octets === null) {
    return refuser(env, jour, "taille", 413);
  }
  let lot;
  let texte;
  try {
    texte = new TextDecoder("utf-8", { fatal: true }).decode(octets);
    lot = JSON.parse(texte);
  } catch {
    return refuser(env, jour, "json", 400);
  }
  const verdict = juger(lot, texte);
  if (verdict !== null) {
    return refuser(env, jour, verdict, 422);
  }
  if (!jourAdmis(lot.jour, jour)) {
    return refuser(env, jour, "jour", 422);
  }
  // Déjà reçu (le programme arrêté entre notre 200 et le retrait de sa file) : 200 pour qu'il le retire, rien de
  // gardé, rien de compté dans les quotas. Avant les quotas : une source qui a atteint le sien voit quand même son
  // doublon accepté, sinon elle le renverrait chaque jour jusqu'à la fin de la garde.
  const marque = lot.installation === undefined ? null : [lot.installation, lot.jour];
  if (marque !== null && (await dejaVu(env, marque))) {
    return refuser(env, jour, "doublon", 200);
  }
  // La source d'abord : une source qui a épuisé son quota ne fait plus monter le compte de tous, sinon elle seule
  // finirait par fermer le relais aux autres pour la journée.
  if (!(await compter(env, jour, source, QUOTA_SOURCE_JOUR))) {
    return refuser(env, jour, "quota", 429);
  }
  if (!(await compter(env, jour, "*", PLAFOND_JOUR))) {
    return refuser(env, jour, "plafond", 429);
  }
  const corps = JSON.stringify(lot);
  const garder = env.DB.prepare(
    "INSERT INTO lots (jour, source, source_large, taille, corps) VALUES (?, ?, ?, ?, ?)",
  ).bind(jour, source, large, encodeur.encode(corps).length, corps);
  if (marque === null) {
    await garder.run();
    return reponse(200);
  }
  // La marque et le lot dans une transaction : la clé primaire de `vus` refuse la seconde de deux requêtes
  // simultanées, et son lot part avec elle. Le premier reçu reste ; aucun envoi n'en remplace un autre.
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO vus (installation, jour_lot, jour) VALUES (?, ?, ?)").bind(...marque, jour),
      garder,
    ]);
  } catch (erreur) {
    if (!(await dejaVu(env, marque))) {
      throw erreur;
    }
    // L'autre requête a gagné la course : ce que celle-ci a compté dans les quotas est rendu.
    await env.DB.prepare("UPDATE quotas SET n = n - 1 WHERE jour = ? AND source IN (?, '*') AND n > 0")
      .bind(jour, source)
      .run();
    return refuser(env, jour, "doublon", 200);
  }
  return reponse(200);
}

/// Le jour d'un lot (déjà vérifié au calendrier) entre LOT_JOURS_AVANT jours avant `jour` et LOT_JOURS_APRES après.
function jourAdmis(jourLot, jour) {
  const ecart = (Date.parse(`${jourLot}T00:00:00Z`) - Date.parse(`${jour}T00:00:00Z`)) / 86400000;
  return ecart >= -LOT_JOURS_AVANT && ecart <= LOT_JOURS_APRES;
}

/// Un lot de cette installation et de ce jour a-t-il déjà été reçu (relevé ou non, dans la garde de 14 jours) ?
async function dejaVu(env, [installation, jourLot]) {
  const ligne = await env.DB.prepare("SELECT 1 AS vu FROM vus WHERE installation = ? AND jour_lot = ?")
    .bind(installation, jourLot)
    .first();
  return ligne !== null;
}

/// Le corps, au plus `max` octets ; `null` au-delà (la lecture s'arrête là).
async function lireBorne(requete, max) {
  if (requete.body === null) {
    return new Uint8Array(0);
  }
  const lecteur = requete.body.getReader();
  const morceaux = [];
  let total = 0;
  for (;;) {
    const { done, value } = await lecteur.read();
    if (done) {
      break;
    }
    total += value.length;
    if (total > max) {
      await lecteur.cancel().catch(() => {});
      return null;
    }
    morceaux.push(value);
  }
  const tout = new Uint8Array(total);
  let k = 0;
  for (const m of morceaux) {
    tout.set(m, k);
    k += m.length;
  }
  return tout;
}

/// Monte le compteur du jour d'une source (« * » : tous) s'il est sous `max` ; faux s'il l'a atteint. Une seule
/// requête, atomique : deux lots simultanés ne dépassent pas la borne.
async function compter(env, jour, source, max) {
  const ligne = await env.DB.prepare(
    "INSERT INTO quotas (jour, source, n) VALUES (?, ?, 1) " +
      "ON CONFLICT (jour, source) DO UPDATE SET n = n + 1 WHERE n < ? RETURNING n",
  )
    .bind(jour, source, max)
    .first();
  return ligne !== null;
}

/// Un refus compté par raison et par jour (le rapport du matin de l'auteur : « K refusés, quota atteint ? »), puis
/// la réponse ; un doublon y est compté de même, avec sa réponse 200. Le compteur s'arrête à REFUS_MAX : au-delà,
/// plus aucune ligne n'est écrite.
async function refuser(env, jour, raison, statut) {
  await env.DB.prepare(
    "INSERT INTO refus (jour, raison, n) VALUES (?, ?, 1) " +
      "ON CONFLICT (jour, raison) DO UPDATE SET n = n + 1 WHERE n < ?",
  )
    .bind(jour, raison, REFUS_MAX)
    .run();
  return reponse(statut);
}

// --- Sources : le préfixe de l'adresse, jamais l'adresse --------------------------------------------------------

// Le sel du jour, gardé par l'isolat pour ne pas relire D1 à chaque lot.
let selEnCache = null;

/// Les deux empreintes d'une adresse : la source (/24 en IPv4, /48 en IPv6) et le réseau large (/16, /32), HMAC
/// avec le sel du jour. Le lendemain, rien ne relie plus une empreinte à un préfixe.
async function sources(env, ip, jour) {
  const cle = await selDuJour(env, jour);
  const { etroit, large } = prefixes(ip);
  return { source: await empreinte(cle, `etroit:${etroit}`), large: await empreinte(cle, `large:${large}`) };
}

async function empreinte(cle, texte) {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cle, encodeur.encode(texte)));
  return hex(mac.subarray(0, 16));
}

function hex(octets) {
  return Array.from(octets, (o) => o.toString(16).padStart(2, "0")).join("");
}

/// Le sel du jour : tiré une fois par le premier lot du jour (la base garde le premier tiré si deux isolats le
/// tirent en même temps). Ce premier lot efface aussi le sel d'hier et purge les vieux lots : la garde de 14 jours
/// tient même si le déclencheur quotidien n'était pas réglé.
async function selDuJour(env, jour) {
  if (selEnCache?.jour === jour) {
    return selEnCache.cle;
  }
  const tire = hex(crypto.getRandomValues(new Uint8Array(32)));
  const pose = await env.DB.prepare("INSERT OR IGNORE INTO sels (jour, sel) VALUES (?, ?)").bind(jour, tire).run();
  if (pose.meta?.changes === 1) {
    await purger(env, jour);
  }
  const ligne = await env.DB.prepare("SELECT sel FROM sels WHERE jour = ?").bind(jour).first();
  const cle = await crypto.subtle.importKey("raw", encodeur.encode(ligne.sel), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  selEnCache = { jour, cle };
  return cle;
}

/// Les préfixes d'une adresse : « a.b.c » et « a.b » en IPv4 ; les trois et les deux premiers groupes en IPv6. Une
/// adresse illisible (absente en essai local) compte comme une seule source.
function prefixes(ip) {
  const v4 = /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/.exec(ip);
  if (v4 && v4.slice(1).every((o) => Number(o) <= 255)) {
    const o = v4.slice(1).map(Number);
    return { etroit: `4:${o[0]}.${o[1]}.${o[2]}`, large: `4:${o[0]}.${o[1]}` };
  }
  const g = groupesIpv6(ip);
  if (g === null) {
    return { etroit: "inconnue", large: "inconnue" };
  }
  // ::ffff:a.b.c.d est une adresse IPv4.
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    const o = [g[6] >> 8, g[6] & 255, g[7] >> 8];
    return { etroit: `4:${o[0]}.${o[1]}.${o[2]}`, large: `4:${o[0]}.${o[1]}` };
  }
  return { etroit: `6:${g.slice(0, 3).join(":")}`, large: `6:${g.slice(0, 2).join(":")}` };
}

/// Les huit groupes d'une adresse IPv6 (« :: » développé, IPv4 finale comprise), ou `null`.
function groupesIpv6(ip) {
  if (!/^[0-9A-Fa-f:.]{2,45}$/.test(ip) || ip.split("::").length > 2) {
    return null;
  }
  const lire = (partie) => {
    if (partie === "") {
      return [];
    }
    const morceaux = partie.split(":");
    const sortie = [];
    for (const [k, m] of morceaux.entries()) {
      if (k === morceaux.length - 1 && m.includes(".")) {
        const v4 = /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/.exec(m);
        if (!v4 || v4.slice(1).some((o) => Number(o) > 255)) {
          return null;
        }
        const o = v4.slice(1).map(Number);
        sortie.push((o[0] << 8) | o[1], (o[2] << 8) | o[3]);
      } else if (/^[0-9A-Fa-f]{1,4}$/.test(m)) {
        sortie.push(parseInt(m, 16));
      } else {
        return null;
      }
    }
    return sortie;
  };
  const [tete, queue] = ip.split("::");
  const a = lire(tete);
  const b = queue === undefined ? [] : lire(queue);
  if (a === null || b === null) {
    return null;
  }
  if (queue === undefined) {
    return a.length === 8 ? a : null;
  }
  const manque = 8 - a.length - b.length;
  return manque >= 1 ? [...a, ...new Array(manque).fill(0), ...b] : null;
}

// --- Relève par l'ordinateur de l'auteur ----------------------------------------------------------------------

async function relever(requete, env) {
  const jour = jourUtc(Date.now());
  if (!(await secretBon(requete.headers.get("authorization"), env.SECRET_RELEVE))) {
    // Un essai raté consomme le limiteur : deviner le secret en rafale n'est pas possible (il ne se devine pas de
    // toute façon). Le refus est compté, l'auteur le voit au matin.
    const { source } = await sources(env, requete.headers.get("cf-connecting-ip") ?? "", jour);
    if (env.LIMITEUR && !(await env.LIMITEUR.limit({ key: `releve:${source}` })).success) {
      return refuser(env, jour, "releve", 429);
    }
    return refuser(env, jour, "releve", 401);
  }
  await purger(env, jour);
  const tailles = await env.DB.prepare("SELECT id, taille FROM lots ORDER BY id LIMIT ?").bind(RELEVE_LOTS).all();
  const lignes = tailles.results ?? [];
  let pris = 0;
  let octets = 0;
  while (pris < lignes.length && (pris === 0 || octets + lignes[pris].taille <= RELEVE_OCTETS)) {
    octets += lignes[pris].taille;
    pris += 1;
  }
  // Lots et refus lus puis effacés dans une seule transaction : une panne au milieu n'efface rien. Les identifiants
  // croissent (AUTOINCREMENT, jamais réemployés) : un lot arrivé entre-temps est hors de l'intervalle effacé.
  const premier = pris > 0 ? lignes[0].id : 0;
  const dernier = pris > 0 ? lignes[pris - 1].id : -1;
  const [lus, , refus] = await env.DB.batch([
    env.DB.prepare(
      "SELECT id, jour, source, source_large, corps FROM lots WHERE id BETWEEN ? AND ? ORDER BY id",
    ).bind(premier, dernier),
    env.DB.prepare("DELETE FROM lots WHERE id BETWEEN ? AND ?").bind(premier, dernier),
    env.DB.prepare("SELECT jour, raison, n FROM refus ORDER BY jour, raison"),
    env.DB.prepare("DELETE FROM refus"),
  ]);
  const lots = lus.results ?? [];
  // Le corps de chaque lot est déjà le JSON réécrit par ce Worker : recopié tel quel, sans le relire.
  const morceaux = lots.map(
    (l) =>
      `{"id":${Number(l.id)},"jour":${JSON.stringify(l.jour)},"source":${JSON.stringify(l.source)},` +
      `"source_large":${JSON.stringify(l.source_large)},"lot":${l.corps}}`,
  );
  const reste = pris < lignes.length || lignes.length === RELEVE_LOTS;
  const corps = `{"releve":1,"lots":[${morceaux.join(",")}],"refus":${JSON.stringify(refus.results ?? [])},"reste":${reste}}`;
  return new Response(corps, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

/// L'en-tête « Authorization: Bearer <secret> » comparé au secret du Worker en temps constant : les deux passent par
/// SHA-256 (même longueur, quelle que soit celle de l'essai), puis chaque octet est comparé sans sortie anticipée.
/// Un secret absent ou trop court ne laisse jamais relever.
async function secretBon(entete, secret) {
  if (typeof secret !== "string" || secret.length < SECRET_MIN || typeof entete !== "string") {
    return false;
  }
  const donne = entete.startsWith("Bearer ") ? entete.slice(7) : "";
  const [a, b] = await Promise.all(
    [donne, secret].map(async (s) => new Uint8Array(await crypto.subtle.digest("SHA-256", encodeur.encode(s)))),
  );
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(a, b) && donne.length > 0;
  }
  let ecart = 0;
  for (let k = 0; k < a.length; k += 1) {
    ecart |= a[k] ^ b[k];
  }
  return ecart === 0 && donne.length > 0;
}

/// Efface ce qui a passé sa garde : les lots reçus il y a 14 jours ou plus (P8) et leurs marques de doublon, les
/// quotas et les sels des jours passés (E4 : le sel d'hier n'existe plus), les refus de plus de 14 jours.
async function purger(env, jour) {
  const limite = jourUtc(Date.parse(`${jour}T00:00:00Z`) - GARDE_JOURS * 86400000);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM lots WHERE jour <= ?").bind(limite),
    env.DB.prepare("DELETE FROM vus WHERE jour <= ?").bind(limite),
    env.DB.prepare("DELETE FROM quotas WHERE jour < ?").bind(jour),
    env.DB.prepare("DELETE FROM sels WHERE jour < ?").bind(jour),
    env.DB.prepare("DELETE FROM refus WHERE jour <= ?").bind(limite),
  ]);
  if (selEnCache !== null && selEnCache.jour < jour) {
    selEnCache = null;
  }
}

function jourUtc(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

// --- Le schéma du lot ------------------------------------------------------------------------------------------

/// `null` si le lot est accepté, sinon la raison du refus : « secret » (le détecteur sonne sur un champ de la voie
/// ouverte, compté à part : c'est une fuite que la première couche, en Rust, a laissée passer) ou « schema ». Tout
/// le lot est parcouru pour qu'un secret soit compté comme tel même s'il y a aussi une faute de forme. `texte` est le
/// corps reçu : une clé en double ou un nombre à décimales, que JSON.parse laisse passer, y est refusé comme en Rust.
function juger(lot, texte) {
  const etat = { schema: false, secret: false };
  verifier(lot, SCHEMA, etat);
  if (texte !== undefined && !formeBrute(texte)) {
    etat.schema = true;
  }
  if (etat.secret || etat.schema) {
    return etat.secret ? "secret" : "schema";
  }
  // Un lot qui a passé le schéma est peu profond : la réécriture ne peut pas déborder la pile.
  return encodeur.encode(JSON.stringify(lot)).length > SCHEMA["x-lot-octets-max"] ? "schema" : null;
}

/// Ce que ce relais vérifie en plus du schéma, d'après « x-verifie-en-rust », pour les définitions nommées ici : le
/// jour qui existe au calendrier, et pour la voie ouverte (« x-voie ») ce que le nettoyage de texte.rs laisse
/// toujours. Une définition de la voie ouverte absente d'ici refuse tout lot qui l'emploie (outils/relais-schema.py
/// le signale avant). JSON strict, lu par ce script.
const EN_PLUS = { "Jour": "jour", "TexteNettoye": "texte", "NomLogiciel": "nom", "VersionTierce": "version" };

/// Le nœud au bout des `$ref`, et le nom de la dernière définition traversée. À côté d'un `$ref`, seules des
/// annotations (outils/relais-schema.py le vérifie).
function resoudre(noeud) {
  let n = noeud;
  let nom = null;
  while (n.$ref !== undefined) {
    nom = n.$ref.replace(/^#\/\$defs\//, "");
    if (!Object.hasOwn(SCHEMA.$defs, nom)) {
      throw new Error(`référence inconnue : ${n.$ref}`);
    }
    n = SCHEMA.$defs[nom];
  }
  return { n, nom };
}

function genre(v) {
  if (v === null) {
    return "null";
  }
  if (Array.isArray(v)) {
    return "array";
  }
  if (typeof v === "number") {
    return Number.isInteger(v) ? "integer" : "number";
  }
  return typeof v;
}

const motifs = new Map();
function motif(source) {
  if (!motifs.has(source)) {
    motifs.set(source, new RegExp(source, "u"));
  }
  return motifs.get(source);
}

/// Le sous-ensemble de JSON Schema qu'emploie outils/veille/schema-envoi.json : `type`, `const`, `enum`, `pattern`,
/// bornes de longueur, de valeur et de taille, `properties` avec `required` et rien d'autre, `minProperties`,
/// `items`, `$ref` ; et ses mots-clés maison `x-octets-max`, `x-cle-unique` et `x-voie`. Tout autre mot-clé est
/// signalé par outils/relais-schema.py. Un objet est toujours fermé : une clé de trop refuse le lot.
function verifier(v, noeud, etat) {
  const { n, nom } = resoudre(noeud);
  const plus = nom !== null && Object.hasOwn(EN_PLUS, nom) ? EN_PLUS[nom] : null;
  if (n["x-voie"] !== undefined) {
    // Trop long : refusé sans passer par le détecteur, dont le temps de calcul croît avec le texte (128 Kio d'un
    // seul champ dépasseraient les 10 ms d'un Worker gratuit).
    if (typeof v === "string" && n["x-octets-max"] !== undefined && encodeur.encode(v).length > n["x-octets-max"]) {
      etat.schema = true;
      return;
    }
    // Puis le détecteur : un secret est compté comme tel, même dans un texte par ailleurs mal formé.
    if (typeof v === "string" && alertes(v) > 0) {
      etat.secret = true;
      return;
    }
    if (n["x-voie"] !== "ouverte" || (plus !== "texte" && plus !== "nom" && plus !== "version")) {
      etat.schema = true;
      return;
    }
  }
  if (n.const !== undefined && v !== n.const) {
    etat.schema = true;
    return;
  }
  if (n.enum !== undefined && !n.enum.some((x) => x === v)) {
    etat.schema = true;
    return;
  }
  if (n.type !== undefined && genre(v) !== n.type) {
    etat.schema = true;
    return;
  }
  if (typeof v === "string") {
    const longueur = Array.from(v).length;
    if (
      (n.maxLength !== undefined && longueur > n.maxLength) ||
      (n.minLength !== undefined && longueur < n.minLength) ||
      (n["x-octets-max"] !== undefined && encodeur.encode(v).length > n["x-octets-max"]) ||
      (n.pattern !== undefined && !motif(n.pattern).test(v)) ||
      (plus === "jour" && !dateExiste(v)) ||
      ((plus === "texte" || plus === "nom" || plus === "version") && !ouvertBon(v, plus))
    ) {
      etat.schema = true;
    }
  } else if (typeof v === "number") {
    if ((n.minimum !== undefined && v < n.minimum) || (n.maximum !== undefined && v > n.maximum)) {
      etat.schema = true;
    }
  } else if (Array.isArray(v)) {
    // Trop long : refusé sans regarder les éléments, le temps de calcul reste borné.
    if ((n.maxItems !== undefined && v.length > n.maxItems) || (n.minItems !== undefined && v.length < n.minItems)) {
      etat.schema = true;
      return;
    }
    if (n.items !== undefined) {
      for (const x of v) {
        verifier(x, n.items, etat);
      }
    }
    if (n["x-cle-unique"] !== undefined && !cleUnique(v, n["x-cle-unique"])) {
      etat.schema = true;
    }
  } else if (v !== null && typeof v === "object") {
    const proprietes = n.properties ?? {};
    for (const cle of n.required ?? []) {
      if (!Object.hasOwn(v, cle)) {
        etat.schema = true;
      }
    }
    const cles = Object.keys(v);
    if (n.minProperties !== undefined && cles.length < n.minProperties) {
      etat.schema = true;
    }
    for (const cle of cles) {
      // `Object.hasOwn` : « constructor » ou « __proto__ » ne trouvent rien dans le prototype du schéma.
      if (!Object.hasOwn(proprietes, cle)) {
        etat.schema = true;
      } else {
        verifier(v[cle], proprietes[cle], etat);
      }
    }
  }
}

/// « x-cle-unique » : deux entrées ne partagent jamais les valeurs de ces champs, un champ absent comptant comme une
/// valeur (schema-envoi.json). Une entrée qui n'est pas un objet est déjà refusée par `items`.
function cleUnique(tableau, champs) {
  const vues = new Set();
  for (const x of tableau) {
    if (x === null || typeof x !== "object") {
      continue;
    }
    const cle = JSON.stringify(champs.map((c) => (Object.hasOwn(x, c) ? [x[c]] : [])));
    if (vues.has(cle)) {
      return false;
    }
    vues.add(cle);
  }
  return true;
}

/// Le corps reçu, déjà lu sans erreur par JSON.parse : aucune clé deux fois dans un même objet (JSON.parse garde la
/// dernière sans rien dire, la première n'aurait pas été vérifiée), aucun nombre à décimales ou à exposant (le schéma
/// n'a que des entiers, que Rust refuse écrits « 1.0 »). Une lecture à plat, sans récursion : la profondeur ne coûte
/// rien.
function formeBrute(texte) {
  const pile = [];
  let i = 0;
  while (i < texte.length) {
    const x = texte[i];
    if (x === '"') {
      let fin = i + 1;
      while (texte[fin] !== '"') {
        fin += texte[fin] === "\\" ? 2 : 1;
      }
      const haut = pile[pile.length - 1];
      if (haut !== undefined && haut.attendCle) {
        // La clé décodée : « a » et « a » sont la même.
        const cle = JSON.parse(texte.slice(i, fin + 1));
        if (haut.cles.has(cle)) {
          return false;
        }
        haut.cles.add(cle);
        haut.attendCle = false;
      }
      i = fin + 1;
    } else if (x === "{") {
      pile.push({ cles: new Set(), attendCle: true });
      i += 1;
    } else if (x === "[") {
      pile.push({ cles: null, attendCle: false });
      i += 1;
    } else if (x === "}" || x === "]") {
      pile.pop();
      i += 1;
    } else if (x === ",") {
      const haut = pile[pile.length - 1];
      if (haut !== undefined && haut.cles !== null) {
        haut.attendCle = true;
      }
      i += 1;
    } else if (x === "-" || (x >= "0" && x <= "9")) {
      let fin = i + 1;
      while (fin < texte.length && /[0-9.eE+-]/.test(texte[fin])) {
        fin += 1;
      }
      if (/[.eE]/.test(texte.slice(i, fin))) {
        return false;
      }
      i = fin;
    } else {
      i += 1;
    }
  }
  return true;
}

function dateExiste(s) {
  const t = Date.parse(`${s}T00:00:00Z`);
  return !Number.isNaN(t) && jourUtc(t) === s;
}

/// Un champ de la voie ouverte (texte d'erreur, nom de logiciel, version tierce), après le détecteur et le motif du
/// schéma : ce que le nettoyage de texte.rs laisse toujours (caractères permis, sans espace au bord ni double, assez
/// de lettres, écritures non mêlées, et pour une version pas trop de lettres).
function ouvertBon(v, sorte) {
  const c = Array.from(v);
  const lettres = c.filter(alpha).length;
  const visibles = c.filter((x) => !blanc(x)).length;
  const bon =
    v.length > 0 &&
    sortiePermise(v) &&
    v.trim() === v &&
    !v.includes("  ") &&
    !v.split(/\p{White_Space}/u).some(melees);
  if (sorte === "texte") {
    return bon && encodeur.encode(v).length <= DETECTEUR.bornes.texte && lettres * 2 >= visibles;
  }
  if (sorte === "nom") {
    return bon && encodeur.encode(v).length <= DETECTEUR.bornes.nom && lettres > 0;
  }
  return (
    bon &&
    encodeur.encode(v).length <= DETECTEUR.bornes.version &&
    /^[0-9][0-9A-Za-z.+_:-]*$/.test(v) &&
    !/[.+_:-]$/.test(v) &&
    lettresDeVersion(v)
  );
}

/// Au plus 10 lettres de suite et 16 en tout (texte.rs, `lettres_de_version`).
function lettresDeVersion(s) {
  let suite = 0;
  let total = 0;
  for (const x of s) {
    if (/[A-Za-z]/.test(x)) {
      suite += 1;
      total += 1;
      if (suite > 10 || total > 16) {
        return false;
      }
    } else {
      suite = 0;
    }
  }
  return true;
}

/// Un mot qui mêle des lettres latines à des lettres grecques ou cyrilliques (texte.rs, `ecritures_melees`).
function melees(mot) {
  const c = Array.from(mot).map((x) => x.codePointAt(0));
  const latin = (p) =>
    (p >= 0x41 && p <= 0x5a) || (p >= 0x61 && p <= 0x7a) || (p >= 0xc0 && p <= 0x24f) || (p >= 0x1e00 && p <= 0x1eff);
  const autre = (p) => (p >= 0x370 && p <= 0x3ff) || (p >= 0x400 && p <= 0x52f) || (p >= 0x1f00 && p <= 0x1fff);
  return c.some(latin) && c.some(autre);
}

// ==== DÉBUT DU SCHÉMA DU LOT ====================================================================================
// Le lot de schéma 2 : la copie exacte de outils/veille/schema-envoi.json (lot A3), qui fait foi. Ne pas le modifier
// à la main : `python3 outils/relais-schema.py --ecrire` le recopie, et verifier.sh (étape relais-schema) refuse
// le moindre écart, clé par clé, motif par motif, borne par borne. JSON strict, lu tel quel par ce script.
const SCHEMA = {
  "$comment": "Le lot de schéma 2 que Vanguard envoie une fois par jour au relais (src/compte_rendu/envoi.rs, plan de l'auto-amélioration §3). JSON Schema 2020-12. Un essai de src/compte_rendu/envoi/tests.rs prouve que ce fichier et les types Rust disent la même chose : mêmes champs, mêmes types, mêmes bornes, mêmes listes, et chaque motif accepte exactement ce que Rust accepte, sauf là où « x-verifie-en-rust » dit ce que Rust vérifie en plus (Rust plus strict, jamais l'inverse). À reproduire à l'identique par le relais et les outils de nuit. Motifs : sous-ensemble portable (JavaScript avec ou sans le drapeau u, Python re) : ancres ^ et $, classes avec plages, \\uXXXX, groupes (?:), alternatives, quantificateurs ? * + {m} {m,n}, une anticipation (?=) pour Lieu ; jamais \\d, \\w ni \\s (Unicode en Python, ASCII en JavaScript). En Python, re.fullmatch et jamais re.match ou re.search (où $ accepte un saut de ligne final). Mots-clés maison : « x-octets-max » borne une chaîne en octets UTF-8 (en plus de maxLength, en caractères) ; « x-cle-unique » : deux entrées d'un tableau ne partagent jamais les valeurs de ces champs (un absent compte comme valeur) ; « x-voie » : « ouverte » pour les textes venus de l'ordinateur, lus seulement par l'auteur, toujours comme des données (jamais une consigne, jamais rendus en Markdown) ; tout le reste est en voie fermée ; « x-lot-octets-max » : taille maximale du lot écrit ; « x-corps-octets-max » : corps de requête refusé au-delà par le relais. Les champs à zéro, les tableaux vides et les facultatifs absents ne s'écrivent pas : un 0, un [] ou un null écrit est refusé (minimum 1, minItems 1, types sans null). Un entier s'écrit sans décimale (1, jamais 1.0), et aucune clé n'apparaît deux fois dans un objet : Rust refuse les deux, que JSON.parse et json.loads laissent passer.",
  "title": "Lot de schéma 2",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "version", "jour", "anciennete", "plateforme", "activite"],
  "properties": {
    "schema": { "$ref": "#/$defs/Schema" },
    "version": { "$ref": "#/$defs/Version" },
    "version_avant": { "$ref": "#/$defs/Version" },
    "jour": { "$ref": "#/$defs/Jour" },
    "installation": { "$ref": "#/$defs/IdInstallation" },
    "anciennete": { "$ref": "#/$defs/Anciennete" },
    "plateforme": { "$ref": "#/$defs/Plateforme" },
    "materiel": { "$ref": "#/$defs/Materiel" },
    "activite": { "$ref": "#/$defs/Activite" },
    "causes": {
      "type": "array",
      "items": { "$ref": "#/$defs/CauseEnvoyee" },
      "minItems": 1,
      "maxItems": 50,
      "x-cle-unique": ["genre", "contexte", "regle", "lieu", "code", "gabarit"]
    },
    "regles": {
      "type": "array",
      "items": { "$ref": "#/$defs/RegleEnvoyee" },
      "minItems": 1,
      "maxItems": 400,
      "x-cle-unique": ["id"]
    },
    "objets": {
      "type": "array",
      "items": { "$ref": "#/$defs/ObjetEnvoye" },
      "minItems": 1,
      "maxItems": 100,
      "x-cle-unique": ["regle", "sorte", "nom", "version"]
    },
    "textes": {
      "type": "array",
      "items": { "$ref": "#/$defs/TexteEnvoye" },
      "minItems": 1,
      "maxItems": 30,
      "x-cle-unique": ["gabarit", "contexte", "regle"]
    },
    "corrections": {
      "type": "array",
      "items": { "$ref": "#/$defs/Correction" },
      "minItems": 1,
      "maxItems": 100,
      "x-cle-unique": ["regle"]
    },
    "choix": {
      "type": "array",
      "items": { "$ref": "#/$defs/Choix" },
      "minItems": 1,
      "maxItems": 100,
      "x-cle-unique": ["regle"]
    },
    "outils": {
      "type": "array",
      "items": { "$ref": "#/$defs/OutilEnvoye" },
      "minItems": 1,
      "maxItems": 80,
      "x-cle-unique": ["outil", "origine"]
    },
    "cache": {
      "type": "array",
      "items": { "$ref": "#/$defs/CacheRegle" },
      "minItems": 1,
      "maxItems": 200,
      "x-cle-unique": ["regle"]
    },
    "reglages": {
      "type": "array",
      "items": { "$ref": "#/$defs/Reglage" },
      "minItems": 1,
      "maxItems": 50,
      "x-cle-unique": ["levier", "regle"]
    },
    "refus_locaux": { "type": "integer", "minimum": 1, "maximum": 1000000 },
    "retires": { "$ref": "#/$defs/Retires" }
  },
  "x-lot-octets-max": 98304,
  "x-corps-octets-max": 131072,
  "$defs": {
    "Schema": { "type": "integer", "const": 2 },
    "Version": {
      "type": "string",
      "pattern": "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
      "description": "Version de Vanguard."
    },
    "Jour": {
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
      "description": "AAAA-MM-JJ, jamais l'heure.",
      "x-verifie-en-rust": "le jour existe au calendrier (pas de 2026-02-30)"
    },
    "IdInstallation": {
      "type": "string",
      "pattern": "^[0-9a-f]{16}$",
      "description": "Identifiant d'installation tiré au hasard, renouvelé tous les 90 jours (plan, P1)."
    },
    "Anciennete": {
      "type": "string",
      "enum": ["moins-7-jours", "moins-30-jours", "moins-90-jours", "90-jours-et-plus"]
    },
    "FamilleFine": {
      "type": "string",
      "enum": [
        "windows-10", "windows-11", "macos", "arch", "debian", "ubuntu", "fedora", "opensuse", "mint", "linux-autre"
      ]
    },
    "SystemeVersion": {
      "type": "string",
      "pattern": "^[0-9]{1,6}(?:\\.[0-9]{1,3})?$",
      "description": "Build de Windows, majeure de macOS, majeur.mineur du noyau Linux."
    },
    "Arch": {
      "type": "string",
      "enum": ["x86_64", "aarch64"]
    },
    "Langue": {
      "type": "string",
      "enum": ["fr", "en"]
    },
    "Edition": {
      "type": "string",
      "enum": ["home", "pro", "entreprise", "serveur"]
    },
    "Processeur": {
      "type": "string",
      "enum": ["intel", "amd", "apple", "qualcomm", "autre"]
    },
    "MemoireGo": {
      "type": "integer",
      "enum": [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096],
      "description": "Go, arrondis à une puissance de 2."
    },
    "Disque": {
      "type": "string",
      "enum": ["nvme", "ssd", "hdd", "inconnu"]
    },
    "Virtuelle": {
      "type": "string",
      "enum": ["aucune", "hyperv", "kvm", "vmware", "virtualbox", "parallels", "wsl", "autre"]
    },
    "TroisEtats": {
      "type": "string",
      "enum": ["oui", "non", "inconnu"]
    },
    "Graphique": {
      "type": "string",
      "enum": ["nvidia", "amd", "intel", "apple", "qualcomm", "autre", "aucune"]
    },
    "Sorte": {
      "type": "string",
      "enum": ["programme", "service", "pilote", "paquet", "unite", "flatpak", "module"]
    },
    "Etat": {
      "type": "string",
      "enum": ["probleme", "sain", "non-verifie"]
    },
    "Origine": {
      "type": "string",
      "enum": ["menu", "ligne"]
    },
    "Levier": {
      "type": "string",
      "enum": ["delai", "duree-cache", "cache-coupe", "second-essai", "reserve-fils", "correction-fragile"]
    },
    "Genre": {
      "type": "string",
      "enum": [
        "plantage", "rattrapee", "impossible", "echec", "erreur", "contredite", "invariant", "ecriture",
        "hors-delai", "muette", "lente", "frole-delai", "lenteur"
      ]
    },
    "Contexte": {
      "type": "string",
      "enum": [
        "mes-ordinateurs", "erreur-interne", "plantage", "autotest", "verification-impossible", "scan-reseau",
        "audit-reseau", "protection-relro", "scan-reseau-non-verifie", "vanguard-administrateur",
        "correction-elevee", "powershell", "wmi", "origine-programme", "protection-cle", "windows-update",
        "taches-planifiees", "bitlocker", "pare-feu-windows", "reseaux", "echec/autre", "annulation/remettre",
        "audit/pq-box", "audit/tls-pq", "autotest/cache", "autotest/dernier", "bilan/pqc-ssh", "bilan/pqc-sshd",
        "bilan/sshd-config", "blocage/pare-feu", "blocage/preparer", "blocage/regler", "canaux/lire",
        "compte-rendu/lire", "compte-rendu/trier", "changements/noter", "dbus/actions", "dbus/etat_d_activite",
        "dns/resolved", "docker", "entretien/etat", "essai", "essai/lecture", "evenements/noter",
        "evenements/perdus", "evenements/version", "examens/ecrire", "http_unix", "http_unix/connexion",
        "machine/ports-bloques", "maj/fwupd", "manifeste/image", "manifeste/relire", "networkmanager",
        "plateforme/fwupd", "plugins/ecrire", "plugins/reglages", "plugins/sceau", "programmes_poses/noter",
        "quarantaine/remettre", "quarantaine/supprimer", "quarantaine/traces", "reseau/appareils", "reseau/carnet",
        "reseau/resolved", "sceau/adopter", "sceau/ecrire", "sceau/temoin", "signaler/controle", "signaler/dossier",
        "signaler/droits", "signaler/ecrire", "signaler/effacer", "signaler/incident", "signaler/langue",
        "signaler/outil", "signaler/programme", "systemd", "veilleur/oublier", "voulues/noter",
        "wifi/networkmanager"
      ]
    },
    "Regle": { "type": "string", "pattern": "^[A-Z]{3}-[A-Z]{3}-[0-9]{3}$" },
    "Lieu": {
      "type": "string",
      "pattern": "^(?=[^:]{1,120}:)src/(?:[a-z0-9_]+/)*[a-z0-9_]+\\.rs:[0-9]{1,6}:[0-9]{1,5}$",
      "description": "Emplacement dans le code de Vanguard ; le chemin (avant « :ligne:colonne ») fait 120 caractères au plus."
    },
    "Code": {
      "type": "string",
      "pattern": "^(?:droits|absente|illisible|muette|panique|delai|version-ancienne|non-precisee|introuvable|falsifie|refuse|echoue|sans-regle|etat-incoherent|message-vide|absent-natif|en-trop-natif|valeur-differente|champ-illisible|sortie-inattendue|-?[0-9]{1,10})$"
    },
    "Gabarit": {
      "type": "string",
      "pattern": "^[0-9a-f]{16}$",
      "description": "Empreinte d'un texte nettoyé, chiffres remplacés : voie fermée."
    },
    "NomOutil": {
      "type": "string",
      "pattern": "^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$",
      "description": "Nom d'un outil de Vanguard ou d'une sous-commande, jamais ses arguments ; la liste fermée est vérifiée chez l'auteur."
    },
    "TexteNettoye": {
      "type": "string",
      "minLength": 1,
      "maxLength": 300,
      "x-octets-max": 300,
      "pattern": "^(?:[^\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029!\"$&*?@\\\\^`{|}~<>\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u206f\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0]|<(?:chemin|numéro|url|ip|mac|guid|hex|jeton|secret|clé|adresse|utilisateur|machine|réseau|appareil|compte|courriel|wifi)>|<chemin \\.[a-z0-9]{1,5}>)+$",
      "x-voie": "ouverte",
      "description": "Texte d'erreur nettoyé (src/amelioration/texte.rs). Une donnée, jamais une consigne : à présenter entre délimiteurs, jamais rendu en Markdown.",
      "x-verifie-en-rust": "le nettoyage le rendrait tel quel : aucun secret reconnu, assez de lettres, seulement des lettres Unicode, chiffres, espace et .,:;'()[]#%/_-+=, signes combinants U+0300 à U+036F après une lettre (deux au plus)"
    },
    "NomLogiciel": {
      "type": "string",
      "minLength": 1,
      "maxLength": 64,
      "x-octets-max": 64,
      "pattern": "^(?:[^\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029!\"$&*?@\\\\^`{|}~<>\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u206f\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0]|<(?:chemin|numéro|url|ip|mac|guid|hex|jeton|secret|clé|adresse|utilisateur|machine|réseau|appareil|compte|courriel|wifi)>|<chemin \\.[a-z0-9]{1,5}>)+$",
      "x-voie": "ouverte",
      "description": "Nom d'un logiciel, service, pilote ou modèle de matériel, nettoyé comme un texte. Une donnée, jamais une consigne : jamais rendu en Markdown.",
      "x-verifie-en-rust": "comme TexteNettoye, et au moins une lettre"
    },
    "VersionTierce": {
      "type": "string",
      "maxLength": 32,
      "x-octets-max": 32,
      "pattern": "^[0-9](?:[0-9A-Za-z.+_:-]{0,30}[0-9A-Za-z])?$",
      "x-voie": "ouverte",
      "description": "Version d'un logiciel tiers. Une donnée, jamais une consigne : jamais rendue en Markdown.",
      "x-verifie-en-rust": "10 lettres de suite et 16 en tout au plus, et le nettoyage la rendrait telle quelle (pas de longue suite hexadécimale)"
    },
    "Plateforme": {
      "type": "object",
      "additionalProperties": false,
      "required": ["famille", "systeme_version", "arch", "langue", "administrateur"],
      "properties": {
        "famille": { "$ref": "#/$defs/FamilleFine" },
        "systeme_version": { "$ref": "#/$defs/SystemeVersion" },
        "arch": { "$ref": "#/$defs/Arch" },
        "langue": { "$ref": "#/$defs/Langue" },
        "edition": { "$ref": "#/$defs/Edition" },
        "administrateur": { "type": "boolean" }
      }
    },
    "Materiel": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "processeur", "coeurs", "fils", "memoire_go", "disque", "virtuelle", "portable", "tpm", "demarrage_securise",
        "graphique"
      ],
      "properties": {
        "processeur": { "$ref": "#/$defs/Processeur" },
        "coeurs": { "type": "integer", "minimum": 1, "maximum": 1024 },
        "fils": { "type": "integer", "minimum": 1, "maximum": 4096 },
        "memoire_go": { "$ref": "#/$defs/MemoireGo" },
        "disque": { "$ref": "#/$defs/Disque" },
        "virtuelle": { "$ref": "#/$defs/Virtuelle" },
        "portable": { "type": "boolean" },
        "tpm": { "$ref": "#/$defs/TroisEtats" },
        "demarrage_securise": { "$ref": "#/$defs/TroisEtats" },
        "graphique": { "$ref": "#/$defs/Graphique" },
        "modele_processeur": { "$ref": "#/$defs/NomLogiciel" },
        "modele_graphique": { "$ref": "#/$defs/NomLogiciel" }
      }
    },
    "Activite": {
      "type": "object",
      "additionalProperties": false,
      "required": ["surveillance", "veilleur", "cle"],
      "properties": {
        "bilans_manuels": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "passes_horaires": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "surveillance": { "type": "boolean" },
        "veilleur": { "type": "boolean" },
        "cle": { "type": "boolean" }
      }
    },
    "CauseEnvoyee": {
      "type": "object",
      "additionalProperties": false,
      "required": ["genre", "contexte", "n"],
      "properties": {
        "genre": { "$ref": "#/$defs/Genre" },
        "contexte": { "$ref": "#/$defs/Contexte" },
        "regle": { "$ref": "#/$defs/Regle" },
        "lieu": { "$ref": "#/$defs/Lieu" },
        "code": { "$ref": "#/$defs/Code" },
        "n": { "type": "integer", "minimum": 1, "maximum": 1000 },
        "duree_ms": { "type": "integer", "minimum": 1, "maximum": 86400000 },
        "en_plus": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "en_moins": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "differents": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "gabarit": { "$ref": "#/$defs/Gabarit" }
      }
    },
    "RegleEnvoyee": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "n", "delai_s"],
      "properties": {
        "id": { "$ref": "#/$defs/Regle" },
        "n": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "med_ms": { "type": "integer", "minimum": 1, "maximum": 86400000 },
        "p90_ms": { "type": "integer", "minimum": 1, "maximum": 86400000 },
        "hors_delai": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "problemes": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "sains": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "non_verifies": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "raisons": {
          "type": "array",
          "items": { "$ref": "#/$defs/RaisonNombre" },
          "minItems": 1,
          "maxItems": 4,
          "x-cle-unique": ["code"]
        },
        "delai_s": { "type": "integer", "minimum": 1, "maximum": 86400 }
      }
    },
    "RaisonNombre": {
      "type": "object",
      "additionalProperties": false,
      "required": ["code", "n"],
      "properties": {
        "code": { "$ref": "#/$defs/Code" },
        "n": { "type": "integer", "minimum": 1, "maximum": 1000000 }
      }
    },
    "ObjetEnvoye": {
      "type": "object",
      "additionalProperties": false,
      "required": ["regle", "sorte", "nom", "etat", "n"],
      "properties": {
        "regle": { "$ref": "#/$defs/Regle" },
        "sorte": { "$ref": "#/$defs/Sorte" },
        "nom": { "$ref": "#/$defs/NomLogiciel" },
        "version": { "$ref": "#/$defs/VersionTierce" },
        "etat": { "$ref": "#/$defs/Etat" },
        "n": { "type": "integer", "minimum": 1, "maximum": 1000000 }
      }
    },
    "TexteEnvoye": {
      "type": "object",
      "additionalProperties": false,
      "required": ["gabarit", "texte", "contexte", "n"],
      "properties": {
        "gabarit": {
          "$ref": "#/$defs/Gabarit",
          "x-verifie-en-rust": "égal au gabarit du texte (SHA-256 du texte, chaque suite de chiffres ramenée à 0, 8 premiers octets en hexadécimal)"
        },
        "texte": { "$ref": "#/$defs/TexteNettoye" },
        "contexte": { "$ref": "#/$defs/Contexte" },
        "regle": { "$ref": "#/$defs/Regle" },
        "n": { "type": "integer", "minimum": 1, "maximum": 1000000 }
      }
    },
    "Correction": {
      "type": "object",
      "additionalProperties": false,
      "required": ["regle"],
      "properties": {
        "regle": { "$ref": "#/$defs/Regle" },
        "proposees": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "acceptees": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "refusees": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "reussies": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "echouees": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "annulees": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "revenues": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "codes": {
          "type": "array",
          "items": { "$ref": "#/$defs/RaisonNombre" },
          "minItems": 1,
          "maxItems": 4,
          "x-cle-unique": ["code"]
        }
      }
    },
    "Choix": {
      "type": "object",
      "additionalProperties": false,
      "required": ["regle"],
      "properties": {
        "regle": { "$ref": "#/$defs/Regle" },
        "normales": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "oublis": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "refus": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "echap": { "type": "integer", "minimum": 1, "maximum": 1000000 }
      }
    },
    "OutilEnvoye": {
      "type": "object",
      "additionalProperties": false,
      "required": ["outil", "origine"],
      "properties": {
        "outil": { "$ref": "#/$defs/NomOutil" },
        "origine": { "$ref": "#/$defs/Origine" },
        "lances": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "finis": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "abandonnes": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "plantes": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "med_ms": { "type": "integer", "minimum": 1, "maximum": 86400000 }
      }
    },
    "CacheRegle": {
      "type": "object",
      "additionalProperties": false,
      "required": ["regle"],
      "properties": {
        "regle": { "$ref": "#/$defs/Regle" },
        "repris": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "a_neuf": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "age_total_s": { "type": "integer", "minimum": 1, "maximum": 4000000000 },
        "gagne_ms": { "type": "integer", "minimum": 1, "maximum": 4000000000 },
        "comparees": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "ecarts": { "type": "integer", "minimum": 1, "maximum": 1000000 }
      }
    },
    "Reglage": {
      "type": "object",
      "additionalProperties": false,
      "required": ["levier", "annule"],
      "properties": {
        "levier": { "$ref": "#/$defs/Levier" },
        "regle": { "$ref": "#/$defs/Regle" },
        "avant": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "apres": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "annule": { "type": "boolean" }
      }
    },
    "Retires": {
      "type": "object",
      "additionalProperties": false,
      "required": [],
      "properties": {
        "regles": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "textes": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "objets": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "cache": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "outils": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "choix": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "corrections": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "reglages": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "causes": { "type": "integer", "minimum": 1, "maximum": 1000000 }
      },
      "minProperties": 1
    }
  }
};
// ==== FIN DU SCHÉMA DU LOT ======================================================================================

// --- Le détecteur de secrets, recopié de src/amelioration/texte.rs ---------------------------------------------
// `alertes` y est nul sur toute sortie du nettoyage : ici, le moindre son refuse le lot. Même ordre que là-bas :
// normalisation, couches précises (blocs PEM, préfixes connus, `clé = valeur`, « Bearer … »), puis l'entropie.
// Chaque fonction porte le nom de son modèle en Rust ; les indices comptent des caractères (points de code).

// ==== DÉBUT DES MOTIFS DU DÉTECTEUR =============================================================================
// Recopiés de texte.rs (PREFIXES, CLES, CLES_COURTES, CLES_FORTES, CLES_LIGNE, SCHEMAS, CLES_SANS_SEPARATEUR,
// MARQUEURS, les formes de « mot de passe », ENTROPIE_LONGUEUR, ENTROPIE_SEUIL, TEXTE_MAX, NOM_MAX, VERSION_MAX, la
// ponctuation permise et les invisibles) : outils/relais-schema.py vérifie qu'ils sont identiques. JSON strict.
const DETECTEUR = {
  "prefixes": [
    ["ghp_", 16], ["gho_", 16], ["ghu_", 16], ["ghs_", 16], ["ghr_", 16], ["github_pat_", 16], ["glpat-", 16],
    ["glptt-", 16], ["gldt-", 16], ["glrt-", 16], ["xoxa-", 8], ["xoxb-", 8], ["xoxe-", 8], ["xoxo-", 8],
    ["xoxp-", 8], ["xoxr-", 8], ["xoxs-", 8], ["xapp-", 8], ["sk-", 16], ["sk_live_", 16], ["sk_test_", 16],
    ["rk_live_", 16], ["rk_test_", 16], ["whsec_", 16], ["AKIA", 16], ["ASIA", 16], ["AIza", 30], ["ya29.", 20],
    ["eyJ", 10], ["npm_", 20], ["hf_", 20], ["pypi-", 20], ["dop_v1_", 20], ["AAAA", 40]
  ],
  "cles": [
    "password", "passwd", "passphrase", "pwd", "secret", "token", "jeton", "apikey", "api_key", "api-key",
    "authorization", "bearer", "cookie", "credential", "private_key", "privatekey", "private-key", "access_key"
  ],
  "cles_courtes": ["pass", "pw", "psk", "mdp", "cle", "clé", "key", "passe", "pin"],
  "cles_fortes": ["passe", "clé", "cle", "password", "passwd", "passphrase", "mdp", "psk"],
  "cles_ligne": ["authorization", "cookie"],
  "schemas": ["bearer", "basic", "token", "digest", "negotiate"],
  "cles_sans_separateur": [
    "password", "passwd", "passphrase", "pwd", "pass", "mdp", "passe", "psk", "secret", "token", "jeton", "apikey", "p"
  ],
  "mots_de_passe": ["mot de passe", "mot-de-passe", "mot_de_passe", "motdepasse"],
  "marqueurs": [
    "<chemin>", "<numéro>", "<url>", "<ip>", "<mac>", "<guid>", "<hex>", "<jeton>", "<secret>", "<clé>",
    "<adresse>", "<utilisateur>", "<machine>", "<réseau>", "<appareil>", "<compte>", "<courriel>", "<numéro>",
    "<wifi>"
  ],
  "extension_max": 5,
  "entropie_longueur": 20,
  "entropie_seuil": 3.5,
  "bornes": { "texte": 300, "nom": 64, "version": 32 },
  "ponctuation": " .,:;'()[]#%/_-+=",
  "invisibles": [
    [173, 173], [847, 847], [1564, 1564], [4447, 4448], [6068, 6069], [6155, 6159], [8203, 8207], [8234, 8238],
    [8288, 8303], [12644, 12644], [65024, 65039], [65279, 65279], [65440, 65440], [917504, 921599]
  ]
};
// ==== FIN DES MOTIFS DU DÉTECTEUR ===============================================================================

const PREFIXES = DETECTEUR.prefixes.map(([p, min]) => [Array.from(p), min]);
const MARQUEURS = DETECTEUR.marqueurs.map((m) => Array.from(m));

// Classes de caractères de Rust (char::is_alphabetic, is_numeric, is_whitespace, is_control, is_lowercase,
// is_uppercase), par les propriétés Unicode : un caractère absent (hors du texte) n'est d'aucune classe.
const de = (re) => (x) => x !== undefined && re.test(x);
const alpha = de(/^\p{Alphabetic}$/u);
const numerique = de(/^\p{N}$/u);
const alnum = (x) => alpha(x) || numerique(x);
const blanc = de(/^\p{White_Space}$/u);
const controle = de(/^\p{Cc}$/u);
const minuscule = de(/^\p{Lowercase}$/u);
const asciiAlnum = de(/^[A-Za-z0-9]$/);
const asciiAlpha = de(/^[A-Za-z]$/);
const asciiChiffre = de(/^[0-9]$/);
const asciiMinuscule = de(/^[a-z]$/);
const asciiMajuscule = de(/^[A-Z]$/);
const dans = (ensemble) => (x) => x !== undefined && ensemble.includes(x);

function invisible(x) {
  const p = x.codePointAt(0);
  return DETECTEUR.invisibles.some(([a, b]) => p >= a && p <= b);
}

const car = (c, i) => (i >= 0 && i < c.length ? c[i] : undefined);
const avant = (c, i) => (i >= 1 ? car(c, i - 1) : undefined);
const entre = (debut, fin) => Math.max(0, fin - debut);
const morceau = (c, debut, fin) => (debut <= fin && fin <= c.length ? c.slice(debut, fin) : []);
const chaine = (c, debut, fin) => morceau(c, debut, fin).join("");
const enMinusculeAscii = (x) => (asciiMajuscule(x) ? x.toLowerCase() : x);

function commencePar(c, i, motif) {
  return motif.every((m, k) => car(c, i + k) === m);
}

function commenceParSansCasse(c, i, motif) {
  return Array.from(motif).every((m, k) => {
    const x = car(c, i + k);
    return x !== undefined && enMinusculeAscii(x) === m;
  });
}

function finTantQue(c, i, p) {
  let j = i;
  while (j < c.length && p(c[j])) {
    j += 1;
  }
  return j;
}

function chercher(c, depuis, motif) {
  for (let i = depuis; i < c.length; i += 1) {
    if (commenceParSansCasse(c, i, motif)) {
      return i;
    }
  }
  return null;
}

const jeton = (x) => asciiAlnum(x) || dans("+/=_-")(x);
const jetonEtendu = (x) => jeton(x) || x === ".";

/// texte.rs, `remplacer` : les marqueurs déjà posés sont recopiés sans rien chercher dedans.
function remplacer(c, trouver) {
  const sortie = [];
  let i = 0;
  while (i < c.length) {
    const m = marqueur(c, i);
    if (m !== null) {
      sortie.push(...c.slice(i, m));
      i = m;
      continue;
    }
    const t = trouver(c, i);
    if (t !== null && t[0] > i) {
      sortie.push(...Array.from(t[1]));
      i = t[0];
    } else {
      sortie.push(c[i]);
      i += 1;
    }
  }
  return sortie;
}

function marqueur(c, i) {
  if (car(c, i) !== "<") {
    return null;
  }
  const m = MARQUEURS.find((x) => commencePar(c, i, x));
  if (m !== undefined) {
    return i + m.length;
  }
  const chemin = Array.from("<chemin .");
  if (commencePar(c, i, chemin)) {
    const debut = i + chemin.length;
    const fin = finTantQue(c, debut, (x) => asciiMinuscule(x) || asciiChiffre(x));
    if (entre(debut, fin) >= 1 && entre(debut, fin) <= DETECTEUR.extension_max && car(c, fin) === ">") {
      return fin + 1;
    }
  }
  return null;
}

function pleineChasse(x) {
  const p = x.codePointAt(0);
  if (p >= 0xff01 && p <= 0xff5e) {
    return String.fromCodePoint(p - 0xfee0);
  }
  return p === 0x3000 ? " " : x;
}

/// texte.rs, `normaliser`.
function normaliser(texte) {
  const c = [];
  for (const brut of texte) {
    const x = pleineChasse(brut);
    if (["\r", "\n", "\u0085", " ", " "].includes(x)) {
      c.push("\n");
    } else if (invisible(x)) {
      // retiré
    } else if (controle(x) || blanc(x)) {
      c.push(" ");
    } else if (["‘", "’", "‚", "‛", "‹", "›", "ʼ", "′"].includes(x)) {
      c.push("'");
    } else if (["“", "”", "„", "‟", "«", "»", "″"].includes(x)) {
      c.push('"');
    } else {
      c.push(x);
    }
  }
  return c;
}

/// texte.rs, `couche_precise`.
function couchePrecise(c, a) {
  const c2 = remplacer(c, (c, i) => {
    let t = blocDeCle(c, i);
    let par = "<clé>";
    if (t === null) {
      t = prefixeConnu(c, i);
      par = "<jeton>";
    }
    if (t === null) {
      return null;
    }
    a.n += 1;
    return [t, par];
  });
  return remplacer(c2, (c, i) => {
    const fin = valeurDeCle(c, i) ?? apresPorteur(c, i);
    if (fin === null) {
      return null;
    }
    a.n += 1;
    return [fin, "<secret>"];
  });
}

function blocDeCle(c, i) {
  if (commenceParSansCasse(c, i, "putty-user-key-file-")) {
    return c.length;
  }
  if (!commenceParSansCasse(c, i, "-----begin")) {
    return null;
  }
  const fin = chercher(c, i + 10, "-----end");
  if (fin === null) {
    return c.length;
  }
  const k = chercher(c, fin + 8, "-----");
  return k === null ? c.length : k + 5;
}

function prefixeConnu(c, i) {
  if (!jetonEtendu(car(c, i)) || asciiAlnum(avant(c, i))) {
    return null;
  }
  const t = PREFIXES.find(([p]) => commencePar(c, i, p));
  if (t === undefined) {
    return null;
  }
  const fin = finTantQue(c, i, jetonEtendu);
  return entre(i + t[0].length, fin) >= t[1] ? fin : null;
}

const motDeCle = (x) => alnum(x) || x === "_" || x === "-";
const entreCleEtValeur = (x) => x === " " || x === "\t" || x === '"' || x === "'";

function motAnnonceUnSecret(mot) {
  return (
    DETECTEUR.cles.some((cle) => mot.includes(cle)) ||
    DETECTEUR.cles_courtes.some((cle) => {
      if (mot === cle) {
        return true;
      }
      if (!mot.endsWith(cle)) {
        return false;
      }
      const tete = mot.slice(0, mot.length - cle.length);
      return tete.endsWith("_") || tete.endsWith("-");
    })
  );
}

function motsAvant(c, fin) {
  const mots = [];
  let k = fin;
  while (mots.length < 4) {
    while (avant(c, k) === " " || avant(c, k) === "\t") {
      k = Math.max(0, k - 1);
    }
    let debut = k;
    while (motDeCle(avant(c, debut))) {
      debut = Math.max(0, debut - 1);
    }
    if (debut === k) {
      break;
    }
    mots.push(chaine(c, debut, k).toLowerCase());
    k = debut;
  }
  return mots;
}

function motDeLaLangue(v) {
  if (v.length === 0) {
    return true;
  }
  return alpha(v[0]) && v.slice(1).every((y) => alpha(y) && minuscule(y));
}

/// texte.rs, `valeur_de_cle`.
function valeurDeCle(c, i) {
  const premier = car(c, i);
  if (premier === undefined || blanc(premier) || "\"'=:".includes(premier)) {
    return null;
  }
  let j = i;
  while (entreCleEtValeur(avant(c, j))) {
    j -= 1;
  }
  if (j === 0) {
    return null;
  }
  const separateur = j - 1;
  const sep = c[separateur];
  if (!(sep === ":" || sep === "=") || (sep === ":" && (avant(c, separateur) === ":" || premier === ":"))) {
    return apresOption(c, i, j);
  }
  let k = separateur;
  for (;;) {
    const y = avant(c, k);
    if (!(entreCleEtValeur(y) || y === "=" || y === ":")) {
      break;
    }
    k -= 1;
  }
  const mots = motsAvant(c, k);
  const dernier = mots[0] ?? "";
  const devant = chaine(c, Math.max(0, k - 48), k).toLowerCase();
  const annonce =
    motAnnonceUnSecret(dernier) ||
    mots.some((m) => DETECTEUR.cles_fortes.includes(m)) ||
    DETECTEUR.mots_de_passe.some((m) => devant.includes(m));
  if (!annonce) {
    return null;
  }
  const milieu = morceau(c, separateur + 1, i);
  let guillemet;
  for (let q = milieu.length - 1; q >= 0; q -= 1) {
    if (milieu[q] === '"' || milieu[q] === "'") {
      guillemet = milieu[q];
      break;
    }
  }
  let fin;
  if (guillemet !== undefined) {
    fin = finTantQue(c, i, (y) => y !== guillemet && y !== "\n");
  } else if (DETECTEUR.cles_ligne.some((cle) => dernier.includes(cle))) {
    fin = finTantQue(c, i, (y) => y !== "\n");
  } else {
    fin = apresSchema(c, i, finTantQue(c, i, (y) => !blanc(y)));
  }
  return fin > i ? fin : null;
}

/// texte.rs, `apres_option`.
function apresOption(c, i, j) {
  if (j === i || morceau(c, j, i).some((y) => y === '"' || y === "'")) {
    return null;
  }
  let debut = j;
  while (motDeCle(avant(c, debut)) || avant(c, debut) === "/") {
    debut -= 1;
  }
  const brut = chaine(c, debut, j).toLowerCase();
  const option = brut.startsWith("-") || brut.startsWith("/");
  const mot = brut.replace(/^[-/]+/, "");
  const fin = finTantQue(c, i, (y) => !blanc(y));
  const valeur = morceau(c, i, fin);
  const utilisateur = option && (mot === "u" || mot === "user") && valeur.some((y) => y === ":" || y === "%");
  const cle = DETECTEUR.cles_sans_separateur.includes(mot) && (option || mot.length > 1);
  return (cle && !motDeLaLangue(valeur)) || utilisateur ? fin : null;
}

function apresSchema(c, debut, fin) {
  const mot = chaine(c, debut, fin).toLowerCase();
  if (!DETECTEUR.schemas.includes(mot)) {
    return fin;
  }
  const suite = finTantQue(c, fin, (y) => y === " " || y === "\t");
  if (suite === fin) {
    return fin;
  }
  const bout = finTantQue(c, suite, (y) => !blanc(y));
  return bout > suite ? bout : fin;
}

function apresPorteur(c, i) {
  if (!jeton(car(c, i)) || jeton(avant(c, i))) {
    return null;
  }
  let j = i;
  while (avant(c, j) === " " || avant(c, j) === "\t") {
    j -= 1;
  }
  if (j < 6) {
    return null;
  }
  const debut = j - 6;
  if (j === i || !commenceParSansCasse(c, debut, "bearer") || alnum(avant(c, debut))) {
    return null;
  }
  const fin = finTantQue(c, i, jetonEtendu);
  return entre(i, fin) >= 8 ? fin : null;
}

/// texte.rs, `couche_entropie`.
function coucheEntropie(c, a) {
  return remplacer(c, (c, i) => {
    if (!jeton(car(c, i)) || jeton(avant(c, i))) {
      return null;
    }
    const fin = finTantQue(c, i, jeton);
    const suite = morceau(c, i, fin);
    const banal =
      suite.length < DETECTEUR.entropie_longueur || formeDeMots(suite) || entropie(suite) <= DETECTEUR.entropie_seuil;
    if (banal && !codeParQuatre(suite)) {
      return null;
    }
    a.n += 1;
    return [fin, "<jeton>"];
  });
}

function entropie(suite) {
  const comptes = new Map();
  for (const x of suite) {
    comptes.set(x, (comptes.get(x) ?? 0) + 1);
  }
  let h = 0;
  for (const n of comptes.values()) {
    const p = n / suite.length;
    h += -p * Math.log2(p);
  }
  return h;
}

function codeParQuatre(suite) {
  const morceaux = decouper(suite, (x) => x === "-");
  return morceaux.length >= 4 && morceaux.every((m) => m.length === 4 && m.every(asciiAlnum));
}

function decouper(suite, separe) {
  const morceaux = [[]];
  for (const x of suite) {
    if (separe(x)) {
      morceaux.push([]);
    } else {
      morceaux[morceaux.length - 1].push(x);
    }
  }
  return morceaux;
}

function formeDeMots(suite) {
  const morceaux = decouper(suite, (x) => x === "_" || x === "-" || x === "/");
  const finisParChiffre = morceaux.filter((m) => asciiChiffre(m[m.length - 1])).length;
  const quatreLettres = morceaux.filter((m) => m.length === 4 && m.every(asciiAlpha)).length;
  return (
    morceaux.length >= 2 &&
    finisParChiffre < 3 &&
    quatreLettres < 4 &&
    morceaux.every((m) => {
      let lettres = 0;
      while (lettres < m.length && asciiAlpha(m[lettres])) {
        lettres += 1;
      }
      const mot = m.slice(0, lettres);
      const chiffres = m.slice(lettres);
      let motOk;
      if (mot.length === 0) {
        motOk = chiffres.length >= 1 && chiffres.length <= 4;
      } else {
        const reste = mot.slice(1);
        motOk = reste.every(asciiMinuscule) || (asciiMajuscule(mot[0]) && reste.every(asciiMajuscule));
      }
      return m.length > 0 && m.length <= 16 && motOk && chiffres.every(asciiChiffre);
    })
  );
}

/// texte.rs, `alertes` : le nombre de fois que le détecteur sonnerait sur ce texte.
function alertes(s) {
  const a = { n: 0 };
  const c = couchePrecise(normaliser(s), a);
  coucheEntropie(c, a);
  return a.n;
}

function permis(x) {
  return (alpha(x) && !invisible(x)) || asciiChiffre(x) || DETECTEUR.ponctuation.includes(x);
}

const accentCombinant = (x) => x !== undefined && x.codePointAt(0) >= 0x300 && x.codePointAt(0) <= 0x36f;

/// texte.rs, `sortie_permise` : caractères permis, et chevrons dans les marqueurs connus seulement.
function sortiePermise(s) {
  const c = Array.from(s);
  let i = 0;
  let accents = 0;
  while (i < c.length) {
    const fin = marqueur(c, i);
    if (fin !== null) {
      i = fin;
      accents = 0;
      continue;
    }
    const x = c[i];
    if (accentCombinant(x)) {
      accents += 1;
      if (accents > 2 || i === 0) {
        return false;
      }
    } else if (permis(x)) {
      accents = 0;
    } else {
      return false;
    }
    i += 1;
  }
  return true;
}
