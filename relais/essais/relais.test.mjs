// Essais du relais (relais/worker.js), sans wrangler ni paquet npm : `node --test relais/essais/`. La base D1 est
// simulée par node:sqlite avec le vrai relais/schema.sql, le limiteur de Cloudflare par un compteur à l'horloge, et
// l'horloge elle-même par mock.timers. Toutes les valeurs sont inventées : adresses des plages de documentation
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), compte « alice », réseau « Salon ».
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { FauxD1, FauxLimiteur } from "./faux-d1.mjs";

const HOTE = "https://relais.exemple.workers.dev";
const JOUR = Date.parse("2026-11-02T10:00:00Z");
const JOUR_MS = 86400000;
// Le secret de relève des essais, inventé ; celui de l'auteur ne vit que dans le Worker et ~/.config/vanguard-dev/.
const SECRET = "secret-de-releve-invente-pour-les-essais-0123456789";

// Les faux secrets sont coupés en morceaux et recollés à l'exécution (comme src/amelioration/texte/tests.rs) :
// d'un seul tenant, ils feraient sonner les détecteurs de secrets de GitHub et des crochets d'envoi.
const c = (...morceaux) => morceaux.join("");
const FAUX_SECRETS = [
  `Erreur gh : jeton ${c("gh", "p_", "FAUXjetonInventePourLesEssais0123")} refusé`,
  `clone avec ${c("github", "_pat_", "11FAUXINVENTE0_PourLesEssaisDeVanguard01234")} échoué`,
  `accès refusé ${c("gl", "pat-", "FauxJetonGitLabEssai1")} par le serveur`,
  `webhook ${c("xo", "xb-", "1234567890-FauxJetonSlackEssais")} non valide`,
  `clé ${c("AK", "IA", "FAUXINVENTEESSAI")} expirée pour le compte`,
  `requête ${c("AI", "za", "SyFauxJetonGoogleInventePourEssais0")} refusée par Google`,
  `appel avec la clé ${c("sk", "-", "proj-FauxJetonInventePourLesEssais0123")} refusé`,
  `paiement ${c("sk", "_live_", "FauxJetonStripeEssais0123")} refusé`,
  `session ${c("ey", "JhbGciOiJIUzI1NiJ9", ".", "eyJmYXV4IjoiamV0b24ifQ", ".", "RmF1eFNpZ25hdHVyZTAxMjM0")} expirée`,
  c("-----BEG", "IN OPENSSH PRIVATE KEY----- TUlJRmF1eENsZQ -----END OPENSSH PRIVATE KEY-----"),
  `clé publique ssh-ed25519 ${c("AAAAC3", "NzaC1lZDI1NTE5AAAAIFauxCleSshInventeePourLesEssais0123456789")} refusée`,
  "connexion avec password=hunter2FauxMdp refusée",
  "Mot de passe : FauxMotDePasse9 invalide",
  "en-tête Authorization: Basic RmF1eEJhc2ljRXNzYWk6bWRw",
  "Cookie: sessionid=FauxCookieInvente01; theme=sombre",
  "curl -H Bearer FauxJetonPorteur01234 a échoué",
  "valeur Zm9vYmFyRmF1eEVudHJvcGllMDEyMzQ1Njc4OQ inattendue dans le fichier",
  "client_secret=FauxSecretClient99 rejeté",
  "X-Api-Key: FauxJetonApi0042 refusée",
  `jeton​ ${c("gh", "p_", "FAUXjetonInventePourLesEssais0456")}‮ refusé`,
  `pleine chasse ${c("ｇｈ", "ｐ＿", "ＦＡＵＸｊｅｔｏｎＩｎｖｅｎｔｅＰｏｕｒＥｓｓａｉｓ")} refusé`,
  "dépôt --password FauxMdpOption7 refusé",
  c("cle ", "WXYZ-ABCD-EFGH-IJKL refusée"),
];

// Des textes nettoyés ordinaires : le détecteur ne doit pas y sonner (faux positif = lot perdu).
const TEXTES_PROPRES = [
  "Échec de la mise à jour : délai dépassé après 30 s",
  "Le service Salon ne répond pas (code 5)",
  "Fichier <chemin .txt> introuvable pour <utilisateur>",
  "La clé publique est absente du trousseau",
  "Mot de passe refusé par le serveur",
  "connexion à <ip> refusée : réseau injoignable",
  "Impossible de lire HKLM/Software/Policies, accès refusé",
  "pilote nvidia-utils version 560.35.03 chargé",
  "le token a expiré, nouvelle tentative dans 5 minutes",
];

/// Un lot de schéma 2 qui emploie chaque partie de outils/veille/schema-envoi.json.
function lotValide() {
  return {
    schema: 2,
    version: "0.89.1",
    version_avant: "0.89.0",
    jour: "2026-11-02",
    installation: "0123456789abcdef",
    anciennete: "moins-30-jours",
    plateforme: { famille: "debian", systeme_version: "6.12", arch: "x86_64", langue: "fr", administrateur: false },
    materiel: {
      processeur: "amd",
      coeurs: 8,
      fils: 16,
      memoire_go: 32,
      disque: "nvme",
      virtuelle: "aucune",
      portable: false,
      tpm: "oui",
      demarrage_securise: "inconnu",
      graphique: "amd",
      modele_processeur: "AMD Ryzen 7 7700",
      modele_graphique: "Radeon RX 7800 XT",
    },
    activite: { bilans_manuels: 2, passes_horaires: 24, surveillance: true, veilleur: false, cle: false },
    causes: [
      {
        genre: "erreur",
        contexte: "maj/fwupd",
        regle: "LNX-MAJ-001",
        lieu: "src/regles/linux/maj.rs:120:17",
        code: "delai",
        n: 3,
        duree_ms: 4500,
        gabarit: "0123456789abcdef",
      },
      { genre: "plantage", contexte: "plantage", lieu: "src/main.rs:88:5", code: "-2147024891", n: 1 },
    ],
    regles: [{ id: "LNX-MAJ-001", n: 24, med_ms: 800, p90_ms: 2100, raisons: [{ code: "droits", n: 2 }], delai_s: 30 }],
    objets: [
      { regle: "LNX-PKG-002", sorte: "paquet", nom: "firefox-esr", version: "128.4.0esr-1", etat: "sain", n: 1 },
    ],
    textes: [{ gabarit: "fedcba9876543210", texte: TEXTES_PROPRES[0], contexte: "essai", regle: "LNX-MAJ-001", n: 2 }],
    corrections: [{ regle: "LNX-MAJ-001", proposees: 1, acceptees: 1, reussies: 1, codes: [{ code: "refuse", n: 1 }] }],
    choix: [{ regle: "LNX-MAJ-001", normales: 1 }],
    outils: [{ outil: "scan-reseau", origine: "menu", lances: 2, finis: 2, med_ms: 15000 }],
    cache: [{ regle: "LNX-MAJ-001", repris: 3, a_neuf: 1 }],
    reglages: [{ levier: "delai", regle: "LNX-MAJ-001", avant: 120, apres: 90, annule: false }],
    refus_locaux: 4,
    retires: { textes: 1 },
  };
}

const SOURCE = readFileSync(new URL("../worker.js", import.meta.url), "utf8");
let numero = 0;

/// Le Worker tel quel, plus l'accès des essais à trois fonctions internes : le Worker déployé n'exporte que son
/// gestionnaire. Un module neuf à chaque appel (le sel gardé par l'isolat repart de zéro).
async function charger() {
  numero += 1;
  const texte = `${SOURCE}\nexport { alertes, juger, sortiePermise };\n// essai ${numero}\n`;
  return import(`data:text/javascript;base64,${Buffer.from(texte).toString("base64")}`);
}

/// Un relais neuf : un module rechargé, une base vide, l'horloge simulée.
async function relais(t, { maintenant = JOUR, secret = SECRET, limiteur = true } = {}) {
  t.mock.timers.enable({ apis: ["Date"], now: maintenant });
  const module = await charger();
  const db = new FauxD1();
  const env = { DB: db, SECRET_RELEVE: secret };
  if (limiteur) {
    env.LIMITEUR = new FauxLimiteur(10, 60);
  }
  const vues = [];
  const appeler = async (requete) => {
    const r = await module.default.fetch(requete, env);
    vues.push(r);
    return r;
  };
  return { module, db, env, vues, appeler, avancer: (ms) => t.mock.timers.setTime(Date.now() + ms) };
}

function envoi(corps, { ip = "192.0.2.10", type = "application/json", entetes = {}, chemin = "/v1/lot" } = {}) {
  const texte = typeof corps === "string" ? corps : JSON.stringify(corps);
  const octets = new TextEncoder().encode(texte);
  return new Request(HOTE + chemin, {
    method: "POST",
    headers: { "content-type": type, "content-length": String(octets.length), "cf-connecting-ip": ip, ...entetes },
    body: octets,
  });
}

function releve(autorisation, ip = "198.51.100.7") {
  const entetes = { "cf-connecting-ip": ip };
  if (autorisation !== undefined) {
    entetes.authorization = autorisation;
  }
  return new Request(`${HOTE}/v1/releve`, { headers: entetes });
}

async function refus(db) {
  return Object.fromEntries(db.lignes("SELECT raison, n FROM refus").map((l) => [l.raison, l.n]));
}

/// Une réponse au programme : rien à lire, que le code (aucun corps, aucun type, aucune redirection).
async function muette(r, statut) {
  assert.equal(r.status, statut);
  assert.equal(r.headers.get("location"), null);
  assert.equal(r.headers.get("content-type"), null);
  assert.equal((await r.arrayBuffer()).byteLength, 0);
  assert.deepEqual([...r.headers.keys()].sort(), ["cache-control", "x-content-type-options"]);
}

describe("réception d'un lot", () => {
  it("accepte un lot valide et garde le JSON réécrit, sans l'adresse", async (t) => {
    const { db, appeler } = await relais(t);
    await muette(await appeler(envoi(lotValide())), 200);
    const lots = db.lignes("SELECT * FROM lots");
    assert.equal(lots.length, 1);
    assert.equal(lots[0].jour, "2026-11-02");
    assert.equal(lots[0].corps, JSON.stringify(lotValide()));
    assert.equal(lots[0].taille, Buffer.byteLength(lots[0].corps));
    assert.match(lots[0].source, /^[0-9a-f]{32}$/);
    assert.match(lots[0].source_large, /^[0-9a-f]{32}$/);
    assert.notEqual(lots[0].source, lots[0].source_large);
    const tout = JSON.stringify(db.lignes("SELECT * FROM lots")) + JSON.stringify(db.lignes("SELECT * FROM quotas"));
    assert.ok(!tout.includes("192.0.2"), "l'adresse ne doit jamais être gardée");
  });

  it("accepte un lot minimal, et le JSON de 128 Kio tout juste", async (t) => {
    const { appeler } = await relais(t);
    const minimal = {
      schema: 2,
      version: "0.89.1",
      jour: "2026-11-02",
      anciennete: "90-jours-et-plus",
      plateforme: { famille: "windows-11", systeme_version: "26100", arch: "x86_64", langue: "en", administrateur: true },
      activite: { surveillance: false, veilleur: false, cle: false },
    };
    await muette(await appeler(envoi(minimal)), 200);
    const texte = JSON.stringify(minimal);
    const plein = texte + " ".repeat(128 * 1024 - Buffer.byteLength(texte));
    assert.equal(Buffer.byteLength(plein), 131072);
    await muette(await appeler(envoi(plein, { ip: "192.0.2.11" })), 200);
  });

  for (const [nom, modifier] of [
    ["une clé de trop en tête", (l) => (l.nom_machine = "Salon")],
    ["une clé de trop dans la plateforme", (l) => (l.plateforme.hote = "salon")],
    ["une clé de trop dans une cause", (l) => (l.causes[1].message = "x")],
    ["une clé de trop dans une raison", (l) => (l.regles[0].raisons[0].detail = "x")],
    ["une clé « __proto__ »", (l) => Object.defineProperty(l, "__proto__", { value: {}, enumerable: true })],
    ["une clé « constructor »", (l) => (l.activite.constructor = 1)],
    ["une clé obligatoire absente", (l) => delete l.plateforme],
    ["une clé obligatoire absente du matériel", (l) => delete l.materiel.tpm],
    ["un schéma 1", (l) => (l.schema = 1)],
    ["une version de Vanguard mal formée", (l) => (l.version = "0.89.1-beta")],
    ["une valeur hors de l'énumération", (l) => (l.plateforme.famille = "windows-12")],
    ["un contexte inconnu", (l) => (l.causes[0].contexte = "bilan/inconnu")],
    ["une mémoire qui n'est pas une puissance de 2", (l) => (l.materiel.memoire_go = 24)],
    ["un motif non suivi", (l) => (l.causes[0].regle = "lnx-maj-001")],
    ["un lieu hors de src/", (l) => (l.causes[0].lieu = "/home/alice/src/main.rs:1:1")],
    ["un lieu au chemin de plus de 120 caractères", (l) => (l.causes[0].lieu = `src/${"a".repeat(114)}.rs:1:1`)],
    ["un code inconnu", (l) => (l.causes[0].code = "acces-refuse")],
    ["un compte au-delà de 1 000", (l) => (l.causes[0].n = 1001)],
    ["un compte à zéro", (l) => (l.regles[0].n = 0)],
    ["un nombre négatif", (l) => (l.regles[0].n = -1)],
    ["un nombre à virgule", (l) => (l.regles[0].n = 1.5)],
    ["un nombre au-delà du maximum", (l) => (l.cache[0].gagne_ms = 4000000001)],
    ["un tableau vide", (l) => (l.choix = [])],
    ["un tableau trop long", (l) => (l.causes = Array.from({ length: 51 }, (_, k) => ({ ...l.causes[1], n: k + 1 })))],
    ["cinq raisons", (l) => (l.regles[0].raisons = ["droits", "absente", "muette", "delai", "refuse"].map((code) => ({ code, n: 1 })))],
    ["deux règles de même identifiant", (l) => l.regles.push({ ...l.regles[0], n: 1 })],
    ["deux causes de même clé (un champ absent compte)", (l) => l.causes.push({ ...l.causes[1], n: 5 })],
    ["deux raisons de même code", (l) => l.regles[0].raisons.push({ code: "droits", n: 1 })],
    ["un objet « retires » vide", (l) => (l.retires = {})],
    ["un null écrit", (l) => (l.version_avant = null)],
    ["une date qui n'existe pas", (l) => (l.jour = "2026-02-30")],
    ["une installation en majuscules", (l) => (l.installation = "0123456789ABCDEF")],
    ["une chaîne au lieu d'un nombre", (l) => (l.activite.bilans_manuels = "2")],
    ["un booléen au lieu d'un objet", (l) => (l.materiel = true)],
    ["un tableau en tête", (l) => [l]],
    ["un nom d'outil avec des arguments", (l) => (l.outils[0].outil = "scan-reseau --tout")],
    ["un nom sans lettre", (l) => (l.objets[0].nom = "7-7")],
    ["un nom trop long", (l) => (l.objets[0].nom = "a".repeat(65))],
    ["un nom trop long en octets", (l) => (l.objets[0].nom = "é".repeat(33))],
    ["un texte trop long", (l) => (l.textes[0].texte = "mot ".repeat(75) + "fin")],
    ["un texte avec un chevron", (l) => (l.textes[0].texte = "Erreur <script> ici")],
    ["un texte avec une arobase", (l) => (l.textes[0].texte = "Erreur pour alice@exemple")],
    ["un texte avec deux espaces", (l) => (l.textes[0].texte = "Erreur  double")],
    ["un texte aux écritures mêlées", (l) => (l.textes[0].texte = "Erreur de pаssword ici")],
    ["un texte vide", (l) => (l.textes[0].texte = "")],
    ["une version tierce en lettres", (l) => (l.objets[0].version = "1.2.3abcdefghijk")],
    ["une version tierce sans chiffre devant", (l) => (l.objets[0].version = "v1.2")],
    ["une version tierce qui finit par un point", (l) => (l.objets[0].version = "1.2.")],
  ]) {
    it(`refuse tout le lot pour ${nom} (422)`, async (t) => {
      const { db, appeler } = await relais(t);
      const lot = lotValide();
      const remplace = modifier(lot);
      const corps = Array.isArray(remplace) ? remplace : lot;
      await muette(await appeler(envoi(corps)), 422);
      assert.equal(db.lignes("SELECT * FROM lots").length, 0);
      assert.deepEqual(await refus(db), { schema: 1 });
    });
  }

  it("refuse 129 Kio annoncés (413) sans lire le corps", async (t) => {
    const { db, appeler } = await relais(t);
    const gros = JSON.stringify(lotValide()).padEnd(129 * 1024, " ");
    await muette(await appeler(envoi(gros)), 413);
    assert.equal(db.lignes("SELECT * FROM lots").length, 0);
    assert.deepEqual(await refus(db), { taille: 1 });
  });

  it("refuse 129 Kio envoyés sans longueur annoncée (413), en arrêtant la lecture", async (t) => {
    const { db, appeler } = await relais(t);
    let tires = 0;
    const flux = new ReadableStream({
      pull(controleur) {
        tires += 1;
        // Un flux sans fin : seule la borne du Worker l'arrête.
        controleur.enqueue(new Uint8Array(16 * 1024).fill(0x20));
      },
    });
    const r = new Request(`${HOTE}/v1/lot`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "192.0.2.10" },
      body: flux,
      duplex: "half",
    });
    await muette(await appeler(r), 413);
    assert.ok(tires <= 10, `lecture arrêtée à la borne (${tires} morceaux lus)`);
    assert.deepEqual(await refus(db), { taille: 1 });
  });

  it("refuse une longueur annoncée illisible (413)", async (t) => {
    const { appeler } = await relais(t);
    for (const longueur of ["-1", "1e3", "abc", "9999999999"]) {
      const r = envoi(lotValide(), { entetes: { "content-length": longueur } });
      await muette(await appeler(r), 413);
    }
  });

  it("refuse un JSON cassé ou un UTF-8 invalide (400)", async (t) => {
    const { db, appeler } = await relais(t);
    for (const corps of ['{"schema":2,', "", "nul", "{'schema':2}", '{"schema":2}{"schema":2}']) {
      await muette(await appeler(envoi(corps)), 400);
    }
    const invalide = new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);
    const r = new Request(`${HOTE}/v1/lot`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "192.0.2.10" },
      body: invalide,
    });
    await muette(await appeler(r), 400);
    assert.deepEqual(await refus(db), { json: 6 });
  });

  it("exige application/json (415)", async (t) => {
    const { db, appeler } = await relais(t);
    for (const type of ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""]) {
      await muette(await appeler(envoi(lotValide(), { type })), 415);
    }
    await muette(await appeler(envoi(lotValide(), { type: "Application/JSON; charset=utf-8" })), 200);
    assert.deepEqual(await refus(db), { type: 4 });
  });

  it("refuse une clé en double, même écrite autrement, et un entier écrit à décimales (422)", async (t) => {
    // JSON.parse laisse passer les deux, Rust non (schema-envoi.json) : la première valeur d'une clé en double
    // n'aurait pas été vérifiée.
    const { db, appeler } = await relais(t);
    const texte = JSON.stringify(lotValide());
    const secret = c("gh", "p_", "FAUXjetonInventePourLesEssais0789");
    const corps = [
      texte.replace('"textes":[', `"textes":[{"gabarit":"0123456789abcdef","texte":"jeton ${secret}","contexte":"essai","n":1}],"textes":[`),
      texte.replace('"schema":2', '"schema":2,"\\u0073chema":2'),
      texte.replace('"coeurs":8', '"coeurs":8,"coeurs":8'),
      texte.replace('"n":24', '"n":24.0'),
      texte.replace('"n":24', '"n":2.4e1'),
      texte.replace('"n":24', '"n":24E0'),
    ];
    let k = 0;
    for (const x of corps) {
      k += 1;
      await muette(await appeler(envoi(x, { ip: `203.0.113.${k}` })), 422);
    }
    assert.equal(db.lignes("SELECT * FROM lots").length, 0);
    assert.deepEqual(await refus(db), { schema: corps.length });
    // Les mêmes clés dans deux objets différents, des chiffres dans les chaînes, des espaces : rien à redire.
    const espace = JSON.stringify(lotValide(), null, 2);
    await muette(await appeler(envoi(espace, { ip: "198.51.100.1" })), 200);
  });

  it("refuse un lot réécrit de plus de 96 Kio (x-lot-octets-max), même sous les 128 Kio du corps", async (t) => {
    const { module } = await relais(t);
    const lot = lotValide();
    lot.regles = Array.from({ length: 400 }, (_, k) => ({
      id: `LNX-MAJ-${String(k).padStart(3, "0")}`,
      n: 1000000,
      med_ms: 86400000,
      p90_ms: 86400000,
      hors_delai: 1000000,
      problemes: 1000000,
      sains: 1000000,
      non_verifies: 1000000,
      raisons: ["droits", "absente", "illisible", "muette"].map((code) => ({ code, n: 1000000 })),
      delai_s: 86400,
    }));
    const taille = Buffer.byteLength(JSON.stringify(lot));
    assert.ok(taille > 98304 && taille < 131072, `taille ${taille}`);
    assert.equal(module.juger(lot, JSON.stringify(lot)), "schema");
    lot.regles = lot.regles.slice(0, 200);
    assert.equal(module.juger(lot, JSON.stringify(lot)), null);
  });
});

describe("le détecteur de secrets (deuxième couche)", () => {
  it("sonne sur chaque faux secret du corpus de texte.rs", async (t) => {
    const { module } = await relais(t);
    for (const s of FAUX_SECRETS) {
      assert.ok(module.alertes(s) > 0, `aucune alerte sur ${JSON.stringify(s)}`);
    }
  });

  it("sonne exactement comme texte.rs sur tout le corpus commun (corpus-detecteur.json)", async (t) => {
    // Les valeurs attendues sont celles du détecteur en Rust : le test corpus_du_relais_identique de
    // src/amelioration/texte/tests.rs les exige de lui, celui-ci les exige du Worker.
    const { module } = await relais(t);
    const corpus = JSON.parse(readFileSync(new URL("./corpus-detecteur.json", import.meta.url), "utf8"));
    assert.ok(corpus.length > 1000);
    const ecarts = corpus.filter(([s, a, p]) => module.alertes(s) !== a || (module.sortiePermise(s) ? 1 : 0) !== p);
    assert.deepEqual(ecarts.slice(0, 5), [], `${ecarts.length} écarts avec texte.rs`);
  });

  it("ne sonne pas sur des textes nettoyés ordinaires", async (t) => {
    const { module } = await relais(t);
    for (const s of TEXTES_PROPRES) {
      assert.equal(module.alertes(s), 0, JSON.stringify(s));
      assert.equal(module.juger({ ...lotValide(), textes: [{ ...lotValide().textes[0], texte: s }] }), null, s);
    }
  });

  for (const [champ, poser] of [
    ["un texte", (l, s) => (l.textes[0].texte = s)],
    ["un nom de logiciel", (l, s) => (l.objets[0].nom = s.slice(0, 60))],
    ["un modèle de processeur", (l, s) => (l.materiel.modele_processeur = s.slice(0, 60))],
  ]) {
    it(`refuse un lot qui porte un secret dans ${champ} (422, compté « secret »)`, async (t) => {
      const { db, appeler } = await relais(t);
      let n = 0;
      for (const s of FAUX_SECRETS.slice(0, 9)) {
        const lot = lotValide();
        poser(lot, s);
        n += 1;
        await muette(await appeler(envoi(lot, { ip: `203.0.113.${n}` })), 422);
      }
      assert.equal(db.lignes("SELECT * FROM lots").length, 0);
      assert.deepEqual(await refus(db), { secret: 9 });
    });
  }

  it("refuse une version tierce qui est un jeton", async (t) => {
    const { db, appeler } = await relais(t);
    const lot = lotValide();
    lot.objets[0].version = "1.0.0-a8Kq2Zx9Lm4Pw7Rt3Yv6";
    await muette(await appeler(envoi(lot)), 422);
    assert.deepEqual(await refus(db), { secret: 1 });
  });

  it("compte un secret comme tel même si le lot a aussi une faute de forme", async (t) => {
    const { module } = await relais(t);
    const lot = lotValide();
    lot.textes[0].texte = FAUX_SECRETS[0];
    lot.inconnue = 1;
    assert.equal(module.juger(lot), "secret");
  });
});

describe("limites de débit", () => {
  it("60 lots d'une source en rafale : 10 passent, 50 reçoivent 429 du limiteur", async (t) => {
    const { db, appeler } = await relais(t);
    const codes = [];
    for (let k = 0; k < 60; k += 1) {
      const r = await appeler(envoi(lotValide(), { ip: `192.0.2.${k % 200}` }));
      await muette(r, r.status);
      codes.push(r.status);
    }
    assert.equal(codes.filter((x) => x === 200).length, 10);
    assert.equal(codes.filter((x) => x === 429).length, 50);
    assert.equal(db.lignes("SELECT * FROM lots").length, 10);
    assert.deepEqual(await refus(db), { limite: 50 });
  });

  it("60 lots d'une source étalés sur la journée : 50 passent, puis le quota du jour (429)", async (t) => {
    const { db, appeler, avancer } = await relais(t, { maintenant: Date.parse("2026-11-02T00:10:00Z") });
    const codes = [];
    for (let k = 0; k < 60; k += 1) {
      codes.push((await appeler(envoi(lotValide(), { ip: "192.0.2.10" }))).status);
      avancer(5 * 60 * 1000);
    }
    assert.deepEqual(codes.slice(0, 50), new Array(50).fill(200));
    assert.deepEqual(codes.slice(50), new Array(10).fill(429));
    assert.deepEqual(await refus(db), { quota: 10 });
    // Une autre source (autre /24) n'est pas touchée ; le même /24 l'est.
    assert.equal((await appeler(envoi(lotValide(), { ip: "192.0.2.99" }))).status, 429);
    assert.equal((await appeler(envoi(lotValide(), { ip: "198.51.100.10" }))).status, 200);
  });

  it("les adresses IPv6 d'un même /48 sont une seule source", async (t) => {
    const { db, appeler } = await relais(t);
    await appeler(envoi(lotValide(), { ip: "2001:db8:1:a::1" }));
    await appeler(envoi(lotValide(), { ip: "2001:DB8:1:ffff:0:0:0:2" }));
    await appeler(envoi(lotValide(), { ip: "2001:db8:2::1" }));
    await appeler(envoi(lotValide(), { ip: "::ffff:192.0.2.1" }));
    await appeler(envoi(lotValide(), { ip: "192.0.2.200" }));
    const lignes = db.lignes("SELECT source, source_large FROM lots ORDER BY id");
    assert.equal(lignes[0].source, lignes[1].source);
    assert.notEqual(lignes[0].source, lignes[2].source);
    assert.equal(lignes[0].source_large, lignes[2].source_large);
    assert.equal(lignes[3].source, lignes[4].source);
  });

  it("le plafond global du jour (5 000 lots) répond 429", async (t) => {
    const { db, appeler } = await relais(t);
    db.db.prepare("INSERT INTO quotas (jour, source, n) VALUES ('2026-11-02', '*', 5000)").run();
    await muette(await appeler(envoi(lotValide())), 429);
    assert.deepEqual(await refus(db), { plafond: 1 });
    assert.equal(db.lignes("SELECT * FROM lots").length, 0);
  });

  it("le compteur d'une raison de refus cesse de monter à 10 000", async (t) => {
    const { db, appeler } = await relais(t);
    db.db.prepare("INSERT INTO refus (jour, raison, n) VALUES ('2026-11-02', 'json', 10000)").run();
    await muette(await appeler(envoi("{")), 400);
    assert.deepEqual(await refus(db), { json: 10000 });
  });

  it("le sel change chaque jour : la même adresse n'a plus la même empreinte", async (t) => {
    const { db, appeler, avancer } = await relais(t);
    await appeler(envoi(lotValide()));
    avancer(JOUR_MS);
    await appeler(envoi(lotValide()));
    const [a, b] = db.lignes("SELECT source FROM lots ORDER BY id");
    assert.notEqual(a.source, b.source);
    assert.deepEqual(
      db.lignes("SELECT jour FROM sels").map((l) => l.jour),
      ["2026-11-03"],
    );
    assert.deepEqual(
      db.lignes("SELECT DISTINCT jour FROM quotas").map((l) => l.jour),
      ["2026-11-03"],
    );
  });
});

describe("relève par l'ordinateur de l'auteur", () => {
  it("sans secret, avec un faux, un autre schéma ou un secret préfixe : 401, compté", async (t) => {
    const { db, appeler } = await relais(t);
    await appeler(envoi(lotValide()));
    for (const a of [
      undefined,
      "",
      "Bearer",
      "Bearer ",
      `Bearer ${SECRET.slice(0, -1)}`,
      `Bearer ${SECRET}x`,
      `bearer ${SECRET}`,
      `Basic ${SECRET}`,
      SECRET,
      `Bearer  ${SECRET}`,
    ]) {
      await muette(await appeler(releve(a)), 401);
    }
    assert.equal(db.lignes("SELECT * FROM lots").length, 1, "rien n'est effacé");
    assert.deepEqual(await refus(db), { releve: 10 });
  });

  it("sans secret configuré, ou trop court, personne ne relève", async (t) => {
    for (const secret of [undefined, "", "court-0123456789"]) {
      const { appeler } = await relais(t, { secret });
      await muette(await appeler(releve(`Bearer ${secret}`)), 401);
      await muette(await appeler(releve("Bearer ")), 401);
      t.mock.timers.reset();
    }
  });

  it("deviner le secret en rafale bute sur le limiteur (429)", async (t) => {
    const { appeler } = await relais(t);
    const codes = [];
    for (let k = 0; k < 15; k += 1) {
      codes.push((await appeler(releve(`Bearer essai-${k}`))).status);
    }
    assert.deepEqual(codes, [...new Array(10).fill(401), ...new Array(5).fill(429)]);
  });

  it("compare le secret en temps constant : empreintes SHA-256, aucune sortie anticipée", () => {
    const corps = SOURCE.slice(SOURCE.indexOf("async function secretBon"), SOURCE.indexOf("async function purger"));
    assert.match(corps, /crypto\.subtle\.digest\("SHA-256"/);
    assert.match(corps, /ecart \|= a\[k\] \^ b\[k\]/);
    assert.doesNotMatch(corps, /donne\s*[!=]==?\s*secret|secret\s*[!=]==?\s*donne/);
    assert.doesNotMatch(corps.slice(corps.indexOf("for (let k")), /return false|break/);
  });

  it("avec le secret : rend les lots et les refus, puis les efface", async (t) => {
    const { db, appeler } = await relais(t);
    await appeler(envoi(lotValide(), { ip: "192.0.2.10" }));
    await appeler(envoi(lotValide(), { ip: "203.0.113.5" }));
    await appeler(envoi("{"));
    const r = await appeler(releve(`Bearer ${SECRET}`));
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/json");
    assert.equal(r.headers.get("cache-control"), "no-store");
    const corps = await r.json();
    assert.equal(corps.releve, 1);
    assert.equal(corps.lots.length, 2);
    assert.deepEqual(corps.lots[0].lot, lotValide());
    assert.equal(corps.lots[0].jour, "2026-11-02");
    assert.notEqual(corps.lots[0].source, corps.lots[1].source);
    assert.deepEqual(corps.refus, [{ jour: "2026-11-02", raison: "json", n: 1 }]);
    assert.equal(corps.reste, false);
    assert.equal(db.lignes("SELECT * FROM lots").length, 0);
    assert.equal(db.lignes("SELECT * FROM refus").length, 0);
    const vide = await (await appeler(releve(`Bearer ${SECRET}`))).json();
    assert.deepEqual(vide, { releve: 1, lots: [], refus: [], reste: false });
  });

  it("une relève trop grosse s'arrête à 4 Mio et dit qu'il en reste", async (t) => {
    const { db, appeler } = await relais(t);
    const corps = JSON.stringify(lotValide());
    const inserer = db.db.prepare(
      "INSERT INTO lots (jour, source, source_large, taille, corps) VALUES ('2026-11-02', 'a', 'b', ?, ?)",
    );
    // La taille notée gouverne la coupe : 40 lots notés à 120 Kio.
    for (let k = 0; k < 40; k += 1) {
      inserer.run(120 * 1024, corps);
    }
    const premiere = await (await appeler(releve(`Bearer ${SECRET}`))).json();
    assert.equal(premiere.lots.length, 34);
    assert.equal(premiere.reste, true);
    const seconde = await (await appeler(releve(`Bearer ${SECRET}`))).json();
    assert.equal(seconde.lots.length, 6);
    assert.equal(seconde.reste, false);
    assert.equal(db.lignes("SELECT * FROM lots").length, 0);
  });

  it("GET /v1/lot et POST /v1/releve : 405", async (t) => {
    const { appeler } = await relais(t);
    await muette(await appeler(new Request(`${HOTE}/v1/lot`)), 405);
    await muette(await appeler(new Request(`${HOTE}/v1/releve`, { method: "POST", body: "{}" })), 405);
    await muette(await appeler(new Request(`${HOTE}/v1/lot`, { method: "PUT", body: "{}" })), 405);
  });
});

describe("garde de 14 jours", () => {
  it("rien de plus vieux que 14 jours ne reste, par le déclencheur quotidien", async (t) => {
    const { module, db, env, appeler, avancer } = await relais(t);
    await appeler(envoi(lotValide()));
    await appeler(envoi("{"));
    avancer(13 * JOUR_MS);
    await module.default.scheduled({}, env);
    assert.equal(db.lignes("SELECT * FROM lots").length, 1, "13 jours : encore là");
    avancer(JOUR_MS);
    await module.default.scheduled({}, env);
    assert.equal(db.lignes("SELECT * FROM lots").length, 0, "14 jours : effacé");
    assert.equal(db.lignes("SELECT * FROM refus").length, 0);
    assert.equal(db.lignes("SELECT * FROM quotas").length, 0);
    assert.equal(db.lignes("SELECT * FROM sels").length, 0);
  });

  it("sans déclencheur, le premier lot du jour purge aussi", async (t) => {
    const { db, appeler, avancer } = await relais(t);
    await appeler(envoi(lotValide()));
    avancer(14 * JOUR_MS);
    await muette(await appeler(envoi(lotValide())), 200);
    assert.deepEqual(
      db.lignes("SELECT jour FROM lots").map((l) => l.jour),
      ["2026-11-16"],
    );
  });

  it("la relève purge avant de rendre", async (t) => {
    const { appeler, avancer } = await relais(t);
    await appeler(envoi(lotValide()));
    avancer(15 * JOUR_MS);
    const corps = await (await appeler(releve(`Bearer ${SECRET}`))).json();
    assert.equal(corps.lots.length, 0);
  });
});

describe("rien à lire pour le programme, aucune redirection", () => {
  it("chemins inconnus, « / » final, paramètres, casse : 404, jamais 3xx", async (t) => {
    const { appeler } = await relais(t);
    for (const chemin of ["/", "/v1/lot/", "/V1/lot", "/v1/lot?x=1", "/v1/releve?a", "//v1/lot", "/v1/lot/../lot", "/v2/lot"]) {
      const r = await appeler(new Request(HOTE + chemin, { method: "POST", body: "{}" }));
      // « /v1/lot/../lot » est ramené à « /v1/lot » par l'analyse de l'adresse : c'est le seul accepté.
      if (chemin === "/v1/lot/../lot") {
        assert.notEqual(r.status, 404);
        continue;
      }
      await muette(r, 404);
    }
  });

  it("une base injoignable répond 503, sans corps", async (t) => {
    const { db, appeler } = await relais(t);
    db.avant = () => {
      throw new Error("D1 injoignable");
    };
    await muette(await appeler(envoi(lotValide())), 503);
    await muette(await appeler(releve(`Bearer ${SECRET}`)), 503);
  });

  it("aucune réponse de tous ces essais n'est une redirection", async (t) => {
    const { vues, appeler } = await relais(t);
    await appeler(envoi(lotValide()));
    await appeler(new Request(`${HOTE}/autre`));
    for (const r of vues) {
      assert.ok(r.status < 300 || r.status >= 400, `code ${r.status}`);
      assert.equal(r.redirected, false);
    }
  });

  it("le Worker n'écrit rien dans la console", () => {
    assert.doesNotMatch(SOURCE, /\bconsole\./);
    assert.doesNotMatch(SOURCE, /Response\.redirect|status:\s*3\d\d/);
    // Le gestionnaire seul : une autre exportation nommée serait lue par Cloudflare comme un point d'entrée.
    assert.deepEqual(SOURCE.match(/^export .*/gm), ["export default {"]);
  });
});
