// Une fausse liaison D1 pour les essais, sans wrangler ni paquet npm : node:sqlite (SQLite, comme D1) derrière la
// même forme d'appel (`prepare().bind().first() / all() / run()`, `batch`, `exec`). Le vrai relais/schema.sql y est
// chargé : les essais exercent les vraies tables et les vraies requêtes.
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const SCHEMA_SQL = new URL("../schema.sql", import.meta.url);

class Requete {
  constructor(base, sql, valeurs = []) {
    this.base = base;
    this.sql = sql;
    this.valeurs = valeurs;
  }

  bind(...valeurs) {
    return new Requete(this.base, this.sql, valeurs);
  }

  preparer() {
    this.base.avant?.(this.sql);
    return this.base.db.prepare(this.sql);
  }

  async first(colonne) {
    const ligne = this.preparer().get(...this.valeurs);
    if (ligne === undefined) {
      return null;
    }
    const simple = { ...ligne };
    return colonne === undefined ? simple : simple[colonne];
  }

  async all() {
    return this.executer();
  }

  async run() {
    return this.executer();
  }

  executer() {
    const req = this.preparer();
    if (req.columns().length > 0) {
      return { success: true, results: req.all(...this.valeurs).map((l) => ({ ...l })), meta: {} };
    }
    const r = req.run(...this.valeurs);
    return {
      success: true,
      results: [],
      meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) },
    };
  }
}

export class FauxD1 {
  constructor() {
    this.db = new DatabaseSync(":memory:");
    this.db.exec(readFileSync(SCHEMA_SQL, "utf8"));
    // Crochet des essais : appelé avant chaque requête (pour compter, ou pour simuler une panne).
    this.avant = null;
  }

  prepare(sql) {
    return new Requete(this, sql);
  }

  // D1 : toutes les requêtes du lot dans une transaction, annulée entière si l'une échoue.
  async batch(requetes) {
    this.db.exec("BEGIN");
    try {
      const resultats = requetes.map((r) => r.executer());
      this.db.exec("COMMIT");
      return resultats;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  async exec(sql) {
    this.db.exec(sql);
    return { count: 1, duration: 0 };
  }

  // Lecture directe, pour les vérifications des essais.
  lignes(sql, ...valeurs) {
    return this.db
      .prepare(sql)
      .all(...valeurs)
      .map((l) => ({ ...l }));
  }
}

/// Le limiteur de Cloudflare, approché : `limite` requêtes par clé et par fenêtre de `periode` secondes, selon
/// l'horloge (simulée par les essais).
export class FauxLimiteur {
  constructor(limite = 10, periode = 60) {
    this.limite = limite;
    this.periode = periode;
    this.vus = new Map();
  }

  async limit({ key }) {
    const fenetre = Math.floor(Date.now() / (this.periode * 1000));
    const cle = `${fenetre}:${key}`;
    const n = (this.vus.get(cle) ?? 0) + 1;
    this.vus.set(cle, n);
    return { success: n <= this.limite };
  }
}
