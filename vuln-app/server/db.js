/**
 * db.js — Configuration base de données SQLite (via sql.js, pur WASM)
 *
 * VULN M6: credentials et secrets en dur dans le code source.
 * Un attaquant qui lit ce fichier (ex: via path traversal) obtient tout.
 */

const initSqlJs = require('sql.js');
const path      = require('path');
const fs        = require('fs');

// VULN M6: credentials fictifs en dur — illustre la fuite de secrets
const DB_SECRET   = "taskflow_db_key_2024";
const DB_ADMIN    = "sa";
const DB_PASSWORD = "Sa$uper123!";

const DB_PATH = path.join(__dirname, '..', 'db', 'taskflow.db');

/**
 * Wrapper synchrone autour de sql.js pour exposer une API proche de better-sqlite3.
 * sql.js est un WASM pur JS — pas de compilation native nécessaire.
 */
class SyncDB {
  constructor(sqlJs, data) {
    this._db   = new sqlJs.Database(data || null);
    this._path = null;
  }

  /** Exécute un ou plusieurs statements (sans retour de données). */
  exec(sql) {
    this._db.run(sql);
    this._save();
  }

  /**
   * Retourne un objet "statement" avec méthodes .run() et .all() et .get().
   * @param {string} sql
   */
  prepare(sql) {
    const db   = this._db;
    const save = () => this._save();
    return {
      run(...params) {
        db.run(sql, params);
        save();
        // Simuler lastInsertRowid
        const row = db.exec('SELECT last_insert_rowid() as id');
        const id  = row.length ? row[0].values[0][0] : null;
        return { lastInsertRowid: id };
      },
      all(...params) {
        const res = db.exec(sql, params);
        if (!res.length) return [];
        const { columns, values } = res[0];
        return values.map(row =>
          Object.fromEntries(columns.map((col, i) => [col, row[i]]))
        );
      },
      get(...params) {
        const res = db.exec(sql, params);
        if (!res.length || !res[0].values.length) return undefined;
        const { columns, values } = res[0];
        return Object.fromEntries(columns.map((col, i) => [col, values[0][i]]));
      }
    };
  }

  _save() {
    if (this._path) {
      const data = this._db.export();
      fs.writeFileSync(this._path, Buffer.from(data));
    }
  }
}

let _db = null;

/**
 * Initialise la base de données de façon synchrone.
 * sql.js est async pour charger le WASM, donc on utilise une IIFE top-level await pattern.
 */
function getDB() {
  if (_db) return _db;
  throw new Error('DB not initialized yet — call initDB() first');
}

async function initDB() {
  const SQL  = await initSqlJs();
  let data   = null;

  if (fs.existsSync(DB_PATH)) {
    data = fs.readFileSync(DB_PATH);
  }

  const wrapper  = new SyncDB(SQL, data);
  wrapper._path  = DB_PATH;

  // Joue le schéma et les seeds si la DB est nouvelle
  if (!data) {
    const initSQL = fs.readFileSync(path.join(__dirname, '..', 'db', 'init.sql'), 'utf8');
    const seedSQL = fs.readFileSync(path.join(__dirname, '..', 'db', 'seed.sql'), 'utf8');
    wrapper.exec(initSQL);
    wrapper.exec(seedSQL);
  }

  _db = wrapper;
  return wrapper;
}

module.exports = { initDB, getDB };
