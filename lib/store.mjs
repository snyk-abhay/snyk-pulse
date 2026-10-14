import { mkdirSync, chmodSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { gzipSync, gunzipSync } from "node:zlib";

export const KEEP_VERSIONS = 10;
export const DEFAULT_STORE = join(homedir(), ".snyk-pulse");

// node:sqlite is built into Node 22.13+; load it lazily so --no-store and
// older runtimes still work, and silence its one-time experimental warning.
async function sqlite() {
  const emit = process.emitWarning;
  process.emitWarning = (warning, ...rest) =>
    String(warning).includes("SQLite") ? undefined : emit.call(process, warning, ...rest);
  try {
    return await import("node:sqlite");
  } catch {
    throw new Error(
      "Saved data needs Node 22.13 or newer (built-in SQLite). Upgrade Node or start with --no-store.",
    );
  } finally {
    process.emitWarning = emit;
  }
}

/**
 * One SQLite file holds dated versions of the loaded datasets, the last data
 * source (so Refresh can repeat it) and, if the user chose to save it, the
 * Snyk token. The directory is 0700 and the database files 0600.
 */
export async function openStore(directory = DEFAULT_STORE) {
  const { DatabaseSync } = await sqlite();
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const file = join(directory, "pulse.db");
  const db = new DatabaseSync(file);
  for (const suffix of ["", "-wal", "-shm"])
    if (existsSync(file + suffix)) chmodSync(file + suffix, 0o600);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS versions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      as_of TEXT NOT NULL,
      source TEXT NOT NULL,
      data_from TEXT,
      issue_count INTEGER NOT NULL,
      datasets TEXT NOT NULL,
      payload BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  `);
  const get = (key) => {
    const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
    return row ? JSON.parse(row.value) : null;
  };
  const set = (key, value) =>
    value == null
      ? db.prepare("DELETE FROM settings WHERE key = ?").run(key)
      : db
          .prepare(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
          )
          .run(key, JSON.stringify(value));
  const summary = (row) => ({
    id: row.id,
    created_at: row.created_at,
    as_of: row.as_of,
    source: row.source,
    from: row.data_from,
    issues: row.issue_count,
    datasets: JSON.parse(row.datasets),
  });
  return {
    file,
    directory,
    /** Save the session's datasets as a new version and prune old ones. */
    saveVersion(session, { from = null } = {}) {
      const datasets = [...session.datasets].map(([name, data]) => ({
        name,
        headers: data.headers,
        rows: data.rows,
        source: data.source || session.snapshot?.source || "CSV import",
        from: data.from,
      }));
      const payload = gzipSync(
        JSON.stringify({ datasets, policy: session.policy }),
      );
      const result = db
        .prepare(
          `INSERT INTO versions (created_at, as_of, source, data_from, issue_count, datasets, payload)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          new Date().toISOString(),
          session.snapshot?.as_of || new Date().toISOString().slice(0, 10),
          session.snapshot?.source || "CSV import",
          from,
          session.snapshot?.issues.length || 0,
          JSON.stringify(datasets.map((d) => ({ name: d.name, rows: d.rows.length }))),
          payload,
        );
      db.prepare(
        "DELETE FROM versions WHERE id NOT IN (SELECT id FROM versions ORDER BY id DESC LIMIT ?)",
      ).run(KEEP_VERSIONS);
      return Number(result.lastInsertRowid);
    },
    listVersions() {
      return db
        .prepare(
          "SELECT id, created_at, as_of, source, data_from, issue_count, datasets FROM versions ORDER BY id DESC",
        )
        .all()
        .map(summary);
    },
    /** Return a stored version's datasets and policy, or null. */
    loadVersion(id) {
      const row =
        id == null
          ? db.prepare("SELECT * FROM versions ORDER BY id DESC LIMIT 1").get()
          : db.prepare("SELECT * FROM versions WHERE id = ?").get(id);
      if (!row) return null;
      const { datasets, policy } = JSON.parse(gunzipSync(row.payload));
      return { ...summary(row), datasets, policy };
    },
    deleteVersion(id) {
      return db.prepare("DELETE FROM versions WHERE id = ?").run(id).changes > 0;
    },
    /** Last data source: CSV metadata or API scope (never the token). */
    getSource: () => get("source"),
    setSource: (source) => set("source", source),
    // Saved at the user's request, in plain text inside this 0600 database.
    getToken: () => get("token"),
    setToken: (token, region) => set("token", token ? { token, region } : null),
    // Org ID -> { id, name } learned from the Snyk API for exports without group columns.
    getGroups: () => get("groups") || {},
    setGroups: (mapping) => set("groups", mapping),
    getWorkspaceName: () => get("workspace_name"),
    setWorkspaceName: (name) => set("workspace_name", name || null),
    getPort: () => get("port"),
    setPort: (port) => set("port", port),
    // Custom metric definitions applied on the Data & metrics page.
    getMetrics: () => get("metrics"),
    setMetrics: (definitions) => set("metrics", definitions?.length ? definitions : null),
    getPolicy: () => get("policy"),
    setPolicy: (policy) => set("policy", policy),
    clear() {
      db.exec("DELETE FROM versions; DELETE FROM settings;");
    },
    close: () => db.close(),
  };
}
