// Pending sign-in state.
//
// Every wedge sign-in is one record keyed by requestId, carrying the challenge
// and the single-use tokens that gate session minting. Single-use is enforced
// structurally: takeAuthenticated() removes the record atomically, so no
// second session can ever be minted from the same sign-in (spec §5.4, §8.3),
// and a challenge dies with its record.
//
// MemoryStore covers one process (dev, tests, single-process servers).
// Multi-process deployments (cluster, pm2 -i) must share state across
// processes — use SqliteStore, or implement the same four methods over
// storage you already share.
//
// Port of sdk/python/wedge_rp/store.py — keep the contract in lockstep.

// Record shape (plain object):
//   requestId, challenge, namespace (strings)
//   username        — asserted at start (username-carrying core flow), else null
//   browserNonce    — browser-binding cookie value (core flow), else null
//   claimToken      — single-use claim token (app-initiated flow), else null
//   status          — "pending" | "authenticated" | "denied"
//   authenticatedUsername — the account that verified, set with "authenticated"
//   expiresAt       — epoch milliseconds

// In-process store. Node's single-threaded event loop makes each synchronous
// method atomic — no locking needed.
export class MemoryStore {
  #records = new Map();

  #prune(now) {
    for (const [rid, rec] of this.#records) {
      if (rec.expiresAt <= now) this.#records.delete(rid);
    }
  }

  put(record) {
    this.#prune(Date.now());
    this.#records.set(record.requestId, { ...record });
  }

  get(requestId) {
    this.#prune(Date.now());
    const rec = this.#records.get(requestId);
    return rec ? { ...rec } : null;
  }

  setAuthenticated(requestId, username) {
    this.#prune(Date.now());
    const rec = this.#records.get(requestId);
    if (!rec || rec.status !== 'pending') return false;
    rec.status = 'authenticated';
    rec.authenticatedUsername = username;
    return true;
  }

  takeAuthenticated(requestId) {
    this.#prune(Date.now());
    const rec = this.#records.get(requestId);
    if (!rec || rec.status !== 'authenticated') return null;
    this.#records.delete(requestId);
    return rec;
  }
}

// SQLite-backed store for multi-process deployments on one host, over the
// built-in node:sqlite (release-candidate stability; unflagged since Node
// 22.13). DatabaseSync is synchronous, and BEGIN IMMEDIATE makes the state
// transitions atomic across every process sharing the file; WAL keeps readers
// and writers from blocking each other.
export class SqliteStore {
  #db;
  #stmts;

  constructor(path) {
    // Lazy built-in lookup keeps `import 'wedge-rp'` working even where
    // node:sqlite is absent, as long as SqliteStore itself isn't used.
    const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
    this.#db = new DatabaseSync(path);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS wedge_requests (
        request_id TEXT PRIMARY KEY,
        challenge TEXT NOT NULL,
        namespace TEXT NOT NULL,
        username TEXT,
        browser_nonce TEXT,
        claim_token TEXT,
        status TEXT NOT NULL,
        authenticated_username TEXT,
        expires_at REAL NOT NULL
      )
    `);
    this.#stmts = {
      prune: this.#db.prepare('DELETE FROM wedge_requests WHERE expires_at <= ?'),
      insert: this.#db.prepare(
        'INSERT OR REPLACE INTO wedge_requests VALUES (?,?,?,?,?,?,?,?,?)',
      ),
      select: this.#db.prepare(
        'SELECT * FROM wedge_requests WHERE request_id = ? AND expires_at > ?',
      ),
      authenticate: this.#db.prepare(
        "UPDATE wedge_requests SET status='authenticated', authenticated_username=?"
        + " WHERE request_id=? AND status='pending' AND expires_at > ?",
      ),
      selectAuthenticated: this.#db.prepare(
        "SELECT * FROM wedge_requests WHERE request_id = ?"
        + " AND status='authenticated' AND expires_at > ?",
      ),
      remove: this.#db.prepare('DELETE FROM wedge_requests WHERE request_id = ?'),
    };
  }

  static #record(row) {
    return {
      requestId: row.request_id,
      challenge: row.challenge,
      namespace: row.namespace,
      username: row.username,
      browserNonce: row.browser_nonce,
      claimToken: row.claim_token,
      status: row.status,
      authenticatedUsername: row.authenticated_username,
      expiresAt: row.expires_at,
    };
  }

  put(record) {
    this.#stmts.prune.run(Date.now());
    this.#stmts.insert.run(
      record.requestId,
      record.challenge,
      record.namespace,
      record.username,
      record.browserNonce,
      record.claimToken,
      record.status,
      record.authenticatedUsername,
      record.expiresAt,
    );
  }

  get(requestId) {
    const row = this.#stmts.select.get(requestId, Date.now());
    return row ? SqliteStore.#record(row) : null;
  }

  setAuthenticated(requestId, username) {
    const { changes } = this.#stmts.authenticate.run(username, requestId, Date.now());
    return changes === 1;
  }

  takeAuthenticated(requestId) {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#stmts.selectAuthenticated.get(requestId, Date.now());
      if (!row) {
        this.#db.exec('ROLLBACK');
        return null;
      }
      this.#stmts.remove.run(requestId);
      this.#db.exec('COMMIT');
      return SqliteStore.#record(row);
    } catch (err) {
      this.#db.exec('ROLLBACK');
      throw err;
    }
  }
}
