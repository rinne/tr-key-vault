'use strict';

const EventEmitter = require('node:events');

// Database layer: a thin pg-pool wrapper (scoopshot db-core style)
// plus the vault's queries. Timestamps travel as unix seconds on the
// way in (to_timestamp) and as Date objects on the way out.

class VaultDB extends EventEmitter {

	#pool;
	#started;
	#version;

	constructor(options) {
		super();
		const { pool } = Object.assign({}, options || {});
		this.#pool = null;
		(async function() {
			try {
				const r = await pool.query('SELECT FLOOR(EXTRACT(EPOCH FROM NOW()) * 1000) AS ts, VERSION() AS v');
				if (r.rowCount !== 1) {
					throw new Error('Unable to test database connection');
				}
				this.#started = Number.parseInt(r.rows[0].ts);
				this.#version = r.rows[0].v;
				this.#pool = pool;
				this.emit('ready');
			} catch (e) {
				this.#pool = null;
				this.emit('error', e);
			}
		}.bind(this))();
	}

	pool() {
		if (! this.#pool) {
			throw new Error('Invalid database');
		}
		return this.#pool;
	}

	info() {
		return { version: this.#version, started: this.#started };
	}

	async q(query, params, connection) {
		if (typeof(query) !== 'string') {
			throw new Error('Query must be a string');
		}
		if (! params) {
			params = [];
		}
		if (! Array.isArray(params)) {
			throw new Error('Query params must be an array');
		}
		if (connection) {
			return connection.query(query, params);
		}
		return this.pool().query(query, params);
	}

	async transaction(cb) {
		const connection = await this.pool().connect();
		try {
			await connection.query('BEGIN TRANSACTION');
			const rv = await cb(connection);
			await connection.query('COMMIT');
			connection.release();
			return rv;
		} catch (e) {
			try { await connection.query('ROLLBACK'); } catch (_) { /* nothing */ }
			try { connection.release(true); } catch (_) { /* nothing */ }
			throw e;
		}
	}

	async end() {
		if (this.#pool) {
			const pool = this.#pool;
			this.#pool = null;
			await pool.end();
		}
	}

	// ---- users ----

	#userRow(row) {
		if (! row) {
			return null;
		}
		return { userId: row.user_id, authToken: row.auth_token, data: row.data };
	}

	async userByTokenHash(hash) {
		const r = await this.q('SELECT user_id, auth_token, data FROM vault_user WHERE auth_token = $1', [ hash ]);
		return this.#userRow(r.rows[0]);
	}

	async userById(userId) {
		const r = await this.q('SELECT user_id, auth_token, data FROM vault_user WHERE user_id = $1::uuid', [ userId ]);
		return this.#userRow(r.rows[0]);
	}

	async insertUser(data) {
		const r = await this.q('INSERT INTO vault_user (data) VALUES ($1::jsonb) RETURNING user_id', [ JSON.stringify(data) ]);
		return r.rows[0].user_id;
	}

	async setUserToken(userId, hash) {
		const r = await this.q('UPDATE vault_user SET auth_token = $2 WHERE user_id = $1::uuid RETURNING user_id', [ userId, hash ]);
		return (r.rowCount === 1);
	}

	async setUserData(userId, data) {
		const r = await this.q('UPDATE vault_user SET data = $2::jsonb WHERE user_id = $1::uuid RETURNING user_id', [ userId, JSON.stringify(data) ]);
		return (r.rowCount === 1);
	}

	async removeUser(userId) {
		const r = await this.q('DELETE FROM vault_user WHERE user_id = $1::uuid RETURNING user_id', [ userId ]);
		return (r.rowCount === 1);
	}

	async listUsers() {
		const r = await this.q('SELECT user_id, auth_token, data FROM vault_user ORDER BY s');
		return r.rows.map(this.#userRow);
	}

	// Returns the subset of `userIds` that do NOT exist.
	async missingUsers(userIds) {
		if (userIds.length < 1) {
			return [];
		}
		const r = await this.q('SELECT user_id FROM vault_user WHERE user_id = ANY($1::uuid[])', [ userIds ]);
		const found = new Set(r.rows.map(function(row) { return row.user_id; }));
		return userIds.filter(function(u) { return ! found.has(u); });
	}

	// ---- keys ----

	#keyRow(row) {
		if (! row) {
			return null;
		}
		return { keyId: row.key_id,
				 kty: row.kty,
				 alg: row.alg,
				 notBefore: row.not_before,
				 expiresAt: row.expires_at,
				 publicKey: row.public_key,
				 embeddingKeyId: row.embedding_key_id,
				 embeddedKey: row.embedded_key,
				 acl: row.acl };
	}

	async insertKey(key) {
		await this.q(`
INSERT INTO vault_key
  (key_id, kty, alg, not_before, expires_at, public_key, embedding_key_id, embedded_key, acl)
VALUES
  ($1::uuid, $2, $3,
   CASE WHEN $4::bigint IS NULL THEN NULL ELSE TO_TIMESTAMP($4::bigint) END,
   CASE WHEN $5::bigint IS NULL THEN NULL ELSE TO_TIMESTAMP($5::bigint) END,
   $6::jsonb, $7, $8, $9::jsonb)
`, [ key.keyId, key.kty, key.alg,
	 (key.notBefore ?? null), (key.expiresAt ?? null),
	 (key.publicKey ? JSON.stringify(key.publicKey) : null),
	 key.embeddingKeyId, key.embeddedKey, JSON.stringify(key.acl) ]);
		return key.keyId;
	}

	async keyById(keyId) {
		const r = await this.q(`
SELECT key_id, kty, alg, not_before, expires_at, public_key, embedding_key_id, embedded_key, acl
FROM vault_key WHERE key_id = $1::uuid
`, [ keyId ]);
		return this.#keyRow(r.rows[0]);
	}

	async keysByAclUser(userId) {
		const r = await this.q(`
SELECT key_id, kty, alg, not_before, expires_at, public_key, embedding_key_id, embedded_key, acl
FROM vault_key WHERE acl ? $1 ORDER BY s
`, [ userId ]);
		return r.rows.map(this.#keyRow);
	}

	async deleteKey(keyId) {
		const r = await this.q('DELETE FROM vault_key WHERE key_id = $1::uuid RETURNING key_id', [ keyId ]);
		return (r.rowCount === 1);
	}

	async updateKeyAcl(keyId, acl) {
		const r = await this.q('UPDATE vault_key SET acl = $2::jsonb, updated_at = NOW() WHERE key_id = $1::uuid RETURNING key_id',
							   [ keyId, JSON.stringify(acl) ]);
		return (r.rowCount === 1);
	}

	async updateKeyEmbedding(keyId, embeddingKeyId, embeddedKey) {
		const r = await this.q(`
UPDATE vault_key SET embedding_key_id = $2, embedded_key = $3, updated_at = NOW()
WHERE key_id = $1::uuid RETURNING key_id
`, [ keyId, embeddingKeyId, embeddedKey ]);
		return (r.rowCount === 1);
	}

	async sweepExpiredKeys(graceSeconds) {
		const r = await this.q(`
DELETE FROM vault_key
WHERE expires_at IS NOT NULL AND expires_at < NOW() - ($1::bigint * INTERVAL '1 second')
RETURNING key_id
`, [ graceSeconds ?? 0 ]);
		return r.rowCount;
	}

	// Keys not wrapped with any of `knownKekIds` — the startup
	// consistency check (SPEC.md §5) and the rewrap work list.
	async unknownEmbeddingKeyIds(knownKekIds) {
		const r = await this.q(`
SELECT embedding_key_id, COUNT(*) AS n
FROM vault_key WHERE NOT (embedding_key_id = ANY($1::text[]))
GROUP BY embedding_key_id ORDER BY embedding_key_id
`, [ knownKekIds ]);
		return r.rows.map(function(row) { return { embeddingKeyId: row.embedding_key_id, count: Number.parseInt(row.n) }; });
	}

	async keysNotEmbeddedWith(activeKekId) {
		const r = await this.q(`
SELECT key_id, kty, alg, not_before, expires_at, public_key, embedding_key_id, embedded_key, acl
FROM vault_key WHERE embedding_key_id <> $1 ORDER BY s
`, [ activeKekId ]);
		return r.rows.map(this.#keyRow);
	}

}

module.exports = VaultDB;
