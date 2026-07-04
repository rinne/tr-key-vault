'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

const { log } = require('./basicutils');

// Apply pending SQL migrations from `migrationsDir` against `pool`.
//
// Migration files are named `<version>_<description>.sql`, where
// `<version>` is a zero-padded integer (e.g. `0001_init.sql`,
// `0002_add_x.sql`). Files are applied in ascending filename order;
// each file runs inside its own transaction. The full filename is
// recorded as the version key in `schema_migrations`.
//
// Idempotent: a second invocation against the same database is a
// no-op. A partially-applied migration that fails rolls back fully
// and the function throws — the caller is expected to abort startup.
//
// Returns { applied: <string[]>, skipped: <number> }.

async function dbMigrate(pool, migrationsDir, ctx) {

	if (! pool) {
		throw new Error('dbMigrate: pool is required');
	}
	if (! (migrationsDir && (typeof(migrationsDir) === 'string'))) {
		throw new Error('dbMigrate: migrationsDir is required');
	}
	const logFn = ctx?.log || log;
	const debugFn = ctx?.debug || function() {};

	let entries;
	try {
		entries = await fs.readdir(migrationsDir);
	} catch (e) {
		if (e.code === 'ENOENT') {
			debugFn(`dbMigrate: no migrations directory at ${migrationsDir}`);
			return { applied: [], skipped: 0 };
		}
		throw e;
	}

	const migrations = entries
		  .filter(function(f) { return /^\d+_.+\.sql$/.test(f); })
		  .sort();

	await pool.query(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_ts TIMESTAMP NOT NULL DEFAULT NOW()
)
`);

	const r = await pool.query('SELECT version FROM schema_migrations');
	const alreadyApplied = new Set(r.rows.map(function(row) { return row.version; }));

	const applied = [];
	for (const file of migrations) {
		if (alreadyApplied.has(file)) {
			debugFn(`dbMigrate: skipping already-applied migration ${file}`);
			continue;
		}
		const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
		const client = await pool.connect();
		try {
			await client.query('BEGIN');
			await client.query(sql);
			await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [ file ]);
			await client.query('COMMIT');
		} catch (e) {
			try { await client.query('ROLLBACK'); } catch (_) { /* nothing */ }
			try { client.release(true); } catch (_) { /* nothing */ }
			throw new Error(`dbMigrate: migration ${file} failed: ${e.message}`);
		}
		client.release();
		applied.push(file);
		logFn(`dbMigrate: applied ${file}`);
	}

	return { applied, skipped: migrations.length - applied.length };
}

module.exports = dbMigrate;
