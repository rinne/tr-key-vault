'use strict';

// Throwaway PostgreSQL cluster for the test suite: initdb + pg_ctl
// into a temp directory, TCP on 127.0.0.1 with a random port, trust
// auth. Each test file starts its own cluster and stops it in an
// after hook (the suite runs with --test-concurrency=1).

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const PgPool = require('pg-pool');

const execFileP = promisify(execFile);

async function startTestPg() {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvpg-'));
	const dataDir = path.join(dir, 'data');
	await execFileP('initdb', [ '-D', dataDir, '-U', 'kvtest', '-A', 'trust',
								'-E', 'UTF8', '--no-locale' ]);
	let port = null;
	for (let attempt = 0; attempt < 5; attempt++) {
		const tryPort = 21000 + Math.floor(Math.random() * 20000);
		try {
			await execFileP('pg_ctl', [ '-D', dataDir, '-l', path.join(dir, 'log'), '-w',
										'-o', `-p ${tryPort} -c listen_addresses=127.0.0.1 -c unix_socket_directories=''`,
										'start' ]);
			port = tryPort;
			break;
		} catch (e) {
			/* port collision or similar -- retry */
		}
	}
	if (! port) {
		await fs.rm(dir, { recursive: true, force: true });
		throw new Error('Unable to start test PostgreSQL');
	}
	{
		const pool = new PgPool({ host: '127.0.0.1', port, user: 'kvtest', database: 'postgres', max: 1 });
		await pool.query('CREATE DATABASE kvtest');
		await pool.end();
	}
	return {
		host: '127.0.0.1',
		port,
		user: 'kvtest',
		database: 'kvtest',
		newPool: function(extra) {
			return new PgPool(Object.assign({ host: '127.0.0.1', port, user: 'kvtest',
											  database: 'kvtest', max: 8 }, extra || {}));
		},
		stop: async function() {
			try {
				await execFileP('pg_ctl', [ '-D', dataDir, '-m', 'immediate', 'stop' ]);
			} catch (_) { /* nothing */ }
			await fs.rm(dir, { recursive: true, force: true });
		}
	};
}

module.exports = { startTestPg };
