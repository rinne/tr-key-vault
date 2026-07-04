'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const dbMigrate = require('../dbmigrate');
const VaultDB = require('../serverdb');
const dbInit = require('../dbinit');
const { Audit } = require('../audit');
const { tokenHash } = require('../serverauth');
const { delay } = require('../basicutils');
const { startTestPg } = require('./pgtestenv');

const MIGRATIONS = path.join(__dirname, '..', 'migrations');
const quiet = { log: function() {}, debug: function() {} };

let pg, pool, db;

test.before(async function() {
	pg = await startTestPg();
	pool = pg.newPool();
	await dbMigrate(pool, MIGRATIONS, quiet);
	db = new VaultDB({ pool });
	await new Promise(function(resolve, reject) {
		db.on('ready', resolve);
		db.on('error', reject);
	});
}, { timeout: 60000 });

test.after(async function() {
	if (db) {
		await db.end();
	}
	if (pg) {
		await pg.stop();
	}
});

test('dbmigrate: idempotent', async function() {
	const again = await dbMigrate(pool, MIGRATIONS, quiet);
	assert.deepEqual(again.applied, []);
	assert.ok(again.skipped >= 1);
});

test('pool: survives an idle backend termination without crashing', async function() {
	// A dedicated pool with the production error handler attached. If
	// the handler were missing, the pool would emit an unhandled
	// 'error' when its idle backend is terminated, crashing the test
	// process (and, in production, the server).
	const rpool = pg.newPool();
	dbInit.attachPoolErrorHandler(rpool, function() {});
	try {
		// Establish one client, learn its backend pid, return it to
		// the pool as idle.
		const c = await rpool.connect();
		const pid = (await c.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
		c.release();
		// Terminate that backend from a separate connection — this is
		// what a PostgreSQL restart does to idle pooled connections.
		const killer = pg.newPool();
		try {
			await killer.query('SELECT pg_terminate_backend($1)', [ pid ]);
		} finally {
			await killer.end();
		}
		// Let the idle client's socket error surface as a pool 'error'.
		await delay(300);
		// The pool recovers: a fresh query works and we are still alive.
		const r = await rpool.query('SELECT 1 AS ok');
		assert.equal(r.rows[0].ok, 1);
	} finally {
		await rpool.end();
	}
});

test('users: CRUD and token hash lookup', async function() {
	const userId = await db.insertUser({ allowedIP: [ '0.0.0.0/0' ], iat: 1 });
	assert.ok(userId);
	const token = 'A0000000-B111-4222-8333-C44444444444';
	await db.setUserToken(userId, tokenHash(token));
	// Lookup is by digest and case-insensitive over the token string.
	const byTok = await db.userByTokenHash(tokenHash(token.toLowerCase()));
	assert.equal(byTok.userId, userId);
	assert.deepEqual(byTok.data.allowedIP, [ '0.0.0.0/0' ]);
	// The digest, not the token, is stored.
	assert.ok(Buffer.isBuffer(byTok.authToken));
	assert.equal(byTok.authToken.length, 32);
	// Token revocation disables lookup.
	await db.setUserToken(userId, null);
	assert.equal(await db.userByTokenHash(tokenHash(token)), null);
	// Data update, listing, missing-user check, removal.
	await db.setUserData(userId, { allowedIP: [], iat: 1, nbf: 5 });
	const u = await db.userById(userId);
	assert.equal(u.data.nbf, 5);
	const all = await db.listUsers();
	assert.ok(all.some(function(x) { return x.userId === userId; }));
	const missing = await db.missingUsers([ userId, 'ffffffff-ffff-4fff-8fff-ffffffffffff' ]);
	assert.deepEqual(missing, [ 'ffffffff-ffff-4fff-8fff-ffffffffffff' ]);
	assert.equal(await db.removeUser(userId), true);
	assert.equal(await db.removeUser(userId), false);
});

test('keys: insert, load, acl listing, delete', async function() {
	const owner = await db.insertUser({});
	const kid = '00000000-0000-4000-8000-000000000001';
	await db.insertKey({ keyId: kid, kty: 'oct', alg: 'A256GCM',
						 notBefore: 1000, expiresAt: 4102444800,
						 publicKey: null, embeddingKeyId: 'kek-x', embeddedKey: 'ey.fake.jwe',
						 acl: { [owner]: [ 'owner' ] } });
	const row = await db.keyById(kid);
	assert.equal(row.keyId, kid);
	assert.equal(row.alg, 'A256GCM');
	assert.equal(row.embeddingKeyId, 'kek-x');
	assert.equal(row.notBefore.getTime(), 1000 * 1000);
	assert.equal(row.expiresAt.getTime(), 4102444800 * 1000);
	assert.deepEqual(row.acl[owner], [ 'owner' ]);
	const listed = await db.keysByAclUser(owner);
	assert.equal(listed.length, 1);
	assert.equal(listed[0].keyId, kid);
	assert.deepEqual(await db.keysByAclUser('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'), []);
	// Embedding update (rewrap path).
	assert.equal(await db.updateKeyEmbedding(kid, 'kek-y', 'ey.other.jwe'), true);
	const row2 = await db.keyById(kid);
	assert.equal(row2.embeddingKeyId, 'kek-y');
	// ACL update.
	assert.equal(await db.updateKeyAcl(kid, { [owner]: [ 'owner', 'sign' ] }), true);
	assert.deepEqual((await db.keyById(kid)).acl[owner], [ 'owner', 'sign' ]);
	// Unknown embedding key report.
	const unknown = await db.unknownEmbeddingKeyIds([ 'kek-z' ]);
	assert.deepEqual(unknown, [ { embeddingKeyId: 'kek-y', count: 1 } ]);
	assert.deepEqual(await db.unknownEmbeddingKeyIds([ 'kek-y' ]), []);
	const worklist = await db.keysNotEmbeddedWith('kek-z');
	assert.equal(worklist.length, 1);
	// Delete.
	assert.equal(await db.deleteKey(kid), true);
	assert.equal(await db.deleteKey(kid), false);
	assert.equal(await db.keyById(kid), null);
	await db.removeUser(owner);
});

test('keys: expiry sweep honors grace', async function() {
	const now = Math.floor(Date.now() / 1000);
	const kidOld = '00000000-0000-4000-8000-000000000002';
	const kidRecent = '00000000-0000-4000-8000-000000000003';
	await db.insertKey({ keyId: kidOld, kty: 'oct', alg: 'A256GCM', expiresAt: now - 1000,
						 publicKey: null, embeddingKeyId: 'k', embeddedKey: 'e', acl: {} });
	await db.insertKey({ keyId: kidRecent, kty: 'oct', alg: 'A256GCM', expiresAt: now - 10,
						 publicKey: null, embeddingKeyId: 'k', embeddedKey: 'e', acl: {} });
	// Grace 100s: only the long-expired key is swept.
	assert.equal(await db.sweepExpiredKeys(100), 1);
	assert.equal(await db.keyById(kidOld), null);
	assert.ok(await db.keyById(kidRecent));
	// Grace 0: the rest goes too.
	assert.equal(await db.sweepExpiredKeys(0), 1);
	assert.equal(await db.keyById(kidRecent), null);
});

test('audit: chain init, events, verify', async function() {
	const audit = new Audit({ pool, log: function() {} });
	await audit.init();
	await audit.event('generate-key', { userId: 'u1', op: 'o1', kid: 'k1', outcome: 'ok' });
	await audit.event('denied', { userId: 'u2', op: 'o2', kid: 'k1' });
	const result = await audit.verify(true);
	assert.equal(result.ok, true);
	assert.ok(result.eventsChecked >= 3);
	// Events carry the tr-key-vault: type prefix and an ISO ts.
	const events = await audit.logger().getEvents(0);
	const types = events.events.map(function(e) { return e.data?.type; });
	assert.ok(types.includes('tr-key-vault:generate-key'));
	assert.ok(types.includes('tr-key-vault:denied'));
	const ev = events.events.find(function(e) { return e.data?.type === 'tr-key-vault:generate-key'; });
	assert.equal(ev.data.userId, 'u1');
	assert.equal(ev.data.outcome, 'ok');
	assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(ev.data.ts));
});
