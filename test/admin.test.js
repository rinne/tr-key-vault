'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const execFileP = promisify(execFile);

const { startTestPg } = require('./pgtestenv');
const { makeEcKekJwk, writeKekFile, stubOpt } = require('./fixtures');
const dbMigrate = require('../dbmigrate');
const VaultDB = require('../serverdb');
const { Audit } = require('../audit');
const { kekInit, KekManager, validateKek } = require('../kek');
const { tokenHash } = require('../serverauth');
const { generateVaultKey, resolveKeyGenParams } = require('../keygen');

const ROOT = path.join(__dirname, '..');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

let pg, pool, db, env;

// Run kv-admin as a real subprocess against the test cluster.
async function admin(args, opts) {
	try {
		const r = await execFileP('node', [ path.join(ROOT, 'kv-admin') ].concat(args),
								  { env, cwd: ROOT });
		return Object.assign({ code: 0 }, r);
	} catch (e) {
		if (opts?.allowFailure) {
			return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
		}
		throw e;
	}
}

test.before(async function() {
	pg = await startTestPg();
	env = Object.assign({}, process.env, {
		KV_OPT_PG_HOST: '127.0.0.1',
		KV_OPT_PG_PORT: String(pg.port),
		KV_OPT_PG_USER: 'kvtest',
		KV_OPT_PG_DATABASE: 'kvtest'
	});
	pool = pg.newPool();
	await dbMigrate(pool, path.join(ROOT, 'migrations'), { log: function() {}, debug: function() {} });
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

test('kv-admin: user lifecycle', async function(t) {
	// add-user prints the new user id.
	const added = await admin([ 'add-user', '--allow-all' ]);
	const userId = added.stdout.trim();
	assert.match(userId, UUID_RE);
	const u = await db.userById(userId);
	assert.deepEqual(u.data.allowedIP, [ '0.0.0.0/0', '0::/0' ]);
	assert.ok(u.data.iat > 0);
	assert.equal(u.authToken, null);

	// set-token prints the bearer token exactly once; only the digest
	// is stored.
	const st = await admin([ 'set-token', '--user', userId ]);
	const token = st.stdout.trim();
	assert.match(token, UUID_RE);
	const u2 = await db.userById(userId);
	assert.ok(Buffer.isBuffer(u2.authToken));
	assert.ok(tokenHash(token).equals(u2.authToken));
	assert.ok(u2.data.auth_token_ts > 0);

	// list-users shows it as api-enabled.
	const ls = await admin([ 'list-users' ]);
	assert.match(ls.stdout, new RegExp(`${userId} api-enabled`));

	// revoke-token disables API access.
	await admin([ 'revoke-token', '--user', userId ]);
	assert.equal((await db.userById(userId)).authToken, null);

	// set-user-data updates allowedIP and nbf/exp.
	await admin([ 'set-user-data', '--user', userId, '--allowed-ip', '10.0.0.0/8',
				  '--allowed-ip', '192.168.1.1-192.168.1.99', '--nbf', '1000' ]);
	const u3 = await db.userById(userId);
	assert.deepEqual(u3.data.allowedIP, [ '10.0.0.0/8', '192.168.1.1-192.168.1.99' ]);
	assert.equal(u3.data.nbf, 1000);
	await admin([ 'set-user-data', '--user', userId, '--clear-nbf' ]);
	assert.equal((await db.userById(userId)).data.nbf, undefined);

	// Invalid allowedIP entries are refused.
	const bad = await admin([ 'set-user-data', '--user', userId, '--allowed-ip', '::1-::2' ],
							{ allowFailure: true });
	assert.notEqual(bad.code, 0);

	// remove-user.
	await admin([ 'remove-user', '--user', userId ]);
	assert.equal(await db.userById(userId), null);
	const gone = await admin([ 'remove-user', '--user', userId ], { allowFailure: true });
	assert.notEqual(gone.code, 0);
});

test('kv-admin: update-acl', async function() {
	const owner = (await admin([ 'add-user', '--allow-all' ])).stdout.trim();
	const other = (await admin([ 'add-user', '--allow-all' ])).stdout.trim();
	const kid = crypto.randomUUID();
	await db.insertKey({ keyId: kid, kty: 'oct', alg: 'A256GCM', publicKey: null,
						 embeddingKeyId: 'k', embeddedKey: 'e',
						 acl: { [owner]: [ 'owner' ] } });
	await admin([ 'update-acl', '--kid', kid,
				  '--acl', JSON.stringify({ [owner]: [ 'owner' ], [other]: [ 'decrypt', 'verify' ] }) ]);
	const row = await db.keyById(kid);
	assert.deepEqual(row.acl[other], [ 'decrypt', 'verify' ]);
	// The owner invariant is enforced.
	const noOwner = await admin([ 'update-acl', '--kid', kid,
								  '--acl', JSON.stringify({ [other]: [ 'decrypt' ] }) ],
								{ allowFailure: true });
	assert.notEqual(noOwner.code, 0);
	// Unknown users are refused.
	const unknown = await admin([ 'update-acl', '--kid', kid,
								  '--acl', JSON.stringify({ 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee': [ 'owner' ] }) ],
								{ allowFailure: true });
	assert.notEqual(unknown.code, 0);
	await db.deleteKey(kid);
});

test('kv-admin: rewrap re-embeds rows under the active KEK', async function(t) {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvadm-'));
	t.after(async function() { await fs.rm(dir, { recursive: true, force: true }); });
	const oldJwk = makeEcKekJwk('adm-old-kek');
	const newJwk = makeEcKekJwk('adm-new-kek');
	await writeKekFile(dir, oldJwk);
	const newFile = await writeKekFile(dir, newJwk);
	const oldFile = path.join(dir, 'adm-old-kek.json');
	// A key wrapped with the OLD KEK.
	const generated = await generateVaultKey(resolveKeyGenParams({ alg: 'HS256' }));
	const oldMgr = new KekManager(validateKek(oldJwk), []);
	const wrapped = oldMgr.embed(generated.secretKey, { kid: generated.kid, iat: 1 });
	await db.insertKey({ keyId: generated.kid, kty: 'oct', alg: 'HS256', publicKey: null,
						 embeddingKeyId: wrapped.embeddingKeyId, embeddedKey: wrapped.embeddedKey,
						 acl: {} });
	// Rewrap with new active + old retired.
	const r = await admin([ 'rewrap', '--embedding-key-file', newFile,
							'--retired-embedding-key-file', oldFile ]);
	assert.match(r.stdout + r.stderr, /1 rewrapped, 0 skipped/);
	const row = await db.keyById(generated.kid);
	assert.equal(row.embeddingKeyId, 'adm-new-kek');
	// The re-embedded key unwraps with the new KEK alone.
	const newMgr = await kekInit(newFile, []);
	assert.deepEqual(newMgr.extract(row.embeddingKeyId, row.embeddedKey, generated.kid),
					 generated.secretKey);
	// nbf/exp survive a rewrap into the embedded claims.
	await db.deleteKey(generated.kid);
});

test('kv-admin: verify-audit and admin audit trail', async function() {
	const r = await admin([ 'verify-audit' ]);
	assert.match(r.stdout + r.stderr, /audit chain ok/);
	// All admin commands from this file are on the chain.
	const audit = new Audit({ pool, log: function() {} });
	await audit.init();
	const events = [];
	for (let x = await audit.logger().getEvents(0); ; x = await audit.logger().getEvents(x.end + 1)) {
		events.push(...x.events);
		if (! x.have_more) {
			break;
		}
	}
	const types = new Set(events.map(function(e) { return e.data?.type; }));
	for (const t of [ 'admin:add-user', 'admin:set-token', 'admin:revoke-token',
					  'admin:set-user-data', 'admin:remove-user', 'admin:list-users',
					  'admin:update-acl', 'admin:rewrap', 'admin:verify-audit' ]) {
		assert.ok(types.has(`tr-key-vault:${t}`), `audited: ${t}`);
	}
	// Admin events carry an actor.
	const ev = events.find(function(e) { return e.data?.type === 'tr-key-vault:admin:add-user'; });
	assert.ok(ev.data.actor);
});

test('kv-admin: bad invocations', async function() {
	const unknown = await admin([ 'frobnicate' ], { allowFailure: true });
	assert.notEqual(unknown.code, 0);
	assert.match(unknown.stderr, /Unknown command/);
	const missing = await admin([ 'set-token' ], { allowFailure: true });
	assert.notEqual(missing.code, 0);
	assert.match(missing.stderr, /requires --user/);
	const noCmd = await admin([], { allowFailure: true });
	assert.notEqual(noCmd.code, 0);
});
