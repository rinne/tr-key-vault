'use strict';

// End-to-end boot smoke test: the real `tr-key-vault` binary,
// configured purely via KV_OPT_* environment variables (the docker
// deployment mode), with audit sealing enabled. A user is
// provisioned with the real `kv-admin` binary and drives the API.

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const execFileP = promisify(execFile);

const { EventChainScheduler } = require('tr-json-chain');

const { startTestPg } = require('./pgtestenv');
const { makeEcKekJwk, writeKekFile } = require('./fixtures');
const { Audit } = require('../audit');
const { delay } = require('../basicutils');

const ROOT = path.join(__dirname, '..');

let pg, dir, env, child, baseUrl, childExit;

test.before(async function() {
	pg = await startTestPg();
	dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvboot-'));
	await writeKekFile(dir, makeEcKekJwk('boot-kek'));
	const seal = EventChainScheduler.generateSealKeyPair('ES256', { kid: 'boot-seal' });
	const sealFile = path.join(dir, 'seal.json');
	await fs.writeFile(sealFile, JSON.stringify(seal.secretKey), { mode: 0o600 });
	const port = 22000 + Math.floor(Math.random() * 20000);
	baseUrl = `http://127.0.0.1:${port}`;
	env = Object.assign({}, process.env, {
		KV_OPT_LISTEN_ADDRESS: '127.0.0.1',
		KV_OPT_LISTEN_PORT: String(port),
		KV_OPT_PG_HOST: '127.0.0.1',
		KV_OPT_PG_PORT: String(pg.port),
		KV_OPT_PG_USER: 'kvtest',
		KV_OPT_PG_DATABASE: 'kvtest',
		KV_OPT_EMBEDDING_KEY_FILE: path.join(dir, 'boot-kek.json'),
		KV_OPT_AUDIT_SEAL_KEY_FILE: sealFile,
		KV_OPT_TRUSTED_PROXY_HOPS: '0'
	});
	child = spawn('node', [ path.join(ROOT, 'tr-key-vault') ], { env, cwd: ROOT, stdio: [ 'ignore', 'pipe', 'pipe' ] });
	childExit = new Promise(function(resolve) {
		child.on('exit', function(code, signal) { resolve({ code, signal }); });
	});
	// Wait for liveness.
	const deadline = Date.now() + 20000;
	for (;;) {
		try {
			const r = await fetch(`${baseUrl}/healthz`);
			if (r.status === 200) {
				break;
			}
		} catch (_) { /* not up yet */ }
		if (Date.now() > deadline) {
			throw new Error('Server did not come up');
		}
		await delay(100);
	}
}, { timeout: 60000 });

test.after(async function() {
	if (child && (child.exitCode === null)) {
		child.kill('SIGTERM');
		await childExit;
	}
	if (pg) {
		await pg.stop();
	}
	if (dir) {
		await fs.rm(dir, { recursive: true, force: true });
	}
});

test('boot: readiness and API roundtrip through the real binary', async function() {
	const rz = await fetch(`${baseUrl}/readyz`);
	assert.equal(rz.status, 200);

	// Provision a user with the real kv-admin binary.
	const added = await execFileP('node', [ path.join(ROOT, 'kv-admin'), 'add-user', '--allow-all' ],
								  { env, cwd: ROOT });
	const userId = added.stdout.trim();
	const st = await execFileP('node', [ path.join(ROOT, 'kv-admin'), 'set-token', '--user', userId ],
							   { env, cwd: ROOT });
	const token = st.stdout.trim();

	async function call(request, data) {
		const r = await fetch(`${baseUrl}/api/v1`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
			body: JSON.stringify({ user: userId, op: crypto.randomUUID(), request, data })
		});
		return { status: r.status, body: await r.json() };
	}

	const hc = await call('healthcheck', {});
	assert.equal(hc.body.status, 'ok');
	assert.ok(hc.body.data.uptime >= 0);

	const gen = await call('generate-key', { alg: 'HS256' });
	assert.equal(gen.body.status, 'ok', JSON.stringify(gen.body));
	const kid = gen.body.data.kid;

	const created = await call('create-jwt', { kid, data: { sub: 'boot' } });
	assert.equal(created.body.status, 'ok');
	const verified = await call('verify-jwt', { token: created.body.data.token });
	assert.equal(verified.body.status, 'ok');
	assert.equal(verified.body.data.data.sub, 'boot');
});

test('boot: audit chain is sealed (root carries sealKey)', async function() {
	const pool = pg.newPool();
	try {
		const audit = new Audit({ pool, log: function() {} });
		const root = await audit.logger().getRootEvent();
		assert.ok(root.data.sealKey, 'chain root carries the public seal key');
		assert.equal(root.data.sealKey.kid, 'boot-seal');
		assert.equal(root.data.sealKey.d, undefined, 'no private material in the root');
		const result = await audit.logger().verify({ full: true, throwOnMismatch: false });
		assert.equal(result.ok, true);
	} finally {
		await pool.end();
	}
});

test('boot: clean shutdown on SIGTERM', async function() {
	child.kill('SIGTERM');
	const r = await childExit;
	assert.equal(r.code, 0);
});
