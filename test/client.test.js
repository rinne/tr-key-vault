'use strict';

// kv-client tests: start the in-process vault (the fixtures harness),
// provision a user, then run the real kv-client binary as a subprocess
// against the harness base URL (the admin.test.js pattern).

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const path = require('node:path');

const { startTestPg } = require('./pgtestenv');
const { startVault } = require('./fixtures');

const ROOT = path.join(__dirname, '..');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

let pg, vault, alice, baseEnv;

// Run kv-client. Returns { code, stdout, stderr }. `opts.input` is
// piped to stdin; `opts.env` overrides/extends the base env.
function client(args, opts) {
	const o = Object.assign({}, opts || {});
	return new Promise(function(resolve) {
		const child = execFile('node', [ path.join(ROOT, 'kv-client') ].concat(args),
								{ cwd: ROOT, env: Object.assign({}, baseEnv, o.env || {}) },
								function(err, stdout, stderr) {
									resolve({ code: (err ? (err.code ?? 1) : 0), stdout, stderr });
								});
		if (o.input !== undefined) {
			child.stdin.end(o.input);
		}
	});
}

test.before(async function() {
	pg = await startTestPg();
	vault = await startVault(pg);
	alice = await vault.createUser();
	baseEnv = Object.assign({}, process.env, {
		KV_CLIENT_OPT_URL: vault.baseUrl,
		KV_CLIENT_OPT_USER: alice.userId,
		KV_CLIENT_OPT_TOKEN: alice.token
	});
}, { timeout: 60000 });

test.after(async function() {
	if (vault) { await vault.stop(); }
	if (pg) { await pg.stop(); }
});

test('probes: healthz and readyz', async function() {
	const hz = await client([ 'healthz' ]);
	assert.equal(hz.code, 0, hz.stderr);
	assert.match(hz.stdout, /"status": "ok"/);
	const rz = await client([ 'readyz' ]);
	assert.equal(rz.code, 0, rz.stderr);
});

test('healthcheck returns uptime', async function() {
	const r = await client([ 'healthcheck' ]);
	assert.equal(r.code, 0, r.stderr);
	assert.match(r.stdout, /"uptime"/);
});

test('output modes: pretty default, --compact-json, --field, --raw', async function() {
	const pretty = await client([ 'healthcheck' ]);
	assert.match(pretty.stdout, /\n/, 'pretty output is multi-line');
	const compact = await client([ 'healthcheck', '--compact-json' ]);
	assert.equal(compact.stdout.trim().split('\n').length, 1, 'compact is one line');
	assert.match(compact.stdout, /^\{"uptime":\d+\}$/m);
	const raw = await client([ 'healthcheck', '--raw', '--compact-json' ]);
	assert.match(raw.stdout, /"status":"ok"/);
	assert.match(raw.stdout, /"op":/);
});

test('generate-key with --field kid, and full-object output', async function() {
	const gen = await client([ 'generate-key', '--alg', 'ES256',
							   '--return-public-key', '--field', 'kid' ]);
	assert.equal(gen.code, 0, gen.stderr);
	const kid = gen.stdout.trim();
	assert.match(kid, UUID_RE);
	// --field on an object (the public JWK) prints it as JSON, not an error.
	const pk = await client([ 'public-key', '--kid', kid, '--field', 'key', '--compact-json' ]);
	assert.equal(pk.code, 0, pk.stderr);
	const jwk = JSON.parse(pk.stdout);
	assert.equal(jwk.kty, 'EC');
	assert.equal(jwk.kid, kid);
	assert.equal(jwk.d, undefined);
});

test('jwt pipeline: create-jwt --field token | verify-jwt - ', async function() {
	const gen = await client([ 'generate-key', '--alg', 'HS256', '--field', 'kid' ]);
	const kid = gen.stdout.trim();
	const created = await client([ 'create-jwt', '--kid', kid,
								   '--data', JSON.stringify({ sub: 'pipe' }), '--field', 'token' ]);
	assert.equal(created.code, 0, created.stderr);
	const token = created.stdout.trim();
	assert.match(token, /^ey/);
	// Verify by piping the token on stdin.
	const verified = await client([ 'verify-jwt', '--kid', kid, '-' ], { input: token });
	assert.equal(verified.code, 0, verified.stderr);
	assert.match(verified.stdout, /"sub": "pipe"/);
});

test('jwe roundtrip via --data-file-equivalent stdin and positional token', async function() {
	const gen = await client([ 'generate-key', '--alg', 'A256GCMKW', '--field', 'kid' ]);
	const kid = gen.stdout.trim();
	// Payload from stdin (--data -).
	const enc = await client([ 'create-jwe', '--kid', kid, '--data', '-', '--field', 'token' ],
							 { input: JSON.stringify({ secret: 42 }) });
	assert.equal(enc.code, 0, enc.stderr);
	const token = enc.stdout.trim();
	// Token as a positional argument.
	const dec = await client([ 'decrypt-jwe', '--kid', kid, token ]);
	assert.equal(dec.code, 0, dec.stderr);
	assert.match(dec.stdout, /"secret": 42/);
});

test('create-jwe --compress auto is accepted', async function() {
	const gen = await client([ 'generate-key', '--alg', 'A256GCMKW', '--field', 'kid' ]);
	const kid = gen.stdout.trim();
	const enc = await client([ 'create-jwe', '--kid', kid,
							   '--data', JSON.stringify({ x: 'y'.repeat(400) }),
							   '--compress', 'auto', '--field', 'token' ]);
	assert.equal(enc.code, 0, enc.stderr);
	const dec = await client([ 'decrypt-jwe', '--kid', kid, enc.stdout.trim() ]);
	assert.match(dec.stdout, /"x": "yyy/);
});

test('list-keys and generate-key acl (multi-user)', async function() {
	const bob = await vault.createUser();
	const gen = await client([ 'generate-key', '--alg', 'ES256',
							   '--acl', JSON.stringify({ [bob.userId]: [ 'verify' ] }),
							   '--field', 'kid' ]);
	const kid = gen.stdout.trim();
	const list = await client([ 'list-keys' ]);
	assert.equal(list.code, 0, list.stderr);
	assert.match(list.stdout, new RegExp(kid));
	// bob (own env) sees the shared key too.
	const bobList = await client([ 'list-keys' ],
								 { env: { KV_CLIENT_OPT_USER: bob.userId, KV_CLIENT_OPT_TOKEN: bob.token } });
	assert.match(bobList.stdout, new RegExp(kid));
});

test('revoke-key hard-deletes', async function() {
	const gen = await client([ 'generate-key', '--alg', 'HS256', '--field', 'kid' ]);
	const kid = gen.stdout.trim();
	const rev = await client([ 'revoke-key', '--kid', kid ]);
	assert.equal(rev.code, 0, rev.stderr);
	assert.match(rev.stdout, /"revoked": true/);
	// A second revoke is an API error (key gone -> masked 1101 -> exit 3).
	const again = await client([ 'revoke-key', '--kid', kid ]);
	assert.equal(again.code, 3);
});

test('raw escape hatch reaches unknown-operation (exit 3)', async function() {
	const r = await client([ 'raw', 'no-such-op' ]);
	assert.equal(r.code, 3, r.stdout);
	assert.match(r.stderr, /API error 1002/);
});

test('exit codes: usage (1), api error (3), transport (2)', async function() {
	// Usage: missing --kid.
	const usage = await client([ 'public-key' ]);
	assert.equal(usage.code, 1);
	assert.match(usage.stderr, /requires --kid/);
	// API error: a well-formed request the server rejects (export-key
	// disabled) -> exit 3.
	const gen = await client([ 'generate-key', '--alg', 'A256GCM', '--field', 'kid' ]);
	const exp = await client([ 'export-key', '--kid', gen.stdout.trim() ]);
	assert.equal(exp.code, 3);
	assert.match(exp.stderr, /API error 1104/);
	// Transport: unreachable port.
	const down = await client([ 'healthcheck' ],
							  { env: { KV_CLIENT_OPT_URL: 'http://127.0.0.1:1' } });
	assert.equal(down.code, 2);
});

test('auth failure surfaces as API error (exit 3)', async function() {
	const bad = await client([ 'healthcheck' ],
							 { env: { KV_CLIENT_OPT_TOKEN: '11111111-2222-4333-8444-555555555555' } });
	assert.equal(bad.code, 3);
	assert.match(bad.stderr, /API error 1001/);
});
