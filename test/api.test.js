'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const jwt = require('tr-jwt');
const jwe = require('tr-jwe');

const { startTestPg } = require('./pgtestenv');
const { startVault, makeEcKekJwk } = require('./fixtures');

let pg, vault, alice, bob;

test.before(async function() {
	pg = await startTestPg();
	vault = await startVault(pg);
	alice = await vault.createUser();
	bob = await vault.createUser();
}, { timeout: 60000 });

test.after(async function() {
	if (vault) {
		await vault.stop();
	}
	if (pg) {
		await pg.stop();
	}
});

function assertOk(r) {
	assert.equal(r.status, 200, JSON.stringify(r.body));
	assert.equal(r.body.status, 'ok', JSON.stringify(r.body));
	assert.equal(r.body.op, r.sentOp.toLowerCase());
	return r.body.data;
}

function assertApiError(r, errorCode, httpStatus) {
	assert.equal(r.status, httpStatus ?? 200, JSON.stringify(r.body));
	assert.equal(r.body.status, 'error');
	assert.equal(r.body.errorCode, errorCode, JSON.stringify(r.body));
	return r.body;
}

async function generateKey(who, data) {
	return assertOk(await vault.call('generate-key', data, who)).kid;
}

// ---- transport ----

test('healthz and readyz', async function() {
	const hz = await fetch(`${vault.baseUrl}/healthz`);
	assert.equal(hz.status, 200);
	assert.deepEqual(await hz.json(), { status: 'ok' });
	const rz = await fetch(`${vault.baseUrl}/readyz`);
	assert.equal(rz.status, 200);
	const hzPost = await fetch(`${vault.baseUrl}/healthz`, { method: 'POST' });
	assert.equal(hzPost.status, 405);
});

test('unknown endpoint is 404, wrong method 405', async function() {
	assertApiError(await vault.call('healthcheck', {}, alice, { path: '/api' }), 1004, 404);
	assertApiError(await vault.call('healthcheck', {}, alice, { path: '/api/v1/extra' }), 1004, 404);
	assertApiError(await vault.call('healthcheck', {}, alice, { method: 'GET', body: undefined }), 1003, 405);
});

test('envelope validation', async function() {
	// Wrong content type.
	assertApiError(await vault.call('healthcheck', {}, alice, { contentType: 'text/plain' }), 1000, 400);
	// Bad JSON.
	assertApiError(await vault.call('healthcheck', {}, alice, { body: '{nope' }), 1000, 400);
	// Non-object body.
	assertApiError(await vault.call('healthcheck', {}, alice, { body: '[1,2]' }), 1000, 400);
	// Missing / invalid op: no op echo possible.
	let r = await vault.call('healthcheck', {}, alice, { envelope: { user: alice.userId, request: 'healthcheck', data: {} } });
	assertApiError(r, 1000, 400);
	assert.equal(r.body.op, undefined);
	r = await vault.call('healthcheck', {}, alice, { op: 'not-a-uuid' });
	assertApiError(r, 1000, 400);
	// Unknown envelope property.
	assertApiError(await vault.call('healthcheck', {}, alice, { envelopeExtra: { extra: 1 } }), 1000, 400);
	// Missing user / request / data.
	assertApiError(await vault.call('healthcheck', {}, alice,
									{ envelope: { op: crypto.randomUUID(), request: 'healthcheck', data: {} } }), 1000, 400);
	assertApiError(await vault.call('healthcheck', {}, alice,
									{ envelope: { op: crypto.randomUUID(), user: alice.userId, data: {} } }), 1000, 400);
	assertApiError(await vault.call('healthcheck', {}, alice,
									{ envelope: { op: crypto.randomUUID(), user: alice.userId, request: 'healthcheck', data: [] } }), 1000, 400);
	// Oversized body: the server responds 400 and severs the
	// connection; depending on timing the client may instead see the
	// severed socket as a network error while still writing.
	const big = JSON.stringify({ user: alice.userId, op: crypto.randomUUID(), request: 'healthcheck',
								 data: { x: 'a'.repeat(2 * 1024 * 1024) } });
	try {
		assertApiError(await vault.call('healthcheck', {}, alice, { body: big }), 1000, 400);
	} catch (e) {
		assert.equal(e.name, 'TypeError', 'oversized body is rejected at the socket');
	}
});

test('op is echoed lower-cased', async function() {
	const op = crypto.randomUUID().toUpperCase();
	const r = await vault.call('healthcheck', {}, alice, { op });
	assert.equal(r.body.op, op.toLowerCase());
});

test('unknown operation is an API-level error (200/1002)', async function() {
	const r = await vault.call('no-such-op', {}, alice);
	assertApiError(r, 1002, 200);
	assert.equal(r.body.op, r.sentOp);
});

// ---- authentication ----

test('authentication failures are uniform 403', async function() {
	// No Authorization header.
	assertApiError(await vault.call('healthcheck', {}, alice, { headers: { 'Authorization': '' } }), 1001, 403);
	// Bogus token.
	assertApiError(await vault.call('healthcheck', {}, { userId: alice.userId, token: crypto.randomUUID() }), 1001, 403);
	// Non-UUID token.
	assertApiError(await vault.call('healthcheck', {}, alice, { headers: { 'Authorization': 'Bearer nope' } }), 1001, 403);
	// Valid token, mismatching user.
	assertApiError(await vault.call('healthcheck', {}, { userId: bob.userId, token: alice.token }), 1001, 403);
	// op still echoed on 403.
	const r = await vault.call('healthcheck', {}, { userId: bob.userId, token: alice.token });
	assert.equal(r.body.op, r.sentOp);
});

test('token is case-insensitive (canonical digest)', async function() {
	const r = await vault.call('healthcheck', {}, { userId: alice.userId, token: alice.token.toUpperCase() });
	assertOk(r);
});

test('user allowedIP: empty denies, absent denies', async function() {
	const denied = await vault.createUser({ allowedIP: [] });
	assertApiError(await vault.call('healthcheck', {}, denied), 1001, 403);
	const noProp = await vault.createUser();
	{
		const u = await vault.db.userById(noProp.userId);
		const data = Object.assign({}, u.data);
		delete data.allowedIP;
		await vault.db.setUserData(noProp.userId, data);
	}
	assertApiError(await vault.call('healthcheck', {}, noProp), 1001, 403);
	// Specific address allow: the test client connects from 127.0.0.1.
	const pinned = await vault.createUser({ allowedIP: [ '127.0.0.1' ] });
	assertOk(await vault.call('healthcheck', {}, pinned));
	const wrongNet = await vault.createUser({ allowedIP: [ '10.0.0.0/8' ] });
	assertApiError(await vault.call('healthcheck', {}, wrongNet), 1001, 403);
});

test('user nbf/exp enforcement', async function() {
	const now = Math.floor(Date.now() / 1000);
	const early = await vault.createUser({ nbf: now + 3600 });
	assertApiError(await vault.call('healthcheck', {}, early), 1001, 403);
	const late = await vault.createUser({ exp: now - 3600 });
	assertApiError(await vault.call('healthcheck', {}, late), 1001, 403);
	const current = await vault.createUser({ nbf: now - 3600, exp: now + 3600 });
	assertOk(await vault.call('healthcheck', {}, current));
});

// ---- operations ----

test('healthcheck returns uptime', async function() {
	const data = assertOk(await vault.call('healthcheck', {}, alice));
	assert.ok(Number.isSafeInteger(data.uptime));
	assert.ok(data.uptime >= 0);
});

test('generate-key: oct and validation errors', async function() {
	const kid = await generateKey(alice, { alg: 'A256GCM' });
	assert.match(kid, /^[0-9a-f-]{36}$/);
	assertApiError(await vault.call('generate-key', { alg: 'nope' }, alice), 1100);
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', kty: 'RSA' }, alice), 1100);
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', keyLength: 128 }, alice), 1100);
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', returnPublicKey: true }, alice), 1100);
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', bogus: 1 }, alice), 1100);
	assertApiError(await vault.call('generate-key', {}, alice), 1100);
	const now = Math.floor(Date.now() / 1000);
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', exp: now - 10 }, alice), 1100);
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', nbf: now + 100, exp: now + 50 }, alice), 1100);
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', nbf: 1.5 }, alice), 1100);
});

test('generate-key: acl validation', async function() {
	// Array form was a spec bug; object required.
	assertApiError(await vault.call('generate-key', { alg: 'A256GCM', acl: [ bob.userId ] }, alice), 1105);
	// Unknown user.
	assertApiError(await vault.call('generate-key',
									{ alg: 'A256GCM', acl: { 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee': [ 'decrypt' ] } },
									alice), 1105);
	// Unknown class.
	assertApiError(await vault.call('generate-key',
									{ alg: 'A256GCM', acl: { [bob.userId]: [ 'sudo' ] } }, alice), 1105);
	// Valid multi-user ACL; caller is merged in as owner.
	const kid = await generateKey(alice, { alg: 'A256GCMKW', acl: { [bob.userId]: [ 'decrypt' ] } });
	const row = await vault.db.keyById(kid);
	assert.deepEqual(row.acl[alice.userId], [ 'owner' ]);
	assert.deepEqual(row.acl[bob.userId], [ 'decrypt' ]);
});

test('generate-key: returnPublicKey exposes no private material', async function() {
	const data = assertOk(await vault.call('generate-key',
											{ alg: 'ES256', returnPublicKey: true }, alice));
	assert.equal(data.key.kty, 'EC');
	assert.equal(data.key.crv, 'P-256');
	assert.equal(data.key.kid, data.kid);
	assert.equal(data.key.alg, 'ES256');
	assert.equal(data.key.d, undefined);
});

test('public-key: acl class and kty checks', async function() {
	const kid = await generateKey(alice, { alg: 'ECDH-ES' });
	const data = assertOk(await vault.call('public-key', { kid }, alice));
	assert.equal(data.key.kty, 'EC');
	assert.equal(data.key.crv, 'P-521');
	assert.equal(data.key.d, undefined);
	// oct key has no public part.
	const octKid = await generateKey(alice, { alg: 'A256GCM' });
	assertApiError(await vault.call('public-key', { kid: octKid }, alice), 1102);
	// Unknown kid and ACL denial are indistinguishable.
	assertApiError(await vault.call('public-key', { kid: crypto.randomUUID() }, alice), 1101);
	assertApiError(await vault.call('public-key', { kid }, bob), 1101);
});

test('jwt: create and verify roundtrip (HS256)', async function() {
	const kid = await generateKey(alice, { alg: 'HS256', acl: { [bob.userId]: [ 'verify' ] } });
	const created = assertOk(await vault.call('create-jwt',
											   { kid, data: { sub: 'test-subject', n: 1 } }, alice));
	// Verify through the API — with explicit kid and with the header kid alone.
	const v1 = assertOk(await vault.call('verify-jwt', { token: created.token, kid }, bob));
	assert.equal(v1.data.sub, 'test-subject');
	assert.equal(v1.header.alg, 'HS256');
	assert.equal(v1.header.kid, kid);
	const v2 = assertOk(await vault.call('verify-jwt', { token: created.token }, bob));
	assert.equal(v2.data.n, 1);
	// bob has verify but not sign.
	assertApiError(await vault.call('create-jwt', { kid, data: { a: 1 } }, bob), 1101);
});

test('jwt: asymmetric create verifies locally against exported public key', async function() {
	const gen = assertOk(await vault.call('generate-key',
										   { alg: 'ES512', returnPublicKey: true }, alice));
	const created = assertOk(await vault.call('create-jwt',
											   { kid: gen.kid, data: { sub: 'x' } }, alice));
	// The vault-created token verifies with plain tr-jwt outside the vault.
	const payload = jwt.decode(created.token, gen.key);
	assert.equal(payload.sub, 'x');
});

test('jwt: kid mismatch, alg confusion, expiry', async function() {
	const kid = await generateKey(alice, { alg: 'HS256' });
	const otherKid = await generateKey(alice, { alg: 'HS256' });
	const created = assertOk(await vault.call('create-jwt', { kid, data: { a: 1 } }, alice));
	// Submitted kid conflicts with the token header kid.
	assertApiError(await vault.call('verify-jwt', { token: created.token, kid: otherKid }, alice), 1103);
	// Tampered token.
	const tampered = created.token.slice(0, -3) + 'abc';
	assertApiError(await vault.call('verify-jwt', { token: tampered, kid }, alice), 1103);
	// Garbage token.
	assertApiError(await vault.call('verify-jwt', { token: 'garbage' }, alice), 1103);
	// No kid anywhere: strip it by re-encoding with a kid-less JWK.
	const raw = vault.keystore.unwrap(await vault.db.keyById(kid));
	const kidless = Object.assign({}, raw);
	delete kidless.kid;
	const tokenNoKid = jwt.encode('HS256', kidless, { a: 1 });
	assertApiError(await vault.call('verify-jwt', { token: tokenNoKid }, alice), 1103);
	// ...but it verifies fine when the kid is submitted.
	assertOk(await vault.call('verify-jwt', { token: tokenNoKid, kid }, alice));
	// Algorithm confusion: token claims a different alg than the key.
	const confusedJwk = Object.assign({}, raw, { kid });
	delete confusedJwk.alg;
	const confused = jwt.encode('HS512', confusedJwk, { a: 1 });
	assertApiError(await vault.call('verify-jwt', { token: confused, kid }, alice), 1103);
	// Expired token: distinct message, same errorCode.
	const expired = assertOk(await vault.call('create-jwt',
											   { kid, data: { exp: Math.floor(Date.now() / 1000) - 10 } },
											   alice));
	const r = await vault.call('verify-jwt', { token: expired.token, kid }, alice);
	assertApiError(r, 1103);
	assert.equal(r.body.message, 'JWT token expired');
	// Bad registered claim shape on create.
	assertApiError(await vault.call('create-jwt', { kid, data: { exp: 'tomorrow' } }, alice), 1100);
	// Sign with an encryption key.
	const encKid = await generateKey(alice, { alg: 'A256GCMKW' });
	assertApiError(await vault.call('create-jwt', { kid: encKid, data: { a: 1 } }, alice), 1102);
});

test('jwe: symmetric roundtrip with compression option', async function() {
	const kid = await generateKey(alice, { alg: 'A256GCMKW', acl: { [bob.userId]: [ 'decrypt' ] } });
	const payload = { message: 'top secret', filler: 'x'.repeat(300) };
	for (const compress of [ undefined, false, true, 'auto' ]) {
		const data = Object.assign({ kid, data: payload }, (compress === undefined) ? {} : { compress });
		const created = assertOk(await vault.call('create-jwe', data, alice));
		const dec = assertOk(await vault.call('decrypt-jwe', { token: created.token }, bob));
		assert.deepEqual(dec.data, payload);
		assert.equal(dec.header.alg, 'A256GCMKW');
		assert.equal(dec.header.kid, kid);
	}
	assertApiError(await vault.call('create-jwe', { kid, data: {}, compress: 'yes' }, alice), 1100);
	// bob has decrypt but not encrypt.
	assertApiError(await vault.call('create-jwe', { kid, data: {} }, bob), 1101);
});

test('jwe: asymmetric roundtrip and local interop', async function() {
	const gen = assertOk(await vault.call('generate-key',
										   { alg: 'ECDH-ES', returnPublicKey: true }, alice));
	const created = assertOk(await vault.call('create-jwe',
											   { kid: gen.kid, data: [ 1, 'two', null ] }, alice));
	// ECDH-ES on P-521 selects A256GCM (curve-matched enc).
	const header = JSON.parse(Buffer.from(created.token.split('.')[0], 'base64url').toString('utf8'));
	assert.equal(header.enc, 'A256GCM');
	const dec = assertOk(await vault.call('decrypt-jwe', { token: created.token, kid: gen.kid }, alice));
	assert.deepEqual(dec.data, [ 1, 'two', null ]);
	// A token encrypted OUTSIDE the vault to the exported public key
	// decrypts inside the vault (the tr-data-escrow reader flow).
	const external = jwe.encrypt('ECDH-ES', gen.key, { escrow: true });
	const dec2 = assertOk(await vault.call('decrypt-jwe', { token: external, kid: gen.kid }, alice));
	assert.deepEqual(dec2.data, { escrow: true });
	// RSA-OAEP too.
	const rsa = assertOk(await vault.call('generate-key',
										   { alg: 'RSA-OAEP', returnPublicKey: true }, alice));
	const ext2 = jwe.encrypt('RSA-OAEP', rsa.key, 'plain string payload');
	const dec3 = assertOk(await vault.call('decrypt-jwe', { token: ext2, kid: rsa.kid }, alice));
	assert.equal(dec3.data, 'plain string payload');
});

test('jwe: incompatible key and tampering', async function() {
	const sigKid = await generateKey(alice, { alg: 'ES256' });
	assertApiError(await vault.call('create-jwe', { kid: sigKid, data: {} }, alice), 1102);
	const kid = await generateKey(alice, { alg: 'A128KW' });
	const created = assertOk(await vault.call('create-jwe', { kid, data: { x: 1 } }, alice));
	// A128KW wraps into A128GCM (matched content key length).
	const header = JSON.parse(Buffer.from(created.token.split('.')[0], 'base64url').toString('utf8'));
	assert.equal(header.enc, 'A128GCM');
	const parts = created.token.split('.');
	parts[3] = parts[3].slice(0, -3) + 'abc';
	assertApiError(await vault.call('decrypt-jwe', { token: parts.join('.'), kid }, alice), 1103);
	assertApiError(await vault.call('decrypt-jwe', { token: 'ey.b.a.d', kid }, alice), 1103);
});

test('masking: denial, missing key and out-of-window are indistinguishable', async function() {
	const now = Math.floor(Date.now() / 1000);
	const kid = await generateKey(alice, { alg: 'A256GCMKW' });
	const futureKid = await generateKey(alice, { alg: 'A256GCMKW', nbf: now + 3600 });
	// A token with a decodable protected header, so the key lookup —
	// not the token syntax — decides the error.
	const fakeToken = function(k) {
		return Buffer.from(JSON.stringify({ alg: 'A256GCMKW', kid: k }), 'utf8')
			.toString('base64url') + '.a.b.c.d';
	};
	const rDenied = await vault.call('decrypt-jwe', { token: fakeToken(kid) }, bob);
	const rMissing = await vault.call('decrypt-jwe', { token: fakeToken(crypto.randomUUID()) }, bob);
	const rWindow = await vault.call('decrypt-jwe', { token: fakeToken(futureKid) }, alice);
	for (const r of [ rDenied, rMissing, rWindow ]) {
		assertApiError(r, 1101);
		assert.equal(r.body.message, 'Key not found');
	}
	// Out-of-window key is unusable even for its owner and not listed.
	const listed = assertOk(await vault.call('list-keys', {}, alice));
	assert.ok(! listed.keys.some(function(k) { return k.kid === futureKid; }));
});

test('key expiry: read-time enforcement and sweep', async function() {
	const now = Math.floor(Date.now() / 1000);
	const kid = await generateKey(alice, { alg: 'A256GCM', exp: now + 1 });
	assert.ok(await vault.db.keyById(kid));
	await new Promise(function(resolve) { setTimeout(resolve, 1100); });
	// Read-time: expired the moment expires_at passes.
	assertApiError(await vault.call('export-key', { kid }, alice), 1104); // disabled first
	vault.opt.set('allow-export-key', true);
	assertApiError(await vault.call('export-key', { kid }, alice), 1101);
	vault.opt.set('allow-export-key', false);
	// Sweep removes the row.
	await vault.keystore.sweep();
	assert.equal(await vault.db.keyById(kid), null);
});

test('revoke-key: hard delete, acl class required', async function() {
	const kid = await generateKey(alice, { alg: 'HS256', acl: { [bob.userId]: [ 'sign' ] } });
	// bob has sign but not revoke-key.
	assertApiError(await vault.call('revoke-key', { kid }, bob), 1101);
	const data = assertOk(await vault.call('revoke-key', { kid }, alice));
	assert.deepEqual(data, { kid, revoked: true });
	assert.equal(await vault.db.keyById(kid), null);
	assertApiError(await vault.call('revoke-key', { kid }, alice), 1101);
	// A non-owner CAN revoke with the revoke-key class.
	const kid2 = await generateKey(alice, { alg: 'HS256', acl: { [bob.userId]: [ 'revoke-key' ] } });
	assertOk(await vault.call('revoke-key', { kid: kid2 }, bob));
});

test('export-key: double gate', async function() {
	const kid = await generateKey(alice, { alg: 'A256GCM', acl: { [bob.userId]: [ 'decrypt' ] } });
	// Config gate off: disabled for everyone, even owners.
	assertApiError(await vault.call('export-key', { kid }, alice), 1104);
	vault.opt.set('allow-export-key', true);
	try {
		// Owner implies export-secret-key.
		const data = assertOk(await vault.call('export-key', { kid }, alice));
		assert.equal(data.key.kty, 'oct');
		assert.equal(data.key.alg, 'A256GCM');
		assert.equal(data.key.kid, kid);
		assert.ok(data.key.k);
		// bob has decrypt but not export-secret-key: masked.
		assertApiError(await vault.call('export-key', { kid }, bob), 1101);
		// Asymmetric export returns the private half.
		const ecKid = await generateKey(alice, { alg: 'ECDH-ES' });
		const ec = assertOk(await vault.call('export-key', { kid: ecKid }, alice));
		assert.ok(ec.key.d);
	} finally {
		vault.opt.set('allow-export-key', false);
	}
});

test('list-keys: own keys only, shape {kid, kty, alg}', async function() {
	const carol = await vault.createUser();
	const k1 = await generateKey(carol, { alg: 'HS256' });
	const k2 = await generateKey(carol, { alg: 'ECDH-ES', acl: { [bob.userId]: [ 'decrypt' ] } });
	const mine = assertOk(await vault.call('list-keys', {}, carol));
	assert.deepEqual(mine.keys.map(function(k) { return k.kid; }).sort(), [ k1, k2 ].sort());
	for (const k of mine.keys) {
		assert.deepEqual(Object.keys(k).sort(), [ 'alg', 'kid', 'kty' ]);
	}
	// bob sees carol's shared key among his listing.
	const bobs = assertOk(await vault.call('list-keys', {}, bob));
	assert.ok(bobs.keys.some(function(k) { return k.kid === k2; }));
	assert.ok(! bobs.keys.some(function(k) { return k.kid === k1; }));
});

test('key-not-available: unconfigured KEK, authorized callers only', async function() {
	const kid = crypto.randomUUID();
	await vault.db.insertKey({ keyId: kid, kty: 'oct', alg: 'A256GCMKW',
							   publicKey: null,
							   embeddingKeyId: 'gone-kek', embeddedKey: 'ey.gone.jwe',
							   acl: { [alice.userId]: [ 'owner' ] } });
	// Authorized caller: distinct error.
	const r = await vault.call('create-jwe', { kid, data: {} }, alice);
	assertApiError(r, 1106);
	assert.equal(r.body.message, 'Key not available');
	// Unauthorized caller: still masked.
	assertApiError(await vault.call('create-jwe', { kid, data: {} }, bob), 1101);
	await vault.db.deleteKey(kid);
});

test('audit: events recorded for operations and denials, not for auth failures', async function() {
	const kid = await generateKey(alice, { alg: 'HS256' });
	await vault.call('create-jwt', { kid, data: { a: 1 } }, alice);
	await vault.call('create-jwt', { kid, data: { a: 1 } }, bob); // masked ACL denial
	await vault.call('healthcheck', {}, { userId: alice.userId, token: crypto.randomUUID() }); // auth failure (not audited)
	const events = [];
	for (let x = await vault.audit.logger().getEvents(0); ; x = await vault.audit.logger().getEvents(x.end + 1)) {
		events.push(...x.events);
		if (! x.have_more) {
			break;
		}
	}
	const byType = function(t) {
		return events.filter(function(e) { return e.data?.type === `tr-key-vault:${t}`; });
	};
	const genEv = byType('generate-key').find(function(e) { return e.data.kid === kid; });
	assert.ok(genEv, 'generate-key audited');
	assert.equal(genEv.data.userId, alice.userId);
	assert.equal(genEv.data.alg, 'HS256');
	assert.equal(genEv.data.outcome, 'ok');
	const signOk = byType('create-jwt').find(function(e) {
		return ((e.data.kid === kid) && (e.data.outcome === 'ok'));
	});
	assert.ok(signOk, 'successful create-jwt audited');
	const signDenied = byType('create-jwt').find(function(e) {
		return ((e.data.kid === kid) && (e.data.outcome === 1101));
	});
	assert.ok(signDenied, 'denied create-jwt audited with errorCode outcome');
	const denied = byType('denied').find(function(e) {
		return ((e.data.kid === kid) && (e.data.userId === bob.userId));
	});
	assert.ok(denied, 'masked ACL denial recorded');
	// Authentication failures are deliberately NOT audited.
	assert.equal(byType('auth-failure').length, 0, 'auth failures are not audited');
	// No secret material anywhere in the chain.
	for (const e of events) {
		const s = JSON.stringify(e.data ?? {});
		assert.ok(! /"(d|k|dp|dq|qi|p|q)":/.test(s), `no private JWK members in audit: ${s}`);
	}
	// The chain verifies.
	const result = await vault.audit.verify(true);
	assert.equal(result.ok, true);
});

test('unauthenticated traffic drives no audit-chain writes', async function() {
	const before = (await vault.audit.logger().getEvent(-1)).id;
	// Bad token, unknown-token, user/token mismatch, and missing
	// header — every unauthenticated failure mode.
	await vault.call('healthcheck', {}, { userId: alice.userId, token: crypto.randomUUID() });
	await vault.call('healthcheck', {}, { userId: bob.userId, token: alice.token });
	await vault.call('healthcheck', {}, alice, { headers: { 'Authorization': '' } });
	const denied = await vault.createUser({ allowedIP: [] }); // disallowed IP
	await vault.call('healthcheck', {}, denied);
	const after = (await vault.audit.logger().getEvent(-1)).id;
	assert.equal(after, before, 'no audit events appended for unauthenticated traffic');
});

test('audit: strict coupling fails the operation on append failure', async function() {
	const kid = await generateKey(alice, { alg: 'HS256' });
	const origEvent = vault.ctx.audit.event;
	vault.ctx.audit.event = async function() { throw new Error('chain down'); };
	try {
		const r = await vault.call('create-jwt', { kid, data: { a: 1 } }, alice);
		assertApiError(r, 1900, 500);
		// healthcheck is not audited and still works.
		assertOk(await vault.call('healthcheck', {}, alice));
	} finally {
		vault.ctx.audit.event = origEvent;
	}
	assertOk(await vault.call('create-jwt', { kid, data: { a: 1 } }, alice));
});

test('retired KEK: old keys unwrap, new keys use active KEK', async function(t) {
	// A second vault whose active KEK differs; the first vault's KEK
	// is retired there. Keys created in vault 1 remain usable.
	const kid = await generateKey(alice, { alg: 'A256GCMKW' });
	const created = assertOk(await vault.call('create-jwe', { kid, data: { v: 1 } }, alice));
	const oldActive = JSON.parse(await require('node:fs/promises')
								 .readFile(`${vault.kekDir}/test-kek-1.json`, 'utf8'));
	const vault2 = await startVault(pg, { activeKekJwk: makeEcKekJwk('test-kek-2'),
										  retiredKekJwks: [ oldActive ] });
	t.after(async function() { await vault2.stop(); });
	// Same database, so the same users and keys are visible.
	const dec = assertOk(await vault2.call('decrypt-jwe', { token: created.token, kid }, alice));
	assert.deepEqual(dec.data, { v: 1 });
	// New keys wrap with the new active KEK.
	const kid2 = assertOk(await vault2.call('generate-key', { alg: 'A256GCM' }, alice)).kid;
	assert.equal((await vault2.db.keyById(kid2)).embeddingKeyId, 'test-kek-2');
	assert.equal((await vault.db.keyById(kid)).embeddingKeyId, 'test-kek-1');
});

test('trusted-proxy-hops: XFF honored and spoof-resistant', async function(t) {
	const vaultP = await startVault(pg, { opt: { 'trusted-proxy-hops': 1 } });
	t.after(async function() { await vaultP.stop(); });
	const pinned = await vaultP.createUser({ allowedIP: [ '203.0.113.7' ] });
	// Proxy-appended XFF: rightmost entry is the client.
	assertOk(await vaultP.call('healthcheck', {}, pinned,
							   { headers: { 'X-Forwarded-For': '203.0.113.7' } }));
	// A forged prefix cannot promote a different client address.
	assertApiError(await vaultP.call('healthcheck', {}, pinned,
									 { headers: { 'X-Forwarded-For': '203.0.113.7, 198.51.100.1' } }),
				   1001, 403);
	// Without XFF the socket peer (127.0.0.1) does not match.
	assertApiError(await vaultP.call('healthcheck', {}, pinned), 1001, 403);
});
