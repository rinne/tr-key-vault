'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const jwe = require('tr-jwe');
const jwt = require('tr-jwt');

const { resolveKeyGenParams, generateVaultKey, KEYGEN_ALGS } = require('../keygen');
const { validateKek, loadKekFile, KekManager, kekInit } = require('../kek');
const { KekUnavailableError } = require('../errors');
const KeyStore = require('../keystore');
const { makeEcKekJwk, makeRsaKekJwk, makeOctKekJwk, writeKekFile } = require('./fixtures');

async function gen(params) {
	return generateVaultKey(resolveKeyGenParams(params));
}

test('keygen: generated JWK shapes', async function() {
	const oct = await gen({ alg: 'A256GCM' });
	assert.equal(oct.kty, 'oct');
	assert.equal(oct.secretKey.kty, 'oct');
	assert.equal(oct.secretKey.alg, 'A256GCM');
	assert.equal(oct.secretKey.use, 'enc');
	assert.equal(oct.secretKey.kid, oct.kid);
	assert.equal(Buffer.from(oct.secretKey.k, 'base64url').length, 32);
	assert.equal(oct.publicKey, null);

	const hmac = await gen({ alg: 'HS384' });
	assert.equal(Buffer.from(hmac.secretKey.k, 'base64url').length, 48);
	assert.deepEqual(hmac.secretKey.key_ops, [ 'sign', 'verify' ]);
	assert.equal(hmac.secretKey.use, 'sig');

	const wide = await gen({ alg: 'HS256', keyLength: 1024 });
	assert.equal(Buffer.from(wide.secretKey.k, 'base64url').length, 128);

	const ec = await gen({ alg: 'ES256' });
	assert.equal(ec.kty, 'EC');
	assert.equal(ec.secretKey.crv, 'P-256');
	assert.ok(ec.secretKey.d);
	assert.ok(! ec.publicKey.d);
	assert.equal(ec.publicKey.kid, ec.kid);
	assert.equal(ec.publicKey.alg, 'ES256');

	const ecdh = await gen({ alg: 'ECDH-ES' });
	assert.equal(ecdh.secretKey.crv, 'P-521');
	assert.equal(ecdh.publicKey.use, 'enc');

	const rsa = await gen({ alg: 'RS256' });
	assert.equal(rsa.kty, 'RSA');
	assert.equal(Buffer.from(rsa.secretKey.n, 'base64url').length * 8, 2048);
	assert.ok(rsa.secretKey.d);
	assert.ok(! rsa.publicKey.d);
});

test('keygen: exact JWK member sets must not drift', async function() {
	// These JWKs are embedded verbatim inside the stored JWEs and
	// consumed by tr-jwe/tr-jwt; the member sets are frozen regardless
	// of the key generation backend.
	const expected = {
		oct: { secret: [ 'alg', 'k', 'key_ops', 'kid', 'kty', 'use' ], public: null },
		EC: { secret: [ 'alg', 'crv', 'd', 'kid', 'kty', 'use', 'x', 'y' ],
			  public: [ 'alg', 'crv', 'kid', 'kty', 'use', 'x', 'y' ] },
		RSA: { secret: [ 'alg', 'd', 'dp', 'dq', 'e', 'kid', 'kty', 'n', 'p', 'q', 'qi', 'use' ],
			   public: [ 'alg', 'e', 'kid', 'kty', 'n', 'use' ] }
	};
	const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
	for (const alg of Object.keys(KEYGEN_ALGS)) {
		const spec = resolveKeyGenParams({ alg });
		const k = await generateVaultKey(spec);
		const e = expected[k.kty];
		assert.deepEqual(Object.keys(k.secretKey).sort(), e.secret, alg + ' secret member set');
		assert.equal(k.secretKey.alg, alg, alg);
		assert.equal(k.secretKey.use, spec.use, alg);
		assert.match(k.secretKey.kid, uuidRe, alg);
		assert.equal(k.secretKey.kid, k.kid, alg);
		if (e.public === null) {
			assert.equal(k.publicKey, null, alg);
			assert.deepEqual(k.secretKey.key_ops, spec.keyOps, alg);
		} else {
			assert.deepEqual(Object.keys(k.publicKey).sort(), e.public, alg + ' public member set');
			assert.equal(k.publicKey.kid, k.kid, alg);
			assert.equal(k.publicKey.alg, alg, alg);
			assert.equal(k.publicKey.use, spec.use, alg);
		}
	}
});

test('keygen: JWT sign/verify roundtrips', async function() {
	for (const alg of [ 'HS256', 'HS512', 'ES256', 'ES512', 'RS256' ]) {
		const k = await gen({ alg });
		const token = jwt.encode(alg, k.secretKey, { sub: 'test', n: 42 });
		const verifyKey = ((k.kty === 'oct') ? k.secretKey : k.publicKey);
		const payload = jwt.decode(token, verifyKey);
		assert.equal(payload.sub, 'test', alg);
		assert.equal(payload.n, 42, alg);
		// Header carries the kid.
		const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
		assert.equal(header.kid, k.kid, alg);
		assert.equal(header.alg, alg);
	}
});

test('keygen: JWE encrypt/decrypt roundtrips', async function() {
	for (const alg of [ 'A128GCMKW', 'A256GCMKW', 'A128KW', 'A256KW' ]) {
		const k = await gen({ alg });
		const token = jwe.encrypt(alg, k.secretKey, { secret: alg });
		assert.deepEqual(jwe.decrypt(token, k.secretKey), { secret: alg });
	}
	for (const alg of [ 'ECDH-ES', 'RSA-OAEP', 'RSA-OAEP-256' ]) {
		const k = await gen({ alg });
		// Encrypt with the public half only, decrypt with the secret.
		const token = jwe.encrypt(alg, k.publicKey, { secret: alg });
		assert.deepEqual(jwe.decrypt(token, k.secretKey), { secret: alg });
	}
});

test('kek: validation rules', function() {
	assert.ok(validateKek(makeEcKekJwk('k1')));
	assert.ok(validateKek(makeRsaKekJwk('k2', 'RSA-OAEP')));
	assert.ok(validateKek(makeRsaKekJwk('k2b', 'RSA-OAEP-256')));
	assert.ok(validateKek(makeOctKekJwk('k3', 'A256GCMKW')));
	assert.ok(validateKek(makeOctKekJwk('k4', 'A128KW')));
	// kid required.
	const noKid = makeEcKekJwk('k5');
	delete noKid.kid;
	assert.throws(function() { validateKek(noKid); }, /kid/);
	// Private key required for asymmetric KEKs.
	const pub = makeEcKekJwk('k6');
	delete pub.d;
	assert.throws(function() { validateKek(pub); }, /private/);
	// RSA KEK alg restricted to OAEP variants.
	const badAlg = makeRsaKekJwk('k7', 'RS256');
	assert.throws(function() { validateKek(badAlg); }, /RSA-OAEP/);
	// oct KEK key length must match the algorithm.
	const badLen = makeOctKekJwk('k8', 'A256GCMKW');
	badLen.k = Buffer.alloc(16).toString('base64url');
	assert.throws(function() { validateKek(badLen); }, /length/);
	// Unsupported oct algs (plain content-encryption algs are not KEKs).
	assert.throws(function() { validateKek(makeOctKekJwk('k9', 'A256GCM')); }, /oct algorithm/);
	// EC wrap algorithm resolution.
	assert.equal(validateKek(makeEcKekJwk('k10')).wrapAlg, 'ECDH-ES');
	assert.equal(validateKek(makeRsaKekJwk('k11', 'RSA-OAEP-256')).wrapAlg, 'RSA-OAEP-256');
});

test('kek: embed/extract roundtrip with every KEK type', async function() {
	const key = await gen({ alg: 'A256GCM' });
	for (const kekJwk of [ makeEcKekJwk('ec-kek'), makeRsaKekJwk('rsa-kek'),
						   makeOctKekJwk('oct-kek', 'A256GCMKW'), makeOctKekJwk('kw-kek', 'A128KW') ]) {
		const mgr = new KekManager(validateKek(kekJwk), []);
		const { embeddingKeyId, embeddedKey } = await mgr.embed(key.secretKey,
																{ kid: key.kid, iat: 1000, nbf: 900, exp: 2000 });
		assert.equal(embeddingKeyId, kekJwk.kid);
		// The embedded JWE protected header carries the KEK kid.
		const header = JSON.parse(Buffer.from(embeddedKey.split('.')[0], 'base64url').toString('utf8'));
		assert.equal(header.kid, kekJwk.kid);
		assert.equal(header.embedded_key_info, undefined);
		const extracted = await mgr.extract(embeddingKeyId, embeddedKey, key.kid);
		assert.deepEqual(extracted, key.secretKey);
	}
});

test('kek: extract failure modes', async function() {
	const key = await gen({ alg: 'A256GCM' });
	const mgr = new KekManager(validateKek(makeEcKekJwk('the-kek')), []);
	const { embeddingKeyId, embeddedKey } = await mgr.embed(key.secretKey, { kid: key.kid, iat: 1000 });
	// Unknown KEK id.
	await assert.rejects(mgr.extract('other-kek', embeddedKey, key.kid),
						 KekUnavailableError);
	// kid mismatch between row and embedded claims.
	await assert.rejects(mgr.extract(embeddingKeyId, embeddedKey, 'ffffffff-ffff-ffff-ffff-ffffffffffff'),
						 /kid mismatch/);
	// Tampered embedded JWE fails to decrypt.
	const tampered = embeddedKey.slice(0, -4) + 'AAAA';
	await assert.rejects(mgr.extract(embeddingKeyId, tampered, key.kid));
});

test('kek: retired KEK unwraps old embeddings', async function() {
	const key = await gen({ alg: 'HS256' });
	const oldKekJwk = makeEcKekJwk('old-kek');
	const oldMgr = new KekManager(validateKek(oldKekJwk), []);
	const wrapped = await oldMgr.embed(key.secretKey, { kid: key.kid, iat: 1 });
	// New active, old retired: old blob still unwraps.
	const newMgr = new KekManager(validateKek(makeEcKekJwk('new-kek')),
								  [ validateKek(oldKekJwk) ]);
	assert.deepEqual(await newMgr.extract(wrapped.embeddingKeyId, wrapped.embeddedKey, key.kid),
					 key.secretKey);
});

test('kek: file loading and permissions', async function(t) {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvkekt-'));
	t.after(async function() { await fs.rm(dir, { recursive: true, force: true }); });
	const jwk = makeEcKekJwk('file-kek');
	const file = await writeKekFile(dir, jwk);
	const loaded = await loadKekFile(file);
	assert.equal(loaded.kid, 'file-kek');
	// Group/world-readable KEK files are refused.
	const laxFile = path.join(dir, 'lax.json');
	await fs.writeFile(laxFile, JSON.stringify(jwk), { mode: 0o644 });
	await assert.rejects(loadKekFile(laxFile), /group or world/);
	// Invalid JSON is refused.
	const junkFile = path.join(dir, 'junk.json');
	await fs.writeFile(junkFile, 'not json', { mode: 0o600 });
	await assert.rejects(loadKekFile(junkFile), /not valid JSON/);
	// kekInit end to end.
	const retired = await writeKekFile(dir, makeEcKekJwk('file-kek-2'));
	const mgr = await kekInit(file, [ retired ]);
	assert.deepEqual(mgr.kekIds().sort(), [ 'file-kek', 'file-kek-2' ]);
	// Duplicate kids are refused.
	await assert.rejects(kekInit(file, [ file ]), /Duplicate/);
});

test('keystore: unwrap cache skips KEK crypto but tracks embedded_key', async function() {
	const key = await gen({ alg: 'A256GCM' });
	let extracts = 0;
	const mgr = new KekManager(validateKek(makeEcKekJwk('cache-kek')), []);
	const kekStub = {
		embed: mgr.embed.bind(mgr),
		extract: function(...av) { extracts++; return mgr.extract(...av); },
		activeKid: mgr.activeKid.bind(mgr),
		kekIds: mgr.kekIds.bind(mgr),
		hasKek: mgr.hasKek.bind(mgr)
	};
	const ks = new KeyStore({ db: null, kek: kekStub, cacheMaxEntries: 10, cacheTtlSeconds: 300 });
	const wrapped = await mgr.embed(key.secretKey, { kid: key.kid, iat: 1 });
	const row = { keyId: key.kid, embeddingKeyId: wrapped.embeddingKeyId, embeddedKey: wrapped.embeddedKey };
	assert.deepEqual(await ks.unwrap(row), key.secretKey);
	assert.deepEqual(await ks.unwrap(row), key.secretKey);
	assert.equal(extracts, 1, 'second unwrap is served from cache');
	// A rewrap (changed embedded_key) misses cleanly.
	const rewrapped = await mgr.embed(key.secretKey, { kid: key.kid, iat: 2 });
	const row2 = { keyId: key.kid, embeddingKeyId: rewrapped.embeddingKeyId, embeddedKey: rewrapped.embeddedKey };
	await ks.unwrap(row2);
	assert.equal(extracts, 2, 'changed embedded_key bypasses the cache');
	// Disabled cache always extracts.
	const ks0 = new KeyStore({ db: null, kek: kekStub, cacheMaxEntries: 0 });
	await ks0.unwrap(row);
	await ks0.unwrap(row);
	assert.equal(extracts, 4);
});
