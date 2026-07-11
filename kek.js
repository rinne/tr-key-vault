'use strict';

const fs = require('node:fs/promises');

const jwe = require('tr-jwe');

const { isPlainObject } = require('./basicutils');
const { KekUnavailableError } = require('./errors');

// Vault embedding keys (KEKs, SPEC.md §5). Exactly one active KEK
// wraps newly stored keys; retired KEKs only unwrap. All KEKs come
// from JWK files supplied by configuration; asymmetric KEKs are
// preferred and the wrap side then uses only the derived public half.

const KEK_OCT_ALGS = [ 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW' ];
const KEK_RSA_ALGS = [ 'RSA-OAEP', 'RSA-OAEP-256' ];
const KEK_EC_CURVES = [ 'P-256', 'P-384', 'P-521' ];
const KEK_RSA_MODULUS_MIN = 2048;
const KEK_OCT_BITS = { 'A128GCMKW': 128, 'A192GCMKW': 192, 'A256GCMKW': 256,
					   'A128KW': 128, 'A192KW': 192, 'A256KW': 256 };

// Validate a KEK JWK and return a descriptor
// { kid, wrapAlg, secretJwk, wrapJwk } where wrapJwk is what the
// wrap (encrypt) side uses: the derived public JWK for asymmetric
// KEKs, the oct JWK itself for symmetric ones. Throws on any
// validity problem.
function validateKek(jwk, source) {
	const fail = function(reason) {
		throw new Error(`Invalid embedding key${source ? (' (' + source + ')') : ''}: ${reason}`);
	};
	if (! isPlainObject(jwk)) {
		fail('not a JWK object');
	}
	if (! ((typeof(jwk.kid) === 'string') && jwk.kid)) {
		fail('kid is required');
	}
	if (jwk.kty === 'oct') {
		if (! KEK_OCT_ALGS.includes(jwk.alg)) {
			fail('unsupported oct algorithm');
		}
		if (typeof(jwk.k) !== 'string') {
			fail('missing key material');
		}
		if (Buffer.from(jwk.k, 'base64url').length !== (KEK_OCT_BITS[jwk.alg] / 8)) {
			fail('key length does not match algorithm');
		}
		return { kid: jwk.kid, wrapAlg: jwk.alg, secretJwk: jwk, wrapJwk: jwk };
	}
	if (jwk.kty === 'RSA') {
		if (! ((typeof(jwk.n) === 'string') && (typeof(jwk.e) === 'string') && (typeof(jwk.d) === 'string'))) {
			fail('RSA KEK must be a private key');
		}
		if (! KEK_RSA_ALGS.includes(jwk.alg)) {
			fail('RSA KEK alg must be RSA-OAEP or RSA-OAEP-256');
		}
		if ((Buffer.from(jwk.n, 'base64url').length * 8) < KEK_RSA_MODULUS_MIN) {
			fail(`RSA modulus must be at least ${KEK_RSA_MODULUS_MIN} bits`);
		}
		const wrapJwk = { kty: 'RSA', n: jwk.n, e: jwk.e, alg: jwk.alg, kid: jwk.kid };
		return { kid: jwk.kid, wrapAlg: jwk.alg, secretJwk: jwk, wrapJwk };
	}
	if (jwk.kty === 'EC') {
		if (! KEK_EC_CURVES.includes(jwk.crv)) {
			fail('unsupported EC curve');
		}
		if (! ((typeof(jwk.x) === 'string') && (typeof(jwk.y) === 'string') && (typeof(jwk.d) === 'string'))) {
			fail('EC KEK must be a private key');
		}
		if ((jwk.alg !== undefined) && (jwk.alg !== 'ECDH-ES')) {
			fail('EC KEK alg must be ECDH-ES');
		}
		const wrapJwk = { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y, kid: jwk.kid };
		return { kid: jwk.kid, wrapAlg: 'ECDH-ES', secretJwk: jwk, wrapJwk };
	}
	fail('unsupported key type');
}

// Load a KEK JWK file. Refuses group/world-readable files — the KEKs
// are the crown jewels (SPEC.md §16).
async function loadKekFile(file) {
	const st = await fs.stat(file);
	if ((st.mode & 0o077) !== 0) {
		throw new Error(`Embedding key file ${file} must not be group or world accessible (chmod 600)`);
	}
	let jwk;
	try {
		jwk = JSON.parse(await fs.readFile(file, 'utf8'));
	} catch (e) {
		throw new Error(`Embedding key file ${file} is not valid JSON`);
	}
	return validateKek(jwk, file);
}

class KekManager {

	#active;
	#byId;

	// Use kekInit() below; the constructor takes already-validated
	// descriptors.
	constructor(active, retired) {
		this.#active = active;
		this.#byId = new Map();
		this.#byId.set(active.kid, active);
		for (const k of (retired || [])) {
			if (this.#byId.has(k.kid)) {
				throw new Error(`Duplicate embedding key id ${k.kid}`);
			}
			this.#byId.set(k.kid, k);
		}
	}

	activeKid() {
		return this.#active.kid;
	}

	kekIds() {
		return Array.from(this.#byId.keys());
	}

	hasKek(kid) {
		return this.#byId.has(kid);
	}

	// Wrap a secret JWK into the stored embedded-key JWE
	// (JWE-KEY-EMBEDDING.md; SPEC.md §5.1). Returns
	// { embeddingKeyId, embeddedKey }. Asynchronous: the JWE crypto
	// runs off the event loop where tr-jwe supports it.
	async embed(secretJwk, meta) {
		const claims = { kid: meta.kid, iat: meta.iat };
		if (meta.nbf !== undefined) {
			claims.nbf = meta.nbf;
		}
		if (meta.exp !== undefined) {
			claims.exp = meta.exp;
		}
		claims.key = secretJwk;
		const embeddedKey = await jwe.encryptAsync(this.#active.wrapAlg, this.#active.wrapJwk, claims);
		return { embeddingKeyId: this.#active.kid, embeddedKey };
	}

	// Unwrap a stored embedded-key JWE. Verifies the embedding-spec
	// consistency rules before returning the JWK. Throws
	// KekUnavailableError when the wrapping KEK is not configured.
	async extract(embeddingKeyId, embeddedKey, expectedKid) {
		const kek = this.#byId.get(embeddingKeyId);
		if (! kek) {
			throw new KekUnavailableError(embeddingKeyId);
		}
		const claims = await jwe.decryptAsync(embeddedKey, kek.secretJwk);
		if (! (isPlainObject(claims) && isPlainObject(claims.key))) {
			throw new Error('Embedded key payload is not a key embedding');
		}
		if (claims.key.kid !== expectedKid) {
			throw new Error('Embedded key kid mismatch');
		}
		if ((claims.kid !== undefined) && (claims.kid !== expectedKid)) {
			throw new Error('Embedded key claims kid mismatch');
		}
		return claims.key;
	}

}

// Load and validate the active + retired KEK files and return a
// ready KekManager. Fail-fast: any unreadable or invalid file throws.
async function kekInit(activeFile, retiredFiles) {
	const active = await loadKekFile(activeFile);
	const retired = [];
	for (const f of (retiredFiles || [])) {
		retired.push(await loadKekFile(f));
	}
	return new KekManager(active, retired);
}

module.exports = { kekInit, KekManager, validateKek, loadKekFile };
