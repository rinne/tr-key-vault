'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const { isPlainObject } = require('./basicutils');

// Key pair generation is asynchronous (libuv thread pool) so that RSA
// generation in particular never blocks the event loop; symmetric key
// generation is cheap but uses the async form for uniformity.
const generateKeyPair = promisify(crypto.generateKeyPair);
const generateKey = promisify(crypto.generateKey);

// The v1 algorithm matrix (SPEC.md §9.2). Deliberately excluded:
// dir, RSA1_5, PS*, ML-DSA, alg-less generation.
const KEYGEN_ALGS = {
	'A128GCM':   { kty: 'oct', kind: 'aes', bits: 128, use: 'enc', keyOps: [ 'encrypt', 'decrypt' ] },
	'A192GCM':   { kty: 'oct', kind: 'aes', bits: 192, use: 'enc', keyOps: [ 'encrypt', 'decrypt' ] },
	'A256GCM':   { kty: 'oct', kind: 'aes', bits: 256, use: 'enc', keyOps: [ 'encrypt', 'decrypt' ] },
	'A128GCMKW': { kty: 'oct', kind: 'aes', bits: 128, use: 'enc', keyOps: [ 'wrapKey', 'unwrapKey' ] },
	'A192GCMKW': { kty: 'oct', kind: 'aes', bits: 192, use: 'enc', keyOps: [ 'wrapKey', 'unwrapKey' ] },
	'A256GCMKW': { kty: 'oct', kind: 'aes', bits: 256, use: 'enc', keyOps: [ 'wrapKey', 'unwrapKey' ] },
	'A128KW':    { kty: 'oct', kind: 'aes', bits: 128, use: 'enc', keyOps: [ 'wrapKey', 'unwrapKey' ] },
	'A192KW':    { kty: 'oct', kind: 'aes', bits: 192, use: 'enc', keyOps: [ 'wrapKey', 'unwrapKey' ] },
	'A256KW':    { kty: 'oct', kind: 'aes', bits: 256, use: 'enc', keyOps: [ 'wrapKey', 'unwrapKey' ] },
	'HS256':     { kty: 'oct', kind: 'hmac', minBits: 256, use: 'sig', keyOps: [ 'sign', 'verify' ] },
	'HS384':     { kty: 'oct', kind: 'hmac', minBits: 384, use: 'sig', keyOps: [ 'sign', 'verify' ] },
	'HS512':     { kty: 'oct', kind: 'hmac', minBits: 512, use: 'sig', keyOps: [ 'sign', 'verify' ] },
	'ECDH-ES':   { kty: 'EC', kind: 'ec', curves: [ 'P-256', 'P-384', 'P-521' ], defaultCurve: 'P-521', use: 'enc' },
	'ES256':     { kty: 'EC', kind: 'ec', curves: [ 'P-256' ], defaultCurve: 'P-256', use: 'sig' },
	'ES384':     { kty: 'EC', kind: 'ec', curves: [ 'P-384' ], defaultCurve: 'P-384', use: 'sig' },
	'ES512':     { kty: 'EC', kind: 'ec', curves: [ 'P-521' ], defaultCurve: 'P-521', use: 'sig' },
	'RSA-OAEP':     { kty: 'RSA', kind: 'rsa', defaultModulus: 2048, use: 'enc' },
	'RSA-OAEP-256': { kty: 'RSA', kind: 'rsa', defaultModulus: 4096, use: 'enc' },
	'RS256':     { kty: 'RSA', kind: 'rsa', defaultModulus: 2048, use: 'sig' },
	'RS384':     { kty: 'RSA', kind: 'rsa', defaultModulus: 3072, use: 'sig' },
	'RS512':     { kty: 'RSA', kind: 'rsa', defaultModulus: 4096, use: 'sig' }
};

const OCT_MAX_BITS = 4096;
const RSA_MODULUS_MIN = 2048;
const RSA_MODULUS_MAX = 16384;

// Named curve mapping for node:crypto.
const EC_NAMED_CURVE = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' };

// Resolve and validate the generation parameters of a generate-key
// request ({ alg, kty?, crv?, keyLength? }). Returns a normalized
// spec object or throws Error with a human-readable reason (mapped to
// invalid-request-data by the caller).
function resolveKeyGenParams(params) {
	if (! isPlainObject(params)) {
		throw new Error('Invalid key generation parameters');
	}
	const { alg, kty, crv, keyLength } = params;
	if (! ((typeof(alg) === 'string') && KEYGEN_ALGS[alg])) {
		throw new Error('Unsupported algorithm');
	}
	const a = KEYGEN_ALGS[alg];
	if ((kty !== undefined) && (kty !== a.kty)) {
		throw new Error('Key type does not match algorithm');
	}
	const spec = { alg, kty: a.kty, kind: a.kind, use: a.use, keyOps: a.keyOps };
	if (a.kind === 'ec') {
		if (keyLength !== undefined) {
			throw new Error('keyLength is not applicable to EC keys');
		}
		if (crv === undefined) {
			spec.crv = a.defaultCurve;
		} else if (a.curves.includes(crv)) {
			spec.crv = crv;
		} else {
			throw new Error('Curve does not match algorithm');
		}
	} else if (crv !== undefined) {
		throw new Error('crv is only applicable to EC keys');
	}
	if (a.kind === 'aes') {
		if ((keyLength !== undefined) && (keyLength !== a.bits)) {
			throw new Error('keyLength does not match algorithm');
		}
		spec.bits = a.bits;
	} else if (a.kind === 'hmac') {
		if (keyLength === undefined) {
			spec.bits = a.minBits;
		} else if (Number.isSafeInteger(keyLength) &&
				   (keyLength >= a.minBits) &&
				   (keyLength <= OCT_MAX_BITS) &&
				   ((keyLength % 8) === 0)) {
			spec.bits = keyLength;
		} else {
			throw new Error('Invalid keyLength for algorithm');
		}
	} else if (a.kind === 'rsa') {
		if (keyLength === undefined) {
			spec.modulusLength = a.defaultModulus;
		} else if (Number.isSafeInteger(keyLength) &&
				   (keyLength >= RSA_MODULUS_MIN) &&
				   (keyLength <= RSA_MODULUS_MAX)) {
			spec.modulusLength = keyLength;
		} else {
			throw new Error('Invalid keyLength for algorithm');
		}
	}
	return spec;
}

// Generate a key or key pair from a spec produced by
// resolveKeyGenParams(). Returns
// { kid, kty, alg, secretKey, publicKey } where secretKey is the full
// JWK (secret material) and publicKey the public JWK or null for
// symmetric keys. Both JWKs carry kid, alg and use; the oct member
// set additionally carries key_ops. The member sets follow the
// tr-data-escrow / tr-jwk conventions and must not drift — these JWKs
// are embedded verbatim inside the stored JWEs and consumed by
// tr-jwe/tr-jwt.
async function generateVaultKey(spec) {
	const kid = crypto.randomUUID();
	if (spec.kind === 'aes') {
		const key = await generateKey('aes', { length: spec.bits });
		const jwk = key.export({ format: 'jwk' });
		const secretKey = { kty: 'oct', k: jwk.k, alg: spec.alg, key_ops: spec.keyOps.slice(), use: spec.use, kid };
		return { kid, kty: 'oct', alg: spec.alg, secretKey, publicKey: null };
	}
	if (spec.kind === 'hmac') {
		const key = await generateKey('hmac', { length: spec.bits });
		const jwk = key.export({ format: 'jwk' });
		const secretKey = { kty: 'oct', k: jwk.k, alg: spec.alg, key_ops: spec.keyOps.slice(), use: spec.use, kid };
		return { kid, kty: 'oct', alg: spec.alg, secretKey, publicKey: null };
	}
	if (spec.kind === 'ec') {
		const pair = await generateKeyPair('ec', { namedCurve: EC_NAMED_CURVE[spec.crv] });
		return { kid, kty: 'EC', alg: spec.alg, ...exportPair(pair, kid, spec.alg, spec.use) };
	}
	if (spec.kind === 'rsa') {
		const pair = await generateKeyPair('rsa', { modulusLength: spec.modulusLength });
		return { kid, kty: 'RSA', alg: spec.alg, ...exportPair(pair, kid, spec.alg, spec.use) };
	}
	throw new Error('Internal error');
}

function exportPair(pair, kid, alg, use) {
	const secretKey = pair.privateKey.export({ format: 'jwk' });
	const publicKey = pair.publicKey.export({ format: 'jwk' });
	delete secretKey.key_ops;
	delete publicKey.key_ops;
	secretKey.alg = alg;
	secretKey.use = use;
	secretKey.kid = kid;
	publicKey.alg = alg;
	publicKey.use = use;
	publicKey.kid = kid;
	return { secretKey, publicKey };
}

// Operation compatibility sets (SPEC.md §9.4–§9.7).
const JWT_ALGS = [ 'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512' ];
const JWE_ALGS = [ 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW', 'ECDH-ES', 'RSA-OAEP', 'RSA-OAEP-256' ];

module.exports = { KEYGEN_ALGS, JWT_ALGS, JWE_ALGS, resolveKeyGenParams, generateVaultKey,
				   RSA_MODULUS_MIN, RSA_MODULUS_MAX, OCT_MAX_BITS };
