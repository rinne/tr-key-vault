'use strict';

const crypto = require('node:crypto');

const { generateVaultKey } = require('./keygen');
const { aclAny } = require('./acl');

// Keystore: persistence and lifecycle of vault keys on top of the DB
// layer and the KEK manager (SPEC.md §9.2, §10).
//
// The unwrap cache only ever skips the KEK-unwrap crypto: the DB row
// (ACL, validity window, existence) is fetched fresh on every request
// by the caller. Entries are keyed by key id and validated against
// sha256(embedded_key), so a rewrap or any row change misses cleanly;
// a hard-deleted key can never be served stale because the row fetch
// fails first.

class KeyStore {

	#db;
	#kek;
	#log;
	#cacheMaxEntries;
	#cacheTtlMs;
	#sweepIntervalMs;
	#expiryGraceSeconds;
	#cache;
	#sweepTimer;

	constructor(options) {
		const { db, kek, log, cacheMaxEntries, cacheTtlSeconds,
				sweepIntervalSeconds, expiryGraceSeconds } = Object.assign({}, options || {});
		this.#db = db;
		this.#kek = kek;
		this.#log = log || function() {};
		this.#cacheMaxEntries = cacheMaxEntries ?? 1024;
		this.#cacheTtlMs = (cacheTtlSeconds ?? 300) * 1000;
		this.#sweepIntervalMs = (sweepIntervalSeconds ?? 60) * 1000;
		this.#expiryGraceSeconds = expiryGraceSeconds ?? 0;
		this.#cache = new Map();
		this.#sweepTimer = null;
	}

	// Generate, embed and store a new key. `spec` comes from
	// resolveKeyGenParams(), `acl` is a normalized ACL object, `nbf`
	// and `exp` are optional unix timestamps. Returns
	// { kid, kty, alg, publicKey }.
	async generate(spec, acl, meta) {
		const { nbf, exp } = Object.assign({}, meta || {});
		const generated = await generateVaultKey(spec);
		const iat = Math.floor(Date.now() / 1000);
		const embedMeta = { kid: generated.kid, iat };
		if (nbf !== undefined) {
			embedMeta.nbf = nbf;
		}
		if (exp !== undefined) {
			embedMeta.exp = exp;
		}
		const { embeddingKeyId, embeddedKey } = this.#kek.embed(generated.secretKey, embedMeta);
		await this.#db.insertKey({
			keyId: generated.kid,
			kty: generated.kty,
			alg: generated.alg,
			notBefore: nbf,
			expiresAt: exp,
			publicKey: generated.publicKey,
			embeddingKeyId,
			embeddedKey,
			acl
		});
		return { kid: generated.kid, kty: generated.kty, alg: generated.alg,
				 publicKey: generated.publicKey };
	}

	async loadKey(kid) {
		return this.#db.keyById(kid);
	}

	// True when the key is inside its validity window. Enforced at
	// read time on every access — the sweep is hygiene, not the
	// security boundary.
	inWindow(row, nowMs) {
		const now = nowMs ?? Date.now();
		if (row.notBefore && (row.notBefore.getTime() > now)) {
			return false;
		}
		if (row.expiresAt && (row.expiresAt.getTime() <= now)) {
			return false;
		}
		return true;
	}

	// Unwrap the stored secret JWK of a key row, via the bounded
	// LRU+TTL cache. Throws KekUnavailableError when the wrapping KEK
	// is not configured.
	unwrap(row) {
		if (this.#cacheMaxEntries < 1) {
			return this.#kek.extract(row.embeddingKeyId, row.embeddedKey, row.keyId);
		}
		const embHash = crypto.createHash('sha256').update(row.embeddedKey).digest('hex');
		const now = Date.now();
		const cached = this.#cache.get(row.keyId);
		if (cached) {
			this.#cache.delete(row.keyId);
			if ((cached.embHash === embHash) && (cached.expires > now)) {
				this.#cache.set(row.keyId, cached);
				return cached.jwk;
			}
		}
		const jwk = this.#kek.extract(row.embeddingKeyId, row.embeddedKey, row.keyId);
		this.#cache.set(row.keyId, { embHash, jwk, expires: now + this.#cacheTtlMs });
		while (this.#cache.size > this.#cacheMaxEntries) {
			this.#cache.delete(this.#cache.keys().next().value);
		}
		return jwk;
	}

	cacheClear() {
		this.#cache.clear();
	}

	// Hard delete (SPEC.md §9.8). Returns true when a row was deleted.
	async revoke(kid) {
		const deleted = await this.#db.deleteKey(kid);
		this.#cache.delete(kid);
		return deleted;
	}

	// Keys the user holds at least one ACL class on, inside their
	// validity window (SPEC.md §9.10).
	async listKeys(userId) {
		const rows = await this.#db.keysByAclUser(userId);
		const now = Date.now();
		return rows
			.filter((row) => (this.inWindow(row, now) && aclAny(row.acl, userId)))
			.map(function(row) { return { kid: row.keyId, kty: row.kty, alg: row.alg }; });
	}

	async sweep() {
		const n = await this.#db.sweepExpiredKeys(this.#expiryGraceSeconds);
		if (n > 0) {
			this.#log(`keystore: expiry sweep deleted ${n} key(s)`);
		}
		return n;
	}

	startSweep() {
		if (this.#sweepTimer) {
			return;
		}
		this.#sweepTimer = setInterval(() => {
			this.sweep().catch((e) => {
				this.#log(`keystore: expiry sweep error: ${e.message}`);
			});
		}, this.#sweepIntervalMs);
		this.#sweepTimer.unref();
	}

	stopSweep() {
		if (this.#sweepTimer) {
			clearInterval(this.#sweepTimer);
			this.#sweepTimer = null;
		}
	}

}

module.exports = KeyStore;
