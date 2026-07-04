'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');

const { EventChainLogger, EventChainScheduler } = require('tr-json-chain');

const { isPlainObject } = require('./basicutils');

// Audit chain (SPEC.md §11): an append-only SHA-256 hash-chained
// event log in the same PostgreSQL database, namespace `kv` (tables
// kv_event_chain / kv_event_payload, owned by tr-json-chain).
//
// Event types use the colon-scoped convention with the prefix
// `tr-key-vault:`. Payloads never contain key material, bearer
// tokens, plaintext, or produced/consumed token strings.
//
// Failure coupling is STRICT: event() rethrows append failures and
// the caller must fail the operation — the vault never returns a
// success response for an unaudited operation.

const NAMESPACE = 'kv';
const TYPE_PREFIX = 'tr-key-vault:';
const HEARTBEAT_SECONDS = 60;

class Audit {

	#logger;
	#scheduler;
	#sealSecretKey;
	#sealInterval;
	#log;

	// options: { pool, sealSecretKey?, sealIntervalSeconds?, log? }
	constructor(options) {
		const { pool, sealSecretKey, sealIntervalSeconds, log } = Object.assign({}, options || {});
		this.#log = log || function() {};
		this.#sealSecretKey = sealSecretKey || null;
		this.#sealInterval = sealIntervalSeconds ?? 3600;
		const loggerOpts = { namespace: NAMESPACE };
		if (this.#sealSecretKey) {
			// The public seal key is fixed in the chain-root event at
			// the chain's FIRST init; rootExtraData has no effect on
			// an already-initialized chain (see README runbook).
			loggerOpts.rootExtraData = { sealKey: derivePublicSealJwk(this.#sealSecretKey) };
		}
		this.#logger = new EventChainLogger(pool, loggerOpts);
		this.#scheduler = null;
	}

	// Awaited at startup; a failure here is fatal (includes the
	// root-canary re-hash).
	async init() {
		await this.#logger.init();
	}

	// Start the periodic `ts` heartbeat (and `seal` events when a
	// seal key is configured). Server process only; kv-admin does not
	// schedule anything.
	startScheduler() {
		if (this.#scheduler) {
			return;
		}
		this.#scheduler = new EventChainScheduler(this.#logger, {
			onError: (e) => { this.#log(`audit scheduler error: ${e?.message ?? e}`); }
		});
		this.#scheduler.scheduleTimestamp(HEARTBEAT_SECONDS);
		if (this.#sealSecretKey) {
			this.#scheduler.scheduleSeal(this.#sealSecretKey, this.#sealInterval);
		}
	}

	stopScheduler() {
		if (this.#scheduler) {
			this.#scheduler.end();
			this.#scheduler = null;
		}
	}

	// Append an audit event. `type` is the unprefixed vault event
	// type (e.g. 'generate-key' or 'admin:add-user'); `fields` the
	// event payload beyond type/ts. Rethrows on failure — strict
	// coupling is the caller's contract.
	async event(type, fields) {
		const data = Object.assign({ type: TYPE_PREFIX + type,
									 ts: new Date().toISOString() },
								   fields || {});
		return this.#logger.recordEvent(data);
	}

	async verify(full) {
		return this.#logger.verify({ full: !! full, throwOnMismatch: false });
	}

	logger() {
		return this.#logger;
	}

}

// Derive the public JWK of a private seal JWK (for the chain-root
// sealKey property).
function derivePublicSealJwk(secretJwk) {
	const pub = crypto.createPublicKey(crypto.createPrivateKey({ key: secretJwk, format: 'jwk' }))
		  .export({ format: 'jwk' });
	delete pub.key_ops;
	for (const prop of [ 'alg', 'kid', 'use' ]) {
		if (secretJwk[prop] !== undefined) {
			pub[prop] = secretJwk[prop];
		}
	}
	return pub;
}

// Load a private seal JWK file (0600, like the KEKs).
async function loadSealKeyFile(file) {
	const st = await fs.stat(file);
	if ((st.mode & 0o077) !== 0) {
		throw new Error(`Audit seal key file ${file} must not be group or world accessible (chmod 600)`);
	}
	let jwk;
	try {
		jwk = JSON.parse(await fs.readFile(file, 'utf8'));
	} catch (e) {
		throw new Error(`Audit seal key file ${file} is not valid JSON`);
	}
	if (! (isPlainObject(jwk) && (typeof(jwk.alg) === 'string'))) {
		throw new Error(`Audit seal key file ${file} must contain a private JWK with alg`);
	}
	return jwk;
}

module.exports = { Audit, loadSealKeyFile, derivePublicSealJwk };
