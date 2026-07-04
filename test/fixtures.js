'use strict';

// Shared test fixtures: KEK JWK files, a stub optist-compatible `opt`
// object, and a full vault server harness for API tests.

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const dbMigrate = require('../dbmigrate');
const VaultDB = require('../serverdb');
const { attachPoolErrorHandler } = require('../dbinit');
const { kekInit } = require('../kek');
const { Audit } = require('../audit');
const KeyStore = require('../keystore');
const createServer = require('../server');
const { tokenHash } = require('../serverauth');

function makeEcKekJwk(kid, crv) {
	const pair = crypto.generateKeyPairSync('ec', {
		namedCurve: ({ 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' })[crv || 'P-521']
	});
	const jwk = pair.privateKey.export({ format: 'jwk' });
	delete jwk.key_ops;
	jwk.kid = kid;
	return jwk;
}

function makeRsaKekJwk(kid, alg, modulusLength) {
	const pair = crypto.generateKeyPairSync('rsa', { modulusLength: modulusLength || 2048 });
	const jwk = pair.privateKey.export({ format: 'jwk' });
	delete jwk.key_ops;
	jwk.alg = alg || 'RSA-OAEP';
	jwk.kid = kid;
	return jwk;
}

function makeOctKekJwk(kid, alg) {
	const a = alg || 'A256GCMKW';
	const bits = Number.parseInt(/^A(\d+)/.exec(a)[1]);
	return { kty: 'oct', k: crypto.randomBytes(bits / 8).toString('base64url'), alg: a, kid };
}

async function writeKekFile(dir, jwk) {
	const file = path.join(dir, `${jwk.kid}.json`);
	await fs.writeFile(file, JSON.stringify(jwk), { mode: 0o600 });
	return file;
}

// optist-compatible stub: value() over a plain map, mutable via set()
// so tests can flip configuration (e.g. allow-export-key) at runtime.
function stubOpt(values) {
	const map = Object.assign({
		'debug': false,
		'allow-export-key': false,
		'trusted-proxy-hops': 0,
		'max-request-body': 1048576,
		'request-timeout': 30,
		'expiry-sweep-interval': 60,
		'key-expiry-grace': 0,
		'key-cache-max-entries': 1024,
		'key-cache-ttl': 300
	}, values || {});
	return {
		value: function(name) {
			if (! (name in map)) {
				throw new Error(`stubOpt: unknown option ${name}`);
			}
			return map[name];
		},
		set: function(name, v) { map[name] = v; }
	};
}

// Full vault server on an ephemeral port against the given test
// cluster. Returns helpers for creating users and making API calls.
async function startVault(pg, options) {
	const opts = Object.assign({}, options || {});
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvkek-'));
	const activeJwk = opts.activeKekJwk || makeEcKekJwk('test-kek-1');
	const activeFile = await writeKekFile(dir, activeJwk);
	const retiredFiles = [];
	for (const jwk of (opts.retiredKekJwks || [])) {
		retiredFiles.push(await writeKekFile(dir, jwk));
	}
	const pool = pg.newPool();
	attachPoolErrorHandler(pool, function() {});
	await dbMigrate(pool, path.join(__dirname, '..', 'migrations'), { debug: function() {}, log: function() {} });
	const db = new VaultDB({ pool });
	await new Promise(function(resolve, reject) {
		db.on('ready', resolve);
		db.on('error', reject);
	});
	const kek = await kekInit(activeFile, retiredFiles);
	const audit = new Audit({ pool, log: function() {} });
	await audit.init();
	const opt = stubOpt(opts.opt);
	const ctx = {
		name: 'tr-key-vault', NAME: 'KV',
		opt, db, kek, audit,
		log: function() {}, debug: function() {}
	};
	ctx.keystore = new KeyStore({ db, kek, log: ctx.log,
								  cacheMaxEntries: opt.value('key-cache-max-entries'),
								  cacheTtlSeconds: opt.value('key-cache-ttl'),
								  sweepIntervalSeconds: opt.value('expiry-sweep-interval'),
								  expiryGraceSeconds: opt.value('key-expiry-grace') });
	const server = createServer(ctx);
	await new Promise(function(resolve, reject) {
		server.on('error', reject);
		server.listen(0, '127.0.0.1', resolve);
	});
	const baseUrl = `http://127.0.0.1:${server.address().port}`;

	async function createUser(userOpts) {
		const o = Object.assign({ allowedIP: [ '0.0.0.0/0', '0::/0' ] }, userOpts || {});
		const data = { allowedIP: o.allowedIP, iat: Math.floor(Date.now() / 1000) };
		if (o.nbf !== undefined) { data.nbf = o.nbf; }
		if (o.exp !== undefined) { data.exp = o.exp; }
		if (o.allowedOps !== undefined) { data.allowedOps = o.allowedOps; }
		const userId = await db.insertUser(data);
		const token = crypto.randomUUID();
		await db.setUserToken(userId, tokenHash(token));
		return { userId, token };
	}

	// Raw API call. `who` is { userId, token }; overrides allow
	// malformed requests for negative tests.
	async function call(request, data, who, overrides) {
		const o = Object.assign({}, overrides || {});
		const envelope = ('envelope' in o) ? o.envelope
			  : Object.assign({ user: who.userId, op: (o.op ?? crypto.randomUUID()),
								request, data: (data ?? {}) }, o.envelopeExtra || {});
		const headers = Object.assign({ 'Content-Type': (o.contentType ?? 'application/json') },
									  o.headers || {});
		if (! ('Authorization' in headers)) {
			headers['Authorization'] = `Bearer ${who.token}`;
		}
		const res = await fetch(`${baseUrl}${o.path ?? '/api/v1'}`, {
			method: (o.method ?? 'POST'),
			headers,
			body: (('body' in o) ? o.body : JSON.stringify(envelope))
		});
		let body = null;
		try {
			body = await res.json();
		} catch (_) { /* nothing */ }
		return { status: res.status, body, sentOp: envelope?.op };
	}

	async function stop() {
		await new Promise(function(resolve) { server.close(resolve); });
		await db.end();
		await fs.rm(dir, { recursive: true, force: true });
	}

	return { ctx, db, kek, audit, keystore: ctx.keystore, opt, server, baseUrl,
			 createUser, call, stop, kekDir: dir };
}

module.exports = { makeEcKekJwk, makeRsaKekJwk, makeOctKekJwk, writeKekFile,
				   stubOpt, startVault };
