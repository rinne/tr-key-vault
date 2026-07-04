'use strict';

const jwe = require('tr-jwe');
const jwt = require('tr-jwt');

const { isUuid, isPlainObject, isUnixTs } = require('./basicutils');
const { ERR, ApiError, KekUnavailableError } = require('./errors');
const { validateAcl, aclAllows, allowedOpsAllows } = require('./acl');
const { resolveKeyGenParams, JWT_ALGS, JWE_ALGS } = require('./keygen');

// API operation handlers (SPEC.md §9). Each handler is
// async (user, data, meta) -> { data, audit } and throws ApiError on
// operation-level failures. `meta` carries { op, clientIp }. The
// dispatcher in server.js does the audit append (strict coupling).

// Reject unknown properties in operation data — strict by design.
function checkProps(data, allowed) {
	if (! isPlainObject(data)) {
		throw new ApiError(ERR.INVALID_REQUEST_DATA);
	}
	for (const prop of Object.keys(data)) {
		if (! allowed.includes(prop)) {
			throw new ApiError(ERR.INVALID_REQUEST_DATA, `Unknown property: ${prop}`);
		}
	}
}

function requireKid(kid) {
	if (! isUuid(kid)) {
		throw new ApiError(ERR.INVALID_REQUEST_DATA, 'Invalid kid');
	}
	return kid.toLowerCase();
}

// Decode the protected header of a compact JOSE token. Returns the
// header object or throws ApiError invalid-input-token.
function decodeProtectedHeader(token) {
	if (! ((typeof(token) === 'string') && token)) {
		throw new ApiError(ERR.INVALID_INPUT_TOKEN);
	}
	const part = token.split('.')[0];
	try {
		const header = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
		if (! isPlainObject(header)) {
			throw new Error('not an object');
		}
		return header;
	} catch (_) {
		throw new ApiError(ERR.INVALID_INPUT_TOKEN);
	}
}

// kid resolution for verify-jwt / decrypt-jwe (SPEC.md §9.5): request
// kid and token-header kid, when both present, must match; at least
// one must be present.
function resolveKid(dataKid, header) {
	let reqKid;
	if (dataKid !== undefined) {
		reqKid = requireKid(dataKid);
	}
	let hdrKid;
	if (header.kid !== undefined) {
		if (! isUuid(header.kid)) {
			throw new ApiError(ERR.INVALID_INPUT_TOKEN);
		}
		hdrKid = header.kid.toLowerCase();
	}
	if (reqKid && hdrKid && (reqKid !== hdrKid)) {
		throw new ApiError(ERR.INVALID_INPUT_TOKEN);
	}
	const kid = reqKid || hdrKid;
	if (! kid) {
		throw new ApiError(ERR.INVALID_INPUT_TOKEN);
	}
	return kid;
}

function serverHandlers(ctx) {

	// Load a key row and authorize `opClass` on it for `user`.
	// Masking (SPEC.md §7): missing key, ACL denial and
	// out-of-window key are indistinguishable (key-not-found); ACL
	// denial of an existing key is additionally marked for the
	// `denied` audit event.
	async function authorizedKey(user, kid, opClass) {
		const row = await ctx.keystore.loadKey(kid);
		if (! row) {
			throw new ApiError(ERR.KEY_NOT_FOUND);
		}
		// Effective right = key ACL grant intersected with the user's
		// allowedOps mask (SPEC.md §7.1). A denial from either is
		// masked identically as key-not-found (existence masking).
		if (! (aclAllows(row.acl, user.userId, opClass) && allowedOpsAllows(user.data, opClass))) {
			const e = new ApiError(ERR.KEY_NOT_FOUND);
			e.maskedDenial = true;
			throw e;
		}
		if (! ctx.keystore.inWindow(row)) {
			throw new ApiError(ERR.KEY_NOT_FOUND);
		}
		return row;
	}

	// Unwrap the stored secret JWK; an unconfigured wrapping KEK is
	// reported as key-not-available — the caller is authorized at
	// this point (SPEC.md §5).
	function unwrapKey(row) {
		try {
			return ctx.keystore.unwrap(row);
		} catch (e) {
			if (e instanceof KekUnavailableError) {
				throw new ApiError(ERR.KEY_NOT_AVAILABLE);
			}
			throw e;
		}
	}

	return {

		'healthcheck': async function(user, data, meta) {
			checkProps(data, []);
			return { data: { uptime: Math.floor(process.uptime()) } };
		},

		'generate-key': async function(user, data, meta) {
			// A user-level pseudo-class with no target key ACL to mask
			// against — an ungranted caller gets a distinct 1107 (§7.1).
			if (! allowedOpsAllows(user.data, 'generate-key')) {
				throw new ApiError(ERR.OPERATION_NOT_PERMITTED);
			}
			checkProps(data, [ 'alg', 'kty', 'crv', 'keyLength', 'nbf', 'exp', 'acl', 'returnPublicKey' ]);
			let spec;
			try {
				spec = resolveKeyGenParams(data);
			} catch (e) {
				throw new ApiError(ERR.INVALID_REQUEST_DATA, e.message);
			}
			const now = Math.floor(Date.now() / 1000);
			if ((data.nbf !== undefined) && ! isUnixTs(data.nbf)) {
				throw new ApiError(ERR.INVALID_REQUEST_DATA, 'Invalid nbf');
			}
			if (data.exp !== undefined) {
				if (! (isUnixTs(data.exp) && (data.exp > now))) {
					throw new ApiError(ERR.INVALID_REQUEST_DATA, 'Invalid exp');
				}
				if ((data.nbf !== undefined) && (data.exp <= data.nbf)) {
					throw new ApiError(ERR.INVALID_REQUEST_DATA, 'Invalid exp');
				}
			}
			if ((data.returnPublicKey !== undefined) && (typeof(data.returnPublicKey) !== 'boolean')) {
				throw new ApiError(ERR.INVALID_REQUEST_DATA, 'Invalid returnPublicKey');
			}
			if (data.returnPublicKey && (spec.kty === 'oct')) {
				throw new ApiError(ERR.INVALID_REQUEST_DATA,
								   'returnPublicKey is only applicable to asymmetric keys');
			}
			const self = user.userId.toLowerCase();
			let acl;
			if (data.acl !== undefined) {
				// Explicit ACL in the request: the caller controls it (and
				// is auto-merged as owner); the user's coOwners are NOT
				// applied.
				try {
					const merged = {};
					if (! isPlainObject(data.acl)) {
						throw new Error('ACL must be an object');
					}
					Object.assign(merged, data.acl);
					const selfKey = Object.keys(merged).find(function(u) {
						return (String(u).toLowerCase() === self);
					});
					const selfOps = (selfKey !== undefined) ? merged[selfKey] : [];
					if (selfKey !== undefined) {
						delete merged[selfKey];
					}
					if (! Array.isArray(selfOps)) {
						throw new Error('ACL ops must be an array');
					}
					merged[self] = selfOps.concat(selfOps.includes('owner') ? [] : [ 'owner' ]);
					acl = validateAcl(merged);
				} catch (e) {
					throw new ApiError(ERR.INVALID_ACL, e.message);
				}
				const missing = await ctx.db.missingUsers(Object.keys(acl));
				if (missing.length > 0) {
					throw new ApiError(ERR.INVALID_ACL, 'Unknown ACL user');
				}
			} else {
				// No explicit ACL in the request: the caller is owner, plus
				// every VALID co-owner from the user's data.coOwners —
				// filtered to syntactic UUIDs and existing users (SPEC.md
				// §9.2). Invalid or since-deleted co-owners are dropped.
				const rawCo = Array.isArray(user.data && user.data.coOwners)
					? user.data.coOwners : [];
				const candidates = Array.from(new Set(
					rawCo.filter(isUuid).map(function(u) { return u.toLowerCase(); })
				)).filter(function(u) { return u !== self; });
				let coOwners = [];
				if (candidates.length > 0) {
					const missing = new Set(await ctx.db.missingUsers(candidates));
					coOwners = candidates.filter(function(u) { return ! missing.has(u); });
				}
				const aclObj = {};
				aclObj[self] = [ 'owner' ];
				for (const u of coOwners) {
					aclObj[u] = [ 'owner' ];
				}
				acl = validateAcl(aclObj);
			}
			const generated = await ctx.keystore.generate(spec, acl, { nbf: data.nbf, exp: data.exp });
			const rv = { kid: generated.kid };
			if (data.returnPublicKey) {
				rv.key = generated.publicKey;
			}
			const audit = { kid: generated.kid, kty: generated.kty, alg: generated.alg,
							aclUsers: Object.keys(acl) };
			if (data.nbf !== undefined) {
				audit.nbf = data.nbf;
			}
			if (data.exp !== undefined) {
				audit.exp = data.exp;
			}
			return { data: rv, audit };
		},

		'public-key': async function(user, data, meta) {
			checkProps(data, [ 'kid' ]);
			const kid = requireKid(data.kid);
			const row = await authorizedKey(user, kid, 'export-public-key');
			if (row.kty === 'oct') {
				throw new ApiError(ERR.INCOMPATIBLE_KEY_TYPE);
			}
			return { data: { key: row.publicKey }, audit: { kid } };
		},

		'create-jwt': async function(user, data, meta) {
			checkProps(data, [ 'kid', 'data' ]);
			const kid = requireKid(data.kid);
			if (! isPlainObject(data.data)) {
				throw new ApiError(ERR.INVALID_REQUEST_DATA, 'JWT payload must be an object');
			}
			const row = await authorizedKey(user, kid, 'sign');
			if (! JWT_ALGS.includes(row.alg)) {
				throw new ApiError(ERR.INCOMPATIBLE_KEY_TYPE);
			}
			const jwk = unwrapKey(row);
			let token;
			try {
				token = jwt.encode(row.alg, jwk, data.data);
			} catch (e) {
				if (/^Invalid JWT claim/.test(e?.message ?? '')) {
					throw new ApiError(ERR.INVALID_REQUEST_DATA, e.message);
				}
				throw e;
			}
			return { data: { token }, audit: { kid } };
		},

		'verify-jwt': async function(user, data, meta) {
			checkProps(data, [ 'token', 'kid' ]);
			const header = decodeProtectedHeader(data.token);
			const kid = resolveKid(data.kid, header);
			const row = await authorizedKey(user, kid, 'verify');
			if (! JWT_ALGS.includes(row.alg)) {
				throw new ApiError(ERR.INCOMPATIBLE_KEY_TYPE);
			}
			// Algorithm-confusion guard: the token must claim exactly
			// the stored key's algorithm.
			if (header.alg !== row.alg) {
				throw new ApiError(ERR.INVALID_INPUT_TOKEN);
			}
			const jwk = ((row.kty === 'oct') ? unwrapKey(row) : row.publicKey);
			let payload;
			try {
				payload = jwt.decode(data.token, jwk);
			} catch (e) {
				const msg = e?.message ?? '';
				if ((msg === 'JWT token expired') || (msg === 'JWT token not yet valid')) {
					throw new ApiError(ERR.INVALID_INPUT_TOKEN, msg);
				}
				throw new ApiError(ERR.INVALID_INPUT_TOKEN);
			}
			return { data: { header, data: payload }, audit: { kid } };
		},

		'create-jwe': async function(user, data, meta) {
			checkProps(data, [ 'kid', 'data', 'compress' ]);
			const kid = requireKid(data.kid);
			if (data.data === undefined) {
				throw new ApiError(ERR.INVALID_REQUEST_DATA, 'JWE payload is required');
			}
			if (! [ undefined, false, true, 'auto' ].includes(data.compress)) {
				throw new ApiError(ERR.INVALID_REQUEST_DATA, 'Invalid compress');
			}
			const row = await authorizedKey(user, kid, 'encrypt');
			if (! JWE_ALGS.includes(row.alg)) {
				throw new ApiError(ERR.INCOMPATIBLE_KEY_TYPE);
			}
			// Asymmetric keys encrypt with the public half from the
			// row — no KEK unwrap needed.
			const jwk = ((row.kty === 'oct') ? unwrapKey(row) : row.publicKey);
			const token = jwe.encrypt(row.alg, jwk, data.data,
									  { compressPayload: (data.compress ?? false) });
			return { data: { token }, audit: { kid } };
		},

		'decrypt-jwe': async function(user, data, meta) {
			checkProps(data, [ 'token', 'kid' ]);
			const header = decodeProtectedHeader(data.token);
			const kid = resolveKid(data.kid, header);
			const row = await authorizedKey(user, kid, 'decrypt');
			if (! JWE_ALGS.includes(row.alg)) {
				throw new ApiError(ERR.INCOMPATIBLE_KEY_TYPE);
			}
			if (header.alg !== row.alg) {
				throw new ApiError(ERR.INVALID_INPUT_TOKEN);
			}
			const jwk = unwrapKey(row);
			let payload;
			try {
				payload = jwe.decrypt(data.token, jwk);
			} catch (e) {
				throw new ApiError(ERR.INVALID_INPUT_TOKEN);
			}
			return { data: { header, data: payload }, audit: { kid } };
		},

		'revoke-key': async function(user, data, meta) {
			checkProps(data, [ 'kid' ]);
			const kid = requireKid(data.kid);
			await authorizedKey(user, kid, 'revoke-key');
			const revoked = await ctx.keystore.revoke(kid);
			if (! revoked) {
				// Row disappeared between load and delete.
				throw new ApiError(ERR.KEY_NOT_FOUND);
			}
			return { data: { kid, revoked: true }, audit: { kid } };
		},

		'export-key': async function(user, data, meta) {
			checkProps(data, [ 'kid' ]);
			const kid = requireKid(data.kid);
			// Config gate first: without --allow-export-key the
			// operation is disabled for everyone, revealing nothing
			// about any key.
			if (! ctx.opt.value('allow-export-key')) {
				throw new ApiError(ERR.OPERATION_DISABLED);
			}
			const row = await authorizedKey(user, kid, 'export-secret-key');
			const jwk = unwrapKey(row);
			return { data: { key: jwk }, audit: { kid } };
		},

		'list-keys': async function(user, data, meta) {
			checkProps(data, []);
			if (! allowedOpsAllows(user.data, 'list-keys')) {
				throw new ApiError(ERR.OPERATION_NOT_PERMITTED);
			}
			const keys = await ctx.keystore.listKeys(user.userId, user.data);
			return { data: { keys }, audit: { keyCount: keys.length } };
		}

	};

}

module.exports = serverHandlers;
