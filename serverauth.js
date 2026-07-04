'use strict';

const crypto = require('node:crypto');

const { isUuid, isPlainObject, isUnixTs } = require('./basicutils');
const { deriveClientIp } = require('./clientip');
const { ipAllowed } = require('./ipmatch');

// Authentication of an API request (SPEC.md §6). All failures are
// equivalent to the caller (one 403, no distinction); the returned
// reason is for the audit log only.

// Canonical token digest: sha256 of the lowercased bearer UUID
// string. This is what vault_user.auth_token stores.
function tokenHash(token) {
	return crypto.createHash('sha256').update(String(token).toLowerCase(), 'utf8').digest();
}

// Returns { ok: true, user, clientIp } on success and
// { ok: false, clientIp, claimedUser?, reason } on failure.
async function authenticate(ctx, req, envelope) {
	const clientIp = deriveClientIp(req.socket?.remoteAddress,
									req.headers['x-forwarded-for'],
									ctx.opt.value('trusted-proxy-hops'));
	const claimedUser = (isUuid(envelope?.user) ? envelope.user.toLowerCase() : undefined);
	const fail = function(reason) {
		return { ok: false, clientIp, claimedUser, reason };
	};
	const m = /^Bearer\s+(\S+)$/.exec(req.headers['authorization'] || '');
	if (! (m && isUuid(m[1]))) {
		return fail('bad-authorization-header');
	}
	const hash = tokenHash(m[1]);
	const user = await ctx.db.userByTokenHash(hash);
	if (! (user && user.authToken && crypto.timingSafeEqual(hash, user.authToken))) {
		return fail('unknown-token');
	}
	if (! (claimedUser && (claimedUser === String(user.userId).toLowerCase()))) {
		return fail('user-token-mismatch');
	}
	const data = (isPlainObject(user.data) ? user.data : {});
	const now = Math.floor(Date.now() / 1000);
	if (isUnixTs(data.nbf) && (data.nbf > now)) {
		return fail('user-not-yet-valid');
	}
	if (isUnixTs(data.exp) && (data.exp < now)) {
		return fail('user-expired');
	}
	// allowedIP fails closed: a missing or malformed property denies
	// everything, exactly like an empty array (SPEC.md §6).
	if (! (clientIp && ipAllowed(clientIp, data.allowedIP))) {
		return fail('ip-not-allowed');
	}
	return { ok: true, user, clientIp };
}

module.exports = { authenticate, tokenHash };
