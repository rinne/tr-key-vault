'use strict';

const { isUuid, isPlainObject } = require('./basicutils');

// Operation classes a user can hold on a key. `owner` implies every
// other class, except operations disabled at configuration level
// (config always wins over ACL).
const OP_CLASSES = [
	'owner',
	'encrypt',
	'decrypt',
	'sign',
	'verify',
	'export-public-key',
	'export-secret-key',
	'revoke-key'
];

// Structural validation of an ACL object. Existence of the referenced
// users is a database concern and checked separately by the caller.
// Returns a normalized copy (lowercased user UUIDs, deduplicated
// classes) or throws Error with a human-readable reason.
function validateAcl(acl) {
	if (! isPlainObject(acl)) {
		throw new Error('ACL must be an object');
	}
	const normalized = {};
	let owners = 0;
	for (const [ user, ops ] of Object.entries(acl)) {
		if (! isUuid(user)) {
			throw new Error('ACL user must be an UUID');
		}
		const userLc = user.toLowerCase();
		if (normalized[userLc]) {
			throw new Error('Duplicate ACL user');
		}
		if (! Array.isArray(ops)) {
			throw new Error('ACL ops must be an array');
		}
		const seen = [];
		for (const op of ops) {
			if (! OP_CLASSES.includes(op)) {
				throw new Error('Unknown ACL operation class');
			}
			if (! seen.includes(op)) {
				seen.push(op);
			}
		}
		if (seen.includes('owner')) {
			owners++;
		}
		normalized[userLc] = seen;
	}
	if (owners < 1) {
		throw new Error('ACL must include at least one owner');
	}
	return normalized;
}

// True when `acl` grants operation class `opClass` to `userId`.
// `owner` implies all classes; configuration-level disables are the
// caller's responsibility.
function aclAllows(acl, userId, opClass) {
	if (! (isPlainObject(acl) && isUuid(userId) && OP_CLASSES.includes(opClass))) {
		return false;
	}
	const ops = acl[userId.toLowerCase()];
	if (! Array.isArray(ops)) {
		return false;
	}
	return (ops.includes(opClass) || ops.includes('owner'));
}

// True when `acl` grants any operation class at all to `userId`.
function aclAny(acl, userId) {
	if (! (isPlainObject(acl) && isUuid(userId))) {
		return false;
	}
	const ops = acl[userId.toLowerCase()];
	return (Array.isArray(ops) && (ops.length > 0));
}

// The key-ACL operation classes subject to the per-key ACL (all of
// OP_CLASSES except the `owner` meta-class).
const KEY_OP_CLASSES = OP_CLASSES.filter(function(c) { return c !== 'owner'; });

// The alphabet of the per-user `allowedOps` capability mask (SPEC.md
// §7.1): the key-ACL classes (not `owner`) plus two user-level
// pseudo-classes that have no per-key ACL to intersect with.
const ALLOWED_OPS_CLASSES = KEY_OP_CLASSES.concat([ 'generate-key', 'list-keys' ]);

// Structural validation of an `allowedOps` array. Returns a normalized
// (deduplicated) copy, or throws Error with a human-readable reason.
// An empty array is valid (it disables everything).
function validateAllowedOps(allowedOps) {
	if (! Array.isArray(allowedOps)) {
		throw new Error('allowedOps must be an array');
	}
	const seen = [];
	for (const op of allowedOps) {
		if (! ALLOWED_OPS_CLASSES.includes(op)) {
			throw new Error('Unknown allowedOps class');
		}
		if (! seen.includes(op)) {
			seen.push(op);
		}
	}
	return seen;
}

// Resolve a user's allowedOps to the effective mask, or null when the
// user is unrestricted. Absent property => null (unrestricted, the
// backward-compatible default). A present array is the mask (empty =>
// deny all). A present-but-malformed value fails closed (deny all).
function userAllowedOps(userData) {
	if (! isPlainObject(userData)) {
		return null;
	}
	const ao = userData.allowedOps;
	if (ao === undefined) {
		return null;
	}
	return Array.isArray(ao) ? ao : [];
}

// True when the user's allowedOps mask permits `opClass` (SPEC.md
// §7.1). Unrestricted users (no mask) permit everything.
function allowedOpsAllows(userData, opClass) {
	const ao = userAllowedOps(userData);
	if (ao === null) {
		return true;
	}
	return ao.includes(opClass);
}

// True when the user has any *effective* key-ACL class on the key:
// the ACL grant (owner expanded) intersected with the user's
// allowedOps mask. Used for list-keys visibility.
function effectiveAny(userData, acl, userId) {
	for (const cls of KEY_OP_CLASSES) {
		if (aclAllows(acl, userId, cls) && allowedOpsAllows(userData, cls)) {
			return true;
		}
	}
	return false;
}

module.exports = {
	OP_CLASSES,
	KEY_OP_CLASSES,
	ALLOWED_OPS_CLASSES,
	validateAcl,
	validateAllowedOps,
	aclAllows,
	aclAny,
	allowedOpsAllows,
	effectiveAny
};
