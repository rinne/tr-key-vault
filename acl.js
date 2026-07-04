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

module.exports = { OP_CLASSES, validateAcl, aclAllows, aclAny };
