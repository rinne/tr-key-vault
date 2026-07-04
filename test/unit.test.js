'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { ipAllowed, validateAllowedIP, parseIPv4, parseIPv6 } = require('../ipmatch');
const { deriveClientIp } = require('../clientip');
const { OP_CLASSES, ALLOWED_OPS_CLASSES, validateAcl, validateAllowedOps,
		aclAllows, aclAny, allowedOpsAllows, effectiveAny } = require('../acl');
const { resolveKeyGenParams, KEYGEN_ALGS } = require('../keygen');
const { isUuid, isPlainObject } = require('../basicutils');

test('ipmatch: IPv4 parsing', function() {
	assert.equal(parseIPv4('1.2.3.4'), 0x01020304);
	assert.equal(parseIPv4('0.0.0.0'), 0);
	assert.equal(parseIPv4('255.255.255.255'), 0xffffffff);
	assert.equal(parseIPv4('256.1.1.1'), null);
	assert.equal(parseIPv4('1.2.3'), null);
	assert.equal(parseIPv4('::1'), null);
});

test('ipmatch: IPv6 parsing', function() {
	assert.equal(parseIPv6('::1'), 1n);
	assert.equal(parseIPv6('::'), 0n);
	assert.equal(parseIPv6('2001:db8::1'), (0x20010db8n << 96n) | 1n);
	assert.equal(parseIPv6('::ffff:1.2.3.4'), (0xffffn << 32n) | 0x01020304n);
	assert.equal(parseIPv6('1:2:3:4:5:6:7:8'), parseIPv6('1:2:3:4:5:6:7:8'));
	assert.equal(parseIPv6('1:2:3:4:5:6:7:8:9'), null);
	assert.equal(parseIPv6('1::2::3'), null);
	assert.equal(parseIPv6('1.2.3.4'), null);
});

test('ipmatch: matching semantics', function() {
	assert.equal(ipAllowed('1.2.3.4', [ '1.2.3.4' ]), true);
	assert.equal(ipAllowed('1.2.3.5', [ '1.2.3.4' ]), false);
	assert.equal(ipAllowed('1.2.3.99', [ '1.2.3.0/24' ]), true);
	assert.equal(ipAllowed('1.2.4.1', [ '1.2.3.0/24' ]), false);
	assert.equal(ipAllowed('9.9.9.9', [ '0.0.0.0/0' ]), true);
	assert.equal(ipAllowed('1.2.3.50', [ '1.2.3.4-1.2.3.99' ]), true);
	assert.equal(ipAllowed('1.2.3.100', [ '1.2.3.4-1.2.3.99' ]), false);
	assert.equal(ipAllowed('2001:db8::42', [ '2001:db8::/32' ]), true);
	assert.equal(ipAllowed('2001:db9::42', [ '2001:db8::/32' ]), false);
	assert.equal(ipAllowed('2001:db8::1', [ '2001:db8::1' ]), true);
	assert.equal(ipAllowed('::1', [ '0::/0' ]), true);
	// Family separation: v4 entry never matches v6 client and vice versa.
	assert.equal(ipAllowed('1.2.3.4', [ '0::/0' ]), false);
	assert.equal(ipAllowed('::1', [ '0.0.0.0/0' ]), false);
	// Empty and missing lists deny everything.
	assert.equal(ipAllowed('1.2.3.4', []), false);
	assert.equal(ipAllowed('1.2.3.4', undefined), false);
	assert.equal(ipAllowed('1.2.3.4', 'nonsense'), false);
	// Invalid entries never allow.
	assert.equal(ipAllowed('1.2.3.4', [ 'x.y.z.w', '1.2.3.4/99', '::1-::2' ]), false);
});

test('ipmatch: validateAllowedIP', function() {
	assert.deepEqual(validateAllowedIP([ '1.2.3.4', '10.0.0.0/8', '2001:db8::/32' ]), []);
	assert.deepEqual(validateAllowedIP([ 'bogus' ]), [ 'bogus' ]);
	// IPv6 start-end ranges are deliberately excluded.
	assert.deepEqual(validateAllowedIP([ '::1-::2' ]), [ '::1-::2' ]);
	assert.deepEqual(validateAllowedIP('nope'), [ '(not an array)' ]);
});

test('clientip: trusted proxy hops', function() {
	// hops=0: socket peer wins, XFF ignored.
	assert.equal(deriveClientIp('10.0.0.1', '9.9.9.9, 8.8.8.8', 0), '10.0.0.1');
	// hops=1: one trusted proxy; rightmost XFF entry is the client.
	assert.equal(deriveClientIp('10.0.0.1', '6.6.6.6, 7.7.7.7', 1), '7.7.7.7');
	// hops=2: forged prefix beyond the trusted depth is ignored.
	assert.equal(deriveClientIp('10.0.0.1', '6.6.6.6, 7.7.7.7', 2), '6.6.6.6');
	// Fewer XFF entries than hops: clamped, socket peer preserved.
	assert.equal(deriveClientIp('10.0.0.1', undefined, 1), '10.0.0.1');
	// IPv4-mapped IPv6 unwrapping.
	assert.equal(deriveClientIp('::ffff:10.0.0.1', undefined, 0), '10.0.0.1');
});

test('acl: validateAcl', function() {
	const u1 = '11111111-1111-1111-1111-111111111111';
	const u2 = '22222222-2222-2222-2222-222222222222';
	const acl = validateAcl({ [u1.toUpperCase()]: [ 'owner', 'owner', 'sign' ], [u2]: [ 'decrypt' ] });
	assert.deepEqual(acl[u1], [ 'owner', 'sign' ]);
	assert.deepEqual(acl[u2], [ 'decrypt' ]);
	assert.throws(function() { validateAcl({ [u2]: [ 'decrypt' ] }); }, /owner/);
	assert.throws(function() { validateAcl({ [u1]: [ 'own' ] }); }, /Unknown ACL operation class/);
	assert.throws(function() { validateAcl({ 'not-a-uuid': [ 'owner' ] }); }, /UUID/);
	assert.throws(function() { validateAcl({ [u1]: 'owner' }); }, /array/);
	assert.throws(function() { validateAcl([ u1 ]); }, /object/);
	const ua = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
	assert.throws(function() { validateAcl({ [ua]: [ 'owner' ], [ua.toUpperCase()]: [ 'sign' ] }); }, /Duplicate/);
});

test('acl: aclAllows owner implication', function() {
	const u1 = '11111111-1111-1111-1111-111111111111';
	const u2 = '22222222-2222-2222-2222-222222222222';
	const acl = { [u1]: [ 'owner' ], [u2]: [ 'decrypt' ] };
	for (const cls of OP_CLASSES) {
		assert.equal(aclAllows(acl, u1, cls), true, `owner implies ${cls}`);
	}
	assert.equal(aclAllows(acl, u1.toUpperCase(), 'sign'), true);
	assert.equal(aclAllows(acl, u2, 'decrypt'), true);
	assert.equal(aclAllows(acl, u2, 'encrypt'), false);
	assert.equal(aclAllows(acl, '33333333-3333-3333-3333-333333333333', 'decrypt'), false);
	assert.equal(aclAllows(acl, u2, 'bogus-class'), false);
	assert.equal(aclAny(acl, u2), true);
	assert.equal(aclAny({ [u2]: [] }, u2), false);
	assert.equal(aclAny(acl, '33333333-3333-3333-3333-333333333333'), false);
});

test('acl: validateAllowedOps', function() {
	// The alphabet is the 7 key classes + two pseudo-classes, not owner.
	assert.ok(! ALLOWED_OPS_CLASSES.includes('owner'));
	for (const c of [ 'encrypt', 'decrypt', 'sign', 'verify', 'export-public-key',
					  'export-secret-key', 'revoke-key', 'generate-key', 'list-keys' ]) {
		assert.ok(ALLOWED_OPS_CLASSES.includes(c), c);
	}
	assert.deepEqual(validateAllowedOps([ 'encrypt', 'encrypt', 'list-keys' ]),
					 [ 'encrypt', 'list-keys' ]);
	assert.deepEqual(validateAllowedOps([]), []);
	assert.throws(function() { validateAllowedOps([ 'owner' ]); }, /Unknown allowedOps class/);
	assert.throws(function() { validateAllowedOps([ 'sudo' ]); }, /Unknown allowedOps class/);
	assert.throws(function() { validateAllowedOps('encrypt'); }, /must be an array/);
});

test('acl: allowedOpsAllows — absent unrestricted, empty deny-all', function() {
	// Absent property => unrestricted.
	assert.equal(allowedOpsAllows({ allowedIP: [] }, 'decrypt'), true);
	assert.equal(allowedOpsAllows({}, 'generate-key'), true);
	// Present mask => membership.
	const u = { allowedOps: [ 'encrypt', 'export-public-key', 'generate-key' ] };
	assert.equal(allowedOpsAllows(u, 'encrypt'), true);
	assert.equal(allowedOpsAllows(u, 'export-public-key'), true);
	assert.equal(allowedOpsAllows(u, 'generate-key'), true);
	assert.equal(allowedOpsAllows(u, 'decrypt'), false);
	assert.equal(allowedOpsAllows(u, 'export-secret-key'), false);
	assert.equal(allowedOpsAllows(u, 'list-keys'), false);
	// Empty array => deny everything.
	assert.equal(allowedOpsAllows({ allowedOps: [] }, 'encrypt'), false);
	assert.equal(allowedOpsAllows({ allowedOps: [] }, 'generate-key'), false);
	// Malformed present value fails closed.
	assert.equal(allowedOpsAllows({ allowedOps: 'encrypt' }, 'encrypt'), false);
});

test('acl: effectiveAny — ACL grant intersected with allowedOps', function() {
	const u1 = '11111111-1111-4111-8111-111111111111';
	const acl = { [u1]: [ 'owner' ] };
	// Owner + unrestricted => has effective classes.
	assert.equal(effectiveAny({}, acl, u1), true);
	// Owner but allowedOps only encrypt => still effective (encrypt).
	assert.equal(effectiveAny({ allowedOps: [ 'encrypt' ] }, acl, u1), true);
	// Owner but allowedOps only the pseudo-classes => no effective *key* class.
	assert.equal(effectiveAny({ allowedOps: [ 'list-keys', 'generate-key' ] }, acl, u1), false);
	// Empty mask => nothing.
	assert.equal(effectiveAny({ allowedOps: [] }, acl, u1), false);
	// Non-owner with decrypt granted, but allowedOps excludes decrypt => none.
	const acl2 = { [u1]: [ 'decrypt' ] };
	assert.equal(effectiveAny({ allowedOps: [ 'encrypt' ] }, acl2, u1), false);
	assert.equal(effectiveAny({ allowedOps: [ 'decrypt' ] }, acl2, u1), true);
});

test('keygen: parameter resolution matrix', function() {
	// Every algorithm resolves with defaults.
	for (const alg of Object.keys(KEYGEN_ALGS)) {
		const spec = resolveKeyGenParams({ alg });
		assert.equal(spec.alg, alg);
	}
	// Implied oct lengths.
	assert.equal(resolveKeyGenParams({ alg: 'A128GCM' }).bits, 128);
	assert.equal(resolveKeyGenParams({ alg: 'A256KW', keyLength: 256 }).bits, 256);
	assert.throws(function() { resolveKeyGenParams({ alg: 'A256GCM', keyLength: 128 }); });
	// HS*: default hash size, larger allowed, smaller and non-multiples rejected.
	assert.equal(resolveKeyGenParams({ alg: 'HS256' }).bits, 256);
	assert.equal(resolveKeyGenParams({ alg: 'HS256', keyLength: 512 }).bits, 512);
	assert.equal(resolveKeyGenParams({ alg: 'HS512', keyLength: 4096 }).bits, 4096);
	assert.throws(function() { resolveKeyGenParams({ alg: 'HS256', keyLength: 128 }); });
	assert.throws(function() { resolveKeyGenParams({ alg: 'HS256', keyLength: 257 }); });
	assert.throws(function() { resolveKeyGenParams({ alg: 'HS256', keyLength: 4104 }); });
	// EC: implied and default curves; mismatches rejected.
	assert.equal(resolveKeyGenParams({ alg: 'ES256' }).crv, 'P-256');
	assert.equal(resolveKeyGenParams({ alg: 'ES384' }).crv, 'P-384');
	assert.equal(resolveKeyGenParams({ alg: 'ES512' }).crv, 'P-521');
	assert.equal(resolveKeyGenParams({ alg: 'ECDH-ES' }).crv, 'P-521');
	assert.equal(resolveKeyGenParams({ alg: 'ECDH-ES', crv: 'P-256' }).crv, 'P-256');
	assert.throws(function() { resolveKeyGenParams({ alg: 'ES256', crv: 'P-384' }); });
	assert.throws(function() { resolveKeyGenParams({ alg: 'ES512', crv: 'P-512' }); });
	assert.throws(function() { resolveKeyGenParams({ alg: 'ECDH-ES', keyLength: 256 }); });
	assert.throws(function() { resolveKeyGenParams({ alg: 'RSA-OAEP', crv: 'P-256' }); });
	// RSA: defaults per algorithm, 2048 minimum.
	assert.equal(resolveKeyGenParams({ alg: 'RSA-OAEP' }).modulusLength, 2048);
	assert.equal(resolveKeyGenParams({ alg: 'RSA-OAEP-256' }).modulusLength, 4096);
	assert.equal(resolveKeyGenParams({ alg: 'RS256' }).modulusLength, 2048);
	assert.equal(resolveKeyGenParams({ alg: 'RS384' }).modulusLength, 3072);
	assert.equal(resolveKeyGenParams({ alg: 'RS512' }).modulusLength, 4096);
	assert.equal(resolveKeyGenParams({ alg: 'RS256', keyLength: 3072 }).modulusLength, 3072);
	assert.throws(function() { resolveKeyGenParams({ alg: 'RS256', keyLength: 1024 }); });
	assert.throws(function() { resolveKeyGenParams({ alg: 'RS256', keyLength: 32768 }); });
	// kty consistency.
	assert.equal(resolveKeyGenParams({ alg: 'HS256', kty: 'oct' }).kty, 'oct');
	assert.throws(function() { resolveKeyGenParams({ alg: 'HS256', kty: 'RSA' }); });
	assert.throws(function() { resolveKeyGenParams({ alg: 'ES256', kty: 'oct' }); });
	// Excluded algorithms.
	for (const alg of [ 'dir', 'RSA1_5', 'PS256', 'ML-DSA-44', 'none' ]) {
		assert.throws(function() { resolveKeyGenParams({ alg }); }, /Unsupported algorithm/);
	}
	assert.throws(function() { resolveKeyGenParams({ kty: 'oct', keyLength: 256 }); }, /Unsupported algorithm/);
});

test('basicutils: validators', function() {
	assert.equal(isUuid('11111111-2222-3333-4444-555555555555'), true);
	assert.equal(isUuid('11111111-2222-3333-4444-55555555555'), false);
	assert.equal(isUuid(42), false);
	assert.equal(isPlainObject({}), true);
	assert.equal(isPlainObject([]), false);
	assert.equal(isPlainObject(null), false);
});
