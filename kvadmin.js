'use strict';

// kv-admin: administrative operations on the vault database
// (SPEC.md §13). Runs in the same package/image as the server and
// talks directly to PostgreSQL; there is no HTTP admin API. Every
// command is audit-logged with strict coupling — the command fails if
// its audit append fails.
//
// Usage: kv-admin [options] <command>
// Commands: add-user, set-token, revoke-token, set-user-data,
//           remove-user, list-users, update-acl, rewrap, verify-audit

module.exports = async function() {

	const name = 'kv-admin';
	const NAME = 'KV';

	const os = require('node:os');
	const crypto = require('node:crypto');

	const Optist = require('optist');
	const ou = require('optist/util');

	const { log } = require('./basicutils');
	const { isUuid, isPlainObject } = require('./basicutils');
	const { validateAcl } = require('./acl');
	const { validateAllowedIP } = require('./ipmatch');
	const { tokenHash } = require('./serverauth');
	const { kekInit } = require('./kek');
	const { Audit } = require('./audit');
	const { existingFileCb, retiredKeyFiles } = require('./serveropts');

	const ctx = {
		name: name,
		NAME: NAME,
		package: require('./package.json'),
		opt: null,
		debug: function() {},
		log: log
	};
	ctx.debug = function (...av) { if (ctx?.opt?.value('debug')) { log(...av); } };

	const uuidCb = function(s) { return (isUuid(s) ? s.toLowerCase() : undefined); };
	const jsonObjectCb = function(s) {
		try {
			const v = JSON.parse(s);
			return (isPlainObject(v) ? v : undefined);
		} catch (_) {
			return undefined;
		}
	};

	// Command-first invocation: kv-admin <command> [options]. The
	// command word is lifted off argv before optist parses the rest.
	const av = process.argv.slice(2);
	const command = ((av.length > 0) && ! av[0].startsWith('-')) ? av.shift() : undefined;

	ctx.opt = ((new Optist())
			   .opts([].concat(
				   [
					   { longName: 'debug',
						 description: 'Debug mode.',
						 environment: ctx.NAME + '_OPT_DEBUG' },
					   { longName: 'user',
						 description: 'Target user id (UUID)',
						 hasArg: true,
						 optArgCb: uuidCb },
					   { longName: 'kid',
						 description: 'Target key id (UUID)',
						 hasArg: true,
						 optArgCb: uuidCb },
					   { longName: 'acl',
						 description: 'ACL as a JSON object (update-acl)',
						 hasArg: true,
						 optArgCb: jsonObjectCb },
					   { longName: 'allowed-ip',
						 description: 'allowedIP entry (address, CIDR or IPv4 range); can be passed multiple times',
						 hasArg: true,
						 multi: true },
					   { longName: 'allow-all',
						 description: 'Set allowedIP to the explicit allow-all [ 0.0.0.0/0, 0::/0 ]' },
					   { longName: 'nbf',
						 description: 'Account not-before as a unix timestamp',
						 hasArg: true,
						 optArgCb: ou.integerWithLimitsCbFactory(1, 253402300799) },
					   { longName: 'exp',
						 description: 'Account expiry as a unix timestamp',
						 hasArg: true,
						 optArgCb: ou.integerWithLimitsCbFactory(1, 253402300799) },
					   { longName: 'clear-nbf',
						 description: 'Remove the account not-before (set-user-data)' },
					   { longName: 'clear-exp',
						 description: 'Remove the account expiry (set-user-data)' },
					   { longName: 'embedding-key-file',
						 description: 'JWK file containing the active vault embedding key (rewrap)',
						 hasArg: true,
						 optArgCb: existingFileCb,
						 environment: ctx.NAME + '_OPT_EMBEDDING_KEY_FILE' },
					   { longName: 'retired-embedding-key-file',
						 description: 'JWK file containing a retired embedding key; can be passed multiple times or colon-separated via environment (rewrap)',
						 hasArg: true,
						 multi: true,
						 environment: ctx.NAME + '_OPT_RETIRED_EMBEDDING_KEY_FILES' }
				   ],
				   (require('./dbopts'))(ctx.NAME),
				   []
			   ))
			   .help(name)
			   .parse(av, 0, 0));

	const actor = os.userInfo().username;

	function requireOpt(o) {
		const v = ctx.opt.value(o);
		if ((v === undefined) || (v === null) || (v === false)) {
			throw new Error(`Command ${command} requires --${o}`);
		}
		return v;
	}

	// allowedIP list from --allow-all / --allowed-ip. Fail-closed
	// default: without either, the list is empty and denies all API
	// access (a warning is printed).
	function allowedIPFromOpts() {
		if (ctx.opt.value('allow-all')) {
			if (ctx.opt.value('allowed-ip').length > 0) {
				throw new Error('--allow-all conflicts with --allowed-ip');
			}
			return [ '0.0.0.0/0', '0::/0' ];
		}
		const list = ctx.opt.value('allowed-ip');
		const invalid = validateAllowedIP(list);
		if (invalid.length > 0) {
			throw new Error(`Invalid allowedIP entries: ${invalid.join(', ')}`);
		}
		return list;
	}

	const commands = {

		'add-user': async function() {
			const allowedIP = allowedIPFromOpts();
			if (allowedIP.length < 1) {
				log('WARNING: empty allowedIP denies all API access for the user ' +
					'(use --allow-all or --allowed-ip)');
			}
			const data = { allowedIP, iat: Math.floor(Date.now() / 1000) };
			if (ctx.opt.value('nbf')) {
				data.nbf = ctx.opt.value('nbf');
			}
			if (ctx.opt.value('exp')) {
				data.exp = ctx.opt.value('exp');
			}
			const userId = await ctx.db.insertUser(data);
			await ctx.audit.event('admin:add-user', { actor, userId, allowedIP });
			console.log(userId);
		},

		'set-token': async function() {
			const userId = requireOpt('user');
			const user = await ctx.db.userById(userId);
			if (! user) {
				throw new Error('User not found');
			}
			const token = crypto.randomUUID();
			const data = Object.assign({}, user.data,
									   { auth_token_ts: Math.floor(Date.now() / 1000) });
			await ctx.db.setUserToken(userId, tokenHash(token));
			await ctx.db.setUserData(userId, data);
			await ctx.audit.event('admin:set-token', { actor, userId });
			// The token is printed exactly once and is unrecoverable
			// from the database (only its sha256 digest is stored).
			console.log(token);
		},

		'revoke-token': async function() {
			const userId = requireOpt('user');
			const user = await ctx.db.userById(userId);
			if (! user) {
				throw new Error('User not found');
			}
			const data = Object.assign({}, user.data,
									   { auth_token_ts: Math.floor(Date.now() / 1000) });
			await ctx.db.setUserToken(userId, null);
			await ctx.db.setUserData(userId, data);
			await ctx.audit.event('admin:revoke-token', { actor, userId });
			log(`token revoked for ${userId}`);
		},

		'set-user-data': async function() {
			const userId = requireOpt('user');
			const user = await ctx.db.userById(userId);
			if (! user) {
				throw new Error('User not found');
			}
			const data = Object.assign({}, user.data);
			if (ctx.opt.value('allow-all') || (ctx.opt.value('allowed-ip').length > 0)) {
				data.allowedIP = allowedIPFromOpts();
			}
			if (ctx.opt.value('nbf')) {
				data.nbf = ctx.opt.value('nbf');
			}
			if (ctx.opt.value('exp')) {
				data.exp = ctx.opt.value('exp');
			}
			if (ctx.opt.value('clear-nbf')) {
				if (ctx.opt.value('nbf')) {
					throw new Error('--clear-nbf conflicts with --nbf');
				}
				delete data.nbf;
			}
			if (ctx.opt.value('clear-exp')) {
				if (ctx.opt.value('exp')) {
					throw new Error('--clear-exp conflicts with --exp');
				}
				delete data.exp;
			}
			await ctx.db.setUserData(userId, data);
			await ctx.audit.event('admin:set-user-data', { actor, userId,
														   allowedIP: data.allowedIP,
														   nbf: data.nbf, exp: data.exp });
			log(`user data updated for ${userId}`);
		},

		'remove-user': async function() {
			const userId = requireOpt('user');
			if (! await ctx.db.removeUser(userId)) {
				throw new Error('User not found');
			}
			await ctx.audit.event('admin:remove-user', { actor, userId });
			log(`user ${userId} removed`);
		},

		'list-users': async function() {
			const users = await ctx.db.listUsers();
			await ctx.audit.event('admin:list-users', { actor, userCount: users.length });
			for (const u of users) {
				const d = (isPlainObject(u.data) ? u.data : {});
				console.log([ u.userId,
							  (u.authToken ? 'api-enabled' : 'api-disabled'),
							  `nbf=${d.nbf ?? '-'}`,
							  `exp=${d.exp ?? '-'}`,
							  `allowedIP=${JSON.stringify(d.allowedIP ?? null)}` ].join(' '));
			}
		},

		'update-acl': async function() {
			const kid = requireOpt('kid');
			const aclInput = requireOpt('acl');
			let acl;
			try {
				acl = validateAcl(aclInput);
			} catch (e) {
				throw new Error(`Invalid ACL: ${e.message}`);
			}
			const missing = await ctx.db.missingUsers(Object.keys(acl));
			if (missing.length > 0) {
				throw new Error(`Invalid ACL: unknown user(s) ${missing.join(', ')}`);
			}
			const row = await ctx.db.keyById(kid);
			if (! row) {
				throw new Error('Key not found');
			}
			await ctx.db.updateKeyAcl(kid, acl);
			await ctx.audit.event('admin:update-acl', { actor, kid, aclUsers: Object.keys(acl) });
			log(`ACL updated for ${kid}`);
		},

		'rewrap': async function() {
			// Re-embed every key row not wrapped with the active KEK
			// (SPEC.md §5.2). Rows wrapped with unconfigured KEKs are
			// skipped with a warning — they need their KEK back first.
			const kek = await kekInit(requireOpt('embedding-key-file'),
									  retiredKeyFiles(ctx.opt));
			const rows = await ctx.db.keysNotEmbeddedWith(kek.activeKid());
			let rewrapped = 0, skipped = 0;
			for (const row of rows) {
				let secretJwk;
				try {
					secretJwk = kek.extract(row.embeddingKeyId, row.embeddedKey, row.keyId);
				} catch (e) {
					log(`WARNING: skipping ${row.keyId} (${e.message})`);
					skipped++;
					continue;
				}
				const meta = { kid: row.keyId, iat: Math.floor(Date.now() / 1000) };
				if (row.notBefore) {
					meta.nbf = Math.floor(row.notBefore.getTime() / 1000);
				}
				if (row.expiresAt) {
					meta.exp = Math.floor(row.expiresAt.getTime() / 1000);
				}
				const { embeddingKeyId, embeddedKey } = kek.embed(secretJwk, meta);
				await ctx.db.updateKeyEmbedding(row.keyId, embeddingKeyId, embeddedKey);
				rewrapped++;
			}
			await ctx.audit.event('admin:rewrap', { actor, activeKek: kek.activeKid(),
													rewrapped, skipped });
			log(`rewrap done: ${rewrapped} rewrapped, ${skipped} skipped`);
		},

		'verify-audit': async function() {
			const result = await ctx.audit.verify(true);
			await ctx.audit.event('admin:verify-audit', { actor, ok: result.ok,
														  eventsChecked: result.eventsChecked });
			if (! result.ok) {
				throw new Error(`AUDIT CHAIN VERIFICATION FAILED: first bad id ${result.firstBadId}`);
			}
			log(`audit chain ok (${result.eventsChecked} event(s) checked)`);
		}

	};

	if (! commands[command]) {
		throw new Error(`Unknown command ${command} (available: ${Object.keys(commands).join(', ')})`);
	}

	ctx.db = await require('./dbinit')(ctx);
	ctx.audit = new Audit({ pool: ctx.db.pool(), log: ctx.log });
	await ctx.audit.init();

	try {
		await commands[command]();
	} finally {
		await ctx.db.end();
	}

};
