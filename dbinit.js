'use strict';

const path = require('node:path');
const PgPool = require('pg-pool');

const dbMigrate = require('./dbmigrate');
const VaultDB = require('./serverdb');

// pg-pool emits 'error' when an *idle* pooled client's backend
// connection fails (e.g. a PostgreSQL restart or a dropped network
// link). Node throws on an 'error' event with no listener, which
// would crash the whole process; pg removes the failed client
// automatically, so a listener that just logs lets the pool recover
// on the next query. Attach this to every pool the process owns.
function attachPoolErrorHandler(pool, log) {
	const logFn = log || function() {};
	pool.on('error', function(e) {
		logFn(`database pool error (recovered): ${e?.message ?? e}`);
	});
}

function dbInit(ctx) {

	return new Promise(function(resolve, reject) {
		(async function() {
			try {
				let opts = { host: ctx.opt.value('db-host'),
							 port: ctx.opt.value('db-port'),
							 user: ctx.opt.value('db-user'),
							 database: ctx.opt.value('db-database'),
							 max: ctx.opt.value('db-max-connections'),
							 maxUses: 1000 };
				if (ctx.opt.value('db-tls')) {
					opts.ssl = true;
				}
				if (ctx.opt.value('db-password')) {
					opts.password = ctx.opt.value('db-password');
				}
				const pool = new PgPool(opts);
				attachPoolErrorHandler(pool, ctx.log);
				await dbMigrate(pool, path.join(__dirname, 'migrations'), ctx);
				const db = new VaultDB({ pool });
				db.on('ready', function() {
					db.removeAllListeners('ready');
					db.removeAllListeners('error');
					return resolve(db);
				});
				db.on('error', function(e) {
					db.removeAllListeners('ready');
					db.removeAllListeners('error');
					return reject(e);
				});
			} catch (e) {
				return reject(e);
			}
		})();
	});
}

module.exports = dbInit;
module.exports.attachPoolErrorHandler = attachPoolErrorHandler;
