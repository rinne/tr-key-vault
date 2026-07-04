'use strict';

module.exports = async function() {

	// The NAME is used in environment variable names (KV_OPT_*). It
	// is NOT related to DNS. Do not change it if you don't know what
	// you are doing!
	const name = 'tr-key-vault';
	const NAME = 'KV';

	const Optist = require('optist');
	const ou = require('optist/util');

	const { delay, log, fatal } = require('./basicutils');
	const { kekInit } = require('./kek');
	const { Audit, loadSealKeyFile } = require('./audit');
	const KeyStore = require('./keystore');
	const createServer = require('./server');

	const ctx = {
		name: name,
		NAME: NAME,
		package: require('./package.json'),
		opt: null,
		debug: function() {},
		log: log
	};
	ctx.debug = function (...av) { if (ctx?.opt?.value('debug')) { log(...av); } };

	// Defense in depth: a stray unhandled rejection must not take the
	// vault down. Known idle-connection pool errors are handled at the
	// pool (dbinit.js); this catches anything else that slips through.
	process.on('unhandledRejection', function(reason) {
		log(`unhandled promise rejection: ${(reason && reason.message) ? reason.message : reason}`);
	});

	ctx.opt = ((new Optist())
			   .opts([].concat(
				   [
					   { longName: 'debug',
						 description: 'Debug mode.',
						 environment: ctx.NAME + '_OPT_DEBUG' },
					   { longName: 'listen-address',
						 description: 'IP address the server listens to.',
						 hasArg: true,
						 defaultValue: '0.0.0.0',
						 environment: ctx.NAME + '_OPT_LISTEN_ADDRESS',
						 optArgCb: ou.ipv4 },
					   { longName: 'listen-port',
						 description: 'TCP port the server listens to.',
						 hasArg: true,
						 defaultValue: '8888',
						 environment: ctx.NAME + '_OPT_LISTEN_PORT',
						 optArgCb: ou.integerWithLimitsCbFactory(1, 65535) }
				   ],
				   (require('./serveropts'))(ctx),
				   (require('./dbopts'))(ctx.NAME),
				   []
			   ))
			   .help(name)
			   .parse(undefined, 0, 0));

	// Fail-fast startup: KEKs first (no point in touching the DB with
	// unusable embedding keys).
	const { retiredKeyFiles } = require('./serveropts');
	ctx.kek = await kekInit(ctx.opt.value('embedding-key-file'),
							retiredKeyFiles(ctx.opt));
	log(`embedding keys loaded (active=${ctx.kek.activeKid()}, total=${ctx.kek.kekIds().length})`);

	ctx.db = await require('./dbinit')(ctx);
	log(`database ready (${ctx.db.info().version})`);

	// Startup consistency check: rows wrapped with a KEK that is no
	// longer configured are unrecoverable until the KEK returns
	// (SPEC.md §5). Warn loudly and continue.
	{
		const unknown = await ctx.db.unknownEmbeddingKeyIds(ctx.kek.kekIds());
		for (const u of unknown) {
			log(`WARNING: ${u.count} key(s) wrapped with unconfigured embedding key ` +
				`${u.embeddingKeyId} — these keys are not available until the key is configured`);
		}
	}

	// Audit chain: init is fatal on failure (includes the root-canary
	// re-hash). The chain lives in the same database, namespace kv.
	{
		let sealSecretKey = null;
		if (ctx.opt.value('audit-seal-key-file')) {
			sealSecretKey = await loadSealKeyFile(ctx.opt.value('audit-seal-key-file'));
		}
		ctx.audit = new Audit({ pool: ctx.db.pool(),
								sealSecretKey,
								sealIntervalSeconds: ctx.opt.value('audit-seal-interval'),
								log: ctx.log });
		await ctx.audit.init();
		ctx.audit.startScheduler();
		log(`audit chain ready (namespace=kv${sealSecretKey ? ', sealed' : ''})`);
	}

	ctx.keystore = new KeyStore({ db: ctx.db,
								  kek: ctx.kek,
								  log: ctx.log,
								  cacheMaxEntries: ctx.opt.value('key-cache-max-entries'),
								  cacheTtlSeconds: ctx.opt.value('key-cache-ttl'),
								  sweepIntervalSeconds: ctx.opt.value('expiry-sweep-interval'),
								  expiryGraceSeconds: ctx.opt.value('key-expiry-grace') });
	await ctx.keystore.sweep();
	ctx.keystore.startSweep();

	const server = createServer(ctx);
	await new Promise(function(resolve, reject) {
		server.on('error', reject);
		server.listen(ctx.opt.value('listen-port'), ctx.opt.value('listen-address'), function() {
			server.removeListener('error', reject);
			resolve();
		});
	});
	log(`Server is up at ${ctx.opt.value('listen-address')}:${ctx.opt.value('listen-port')}`);

	let shuttingDown = false;
	async function shutdown(signal) {
		if (shuttingDown) {
			return;
		}
		shuttingDown = true;
		log(`${signal} received, shutting down`);
		try {
			ctx.keystore.stopSweep();
			ctx.audit.stopScheduler();
			await new Promise(function(resolve) { server.close(resolve); });
			await ctx.db.end();
		} catch (e) {
			fatal(`shutdown error: ${e.message}`);
		}
		process.exit(0);
	}
	process.on('SIGTERM', function() { shutdown('SIGTERM'); });
	process.on('SIGINT', function() { shutdown('SIGINT'); });

	// Wait forever.
	for (let i = 0; /*NOTHING*/; i++) {
		await delay(1000);
	}

};
