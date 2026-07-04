'use strict';

const fs = require('node:fs');
const ou = require('optist/util');

// Option argument callback: the argument must name a readable file.
// Returns the file name or undefined (= parse failure).
function existingFileCb(s) {
	if (! s) {
		return undefined;
	}
	try {
		fs.accessSync(s, fs.constants.R_OK);
	} catch (_) {
		return undefined;
	}
	return s;
}

function serverOpts(ctx) {

	return [
		{ longName: 'embedding-key-file',
		  description: 'JWK file containing the active vault embedding key (KEK)',
		  hasArg: true,
		  required: true,
		  optArgCb: existingFileCb,
		  environment: ctx.NAME + '_OPT_EMBEDDING_KEY_FILE' },
		// No per-argument file check here: the environment form packs
		// multiple paths into one PATH-style colon-separated value
		// (docker can only set a single string). retiredKeyFiles()
		// below splits it; kekInit() fail-fasts on unreadable files.
		{ longName: 'retired-embedding-key-file',
		  description: 'JWK file containing a retired (decrypt-only) embedding key; can be passed multiple times (or colon-separated via environment)',
		  hasArg: true,
		  multi: true,
		  environment: ctx.NAME + '_OPT_RETIRED_EMBEDDING_KEY_FILES' },
		{ longName: 'allow-export-key',
		  description: 'Globally enable the export-key operation (default: disabled)',
		  environment: ctx.NAME + '_OPT_ALLOW_EXPORT_KEY' },
		// Number of trusted reverse-proxy hops in front of the service. The
		// real client IP is taken from X-Forwarded-For honoring this many
		// trusted (rightmost) hops. X-Forwarded-For is attacker-controllable,
		// so this MUST match the real deployment depth or the per-user
		// allowedIP controls can be spoofed. The committed stack runs exactly
		// one nginx TLS proxy, hence default 1. Set 0 for direct (no-proxy)
		// exposure so X-Forwarded-For is ignored.
		{ longName: 'trusted-proxy-hops',
		  description: 'Trusted reverse-proxy hops for X-Forwarded-For client-IP derivation (0 = ignore XFF, use socket peer)',
		  hasArg: true,
		  defaultValue: '1',
		  environment: ctx.NAME + '_OPT_TRUSTED_PROXY_HOPS',
		  optArgCb: ou.integerWithLimitsCbFactory(0, 16) },
		{ longName: 'max-request-body',
		  description: 'Maximum accepted request body size in bytes',
		  hasArg: true,
		  defaultValue: '1048576',
		  environment: ctx.NAME + '_OPT_MAX_REQUEST_BODY',
		  optArgCb: ou.integerWithLimitsCbFactory(1024, 134217728) },
		{ longName: 'request-timeout',
		  description: 'HTTP request timeout in seconds',
		  hasArg: true,
		  defaultValue: '30',
		  environment: ctx.NAME + '_OPT_REQUEST_TIMEOUT',
		  optArgCb: ou.integerWithLimitsCbFactory(1, 3600) },
		{ longName: 'expiry-sweep-interval',
		  description: 'Interval of the expired key sweep in seconds',
		  hasArg: true,
		  defaultValue: '60',
		  environment: ctx.NAME + '_OPT_EXPIRY_SWEEP_INTERVAL',
		  optArgCb: ou.integerWithLimitsCbFactory(1, 86400) },
		{ longName: 'key-expiry-grace',
		  description: 'Grace period in seconds before an expired key row is deleted (expiry itself is enforced at read time)',
		  hasArg: true,
		  defaultValue: '0',
		  environment: ctx.NAME + '_OPT_KEY_EXPIRY_GRACE',
		  optArgCb: ou.integerWithLimitsCbFactory(0, 31536000) },
		{ longName: 'key-cache-max-entries',
		  description: 'Maximum number of entries in the unwrapped key cache (0 = cache disabled)',
		  hasArg: true,
		  defaultValue: '1024',
		  environment: ctx.NAME + '_OPT_KEY_CACHE_MAX_ENTRIES',
		  optArgCb: ou.integerWithLimitsCbFactory(0, 1000000) },
		{ longName: 'key-cache-ttl',
		  description: 'TTL of unwrapped key cache entries in seconds',
		  hasArg: true,
		  defaultValue: '300',
		  environment: ctx.NAME + '_OPT_KEY_CACHE_TTL',
		  optArgCb: ou.integerWithLimitsCbFactory(1, 86400) },
		{ longName: 'audit-seal-key-file',
		  description: 'Private seal JWK file; when given, the audit chain is sealed periodically (must be configured at the chain\'s first init)',
		  hasArg: true,
		  optArgCb: existingFileCb,
		  environment: ctx.NAME + '_OPT_AUDIT_SEAL_KEY_FILE' },
		{ longName: 'audit-seal-interval',
		  description: 'Interval of periodic audit chain seals in seconds',
		  hasArg: true,
		  defaultValue: '3600',
		  environment: ctx.NAME + '_OPT_AUDIT_SEAL_INTERVAL',
		  optArgCb: ou.integerWithLimitsCbFactory(60, 604800) }
	];

}

// Resolve the retired embedding key file list from a parsed option
// set: each --retired-embedding-key-file value may itself be a
// PATH-style colon-separated list (the environment form).
function retiredKeyFiles(opt) {
	return opt.value('retired-embedding-key-file')
		.flatMap(function(v) { return String(v).split(':'); })
		.filter(function(v) { return !! v; });
}

module.exports = serverOpts;
module.exports.existingFileCb = existingFileCb;
module.exports.retiredKeyFiles = retiredKeyFiles;
