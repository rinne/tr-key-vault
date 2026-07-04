'use strict';

// kv-client: a thin command-line HTTP client for the tr-key-vault API
// (KV-CLIENT-SPEC.md). It builds the { user, op, request, data }
// envelope, sends it to POST /api/v1 (or GETs the /healthz|/readyz
// probes), and prints the response. It performs no cryptography and no
// database access — it is a faithful, dependency-light exerciser of
// the wire protocol, mainly for the test campaign.
//
// Usage: kv-client [global-options] <command> [command-options] [args]
//
// Exit codes: 0 ok, 1 local/usage error, 2 transport error,
//             3 API operation error (see §6 of the spec).

module.exports = async function() {

	const name = 'kv-client';
	const NAME = 'KV_CLIENT';

	const crypto = require('node:crypto');
	const fs = require('node:fs');
	const http = require('node:http');
	const https = require('node:https');

	const Optist = require('optist');
	const ou = require('optist/util');

	const { isUuid, isPlainObject } = require('./basicutils');

	// Local/usage error -> exit 1.
	function usageError(msg) {
		process.stderr.write(`${name}: ${msg}\n`);
		process.exit(1);
	}
	// Transport error -> exit 2.
	function transportError(msg) {
		process.stderr.write(`${name}: ${msg}\n`);
		process.exit(2);
	}

	const uuidCb = function(s) { return (isUuid(s) ? s.toLowerCase() : undefined); };
	const compressCb = function(s) {
		if (s === 'false') { return 'false'; }
		if (s === 'true') { return 'true'; }
		if (s === 'auto') { return 'auto'; }
		return undefined;
	};

	// Command-first invocation: kv-client <command> [options] (the
	// kv-admin pattern). The command word is lifted off argv before
	// optist parses the rest.
	const av = process.argv.slice(2);
	const command = ((av.length > 0) && ! av[0].startsWith('-')) ? av.shift() : undefined;

	const opt = ((new Optist())
				 .opts([
					 // --- connection / auth ---
					 { longName: 'url',
					   description: 'Base URL of the vault, e.g. https://vault.example.com',
					   hasArg: true,
					   environment: NAME + '_OPT_URL' },
					 { longName: 'user',
					   description: 'Caller user id (UUID)',
					   hasArg: true,
					   optArgCb: uuidCb,
					   environment: NAME + '_OPT_USER' },
					 { longName: 'token',
					   description: 'Bearer token (UUID). Prefer the environment or --token-file (argv is visible in ps)',
					   hasArg: true,
					   environment: NAME + '_OPT_TOKEN' },
					 { longName: 'token-file',
					   description: 'Read the bearer token from a file',
					   hasArg: true,
					   conflictsWith: [ 'token' ],
					   environment: NAME + '_OPT_TOKEN_FILE' },
					 { longName: 'op',
					   description: 'Client operation correlation id (UUID); default a fresh random one',
					   hasArg: true,
					   optArgCb: uuidCb },
					 { longName: 'timeout',
					   description: 'Request timeout in seconds',
					   hasArg: true,
					   defaultValue: '30',
					   optArgCb: ou.integerWithLimitsCbFactory(1, 3600),
					   environment: NAME + '_OPT_TIMEOUT' },
					 { shortName: 'k', longName: 'insecure',
					   description: 'Skip TLS certificate verification (test only)',
					   environment: NAME + '_OPT_INSECURE' },
					 { longName: 'ca-file',
					   description: 'PEM CA bundle to trust',
					   hasArg: true,
					   environment: NAME + '_OPT_CA_FILE' },
					 // --- output ---
					 { longName: 'compact-json',
					   description: 'Emit compact single-line JSON (default is pretty-printed)' },
					 { longName: 'raw',
					   description: 'Print the full response envelope instead of just data' },
					 { longName: 'field',
					   description: 'Print only this field of the result (scalar bare, object/array as JSON)',
					   hasArg: true },
					 { shortName: 'v', longName: 'verbose',
					   description: 'Log the request line and HTTP status to stderr' },
					 // --- operation data ---
					 { longName: 'alg', description: 'Key algorithm (generate-key)', hasArg: true },
					 { longName: 'kty', description: 'Key type (generate-key)', hasArg: true },
					 { longName: 'crv', description: 'EC curve (generate-key)', hasArg: true },
					 { longName: 'key-length',
					   description: 'Key length / RSA modulus bits (generate-key)',
					   hasArg: true,
					   optArgCb: ou.integerWithLimitsCbFactory(1, 16384) },
					 { longName: 'nbf',
					   description: 'Key not-before, unix timestamp (generate-key)',
					   hasArg: true,
					   optArgCb: ou.integerWithLimitsCbFactory(1, 253402300799) },
					 { longName: 'exp',
					   description: 'Key expiry, unix timestamp (generate-key)',
					   hasArg: true,
					   optArgCb: ou.integerWithLimitsCbFactory(1, 253402300799) },
					 { longName: 'return-public-key',
					   description: 'Return the public key (generate-key, asymmetric)' },
					 { longName: 'acl',
					   description: 'ACL as a JSON object (generate-key)',
					   hasArg: true },
					 { longName: 'acl-file',
					   description: 'Read the ACL JSON object from a file (generate-key)',
					   hasArg: true,
					   conflictsWith: [ 'acl' ] },
					 { longName: 'kid',
					   description: 'Target key id (UUID)',
					   hasArg: true,
					   optArgCb: uuidCb },
					 { longName: 'data',
					   description: 'Operation payload as JSON (- reads stdin)',
					   hasArg: true },
					 { longName: 'data-file',
					   description: 'Read the operation payload JSON from a file',
					   hasArg: true,
					   conflictsWith: [ 'data' ] },
					 { longName: 'compress',
					   description: 'JWE compression: false | true | auto (create-jwe)',
					   hasArg: true,
					   optArgCb: compressCb }
				 ])
				 .help(name)
				 .parse(av, 0, 1));

	if (! command) {
		usageError('no command given (try --help)');
	}

	const verbose = opt.value('verbose');

	// ---- input helpers ----

	function readStdin() {
		if (process.stdin.isTTY) {
			usageError('expected input on stdin');
		}
		try {
			return fs.readFileSync(0, 'utf8');
		} catch (e) {
			usageError(`cannot read stdin: ${e.message}`);
		}
	}

	// The operation payload from --data / --data-file / --data - .
	// Returns undefined when no source was given.
	function payloadInput() {
		let text;
		if (opt.value('data') !== undefined) {
			text = (opt.value('data') === '-') ? readStdin() : opt.value('data');
		} else if (opt.value('data-file') !== undefined) {
			try {
				text = fs.readFileSync(opt.value('data-file'), 'utf8');
			} catch (e) {
				usageError(`cannot read --data-file: ${e.message}`);
			}
		} else {
			return undefined;
		}
		try {
			return JSON.parse(text);
		} catch (_) {
			usageError('payload is not valid JSON');
		}
	}

	function requirePayload() {
		const p = payloadInput();
		if (p === undefined) {
			usageError('this command requires --data / --data-file / --data -');
		}
		return p;
	}

	function aclInput() {
		let text;
		if (opt.value('acl') !== undefined) {
			text = opt.value('acl');
		} else if (opt.value('acl-file') !== undefined) {
			try {
				text = fs.readFileSync(opt.value('acl-file'), 'utf8');
			} catch (e) {
				usageError(`cannot read --acl-file: ${e.message}`);
			}
		} else {
			return undefined;
		}
		let v;
		try {
			v = JSON.parse(text);
		} catch (_) {
			usageError('acl is not valid JSON');
		}
		if (! isPlainObject(v)) {
			usageError('acl must be a JSON object');
		}
		return v;
	}

	// The compact JOSE token for verify/decrypt: positional argument,
	// or stdin (explicit '-' or no positional).
	function tokenInput() {
		const pos = opt.rest()[0];
		if ((pos !== undefined) && (pos !== '-')) {
			return pos;
		}
		return readStdin().trim();
	}

	function requireKid() {
		const kid = opt.value('kid');
		if (! kid) {
			usageError('this command requires --kid <uuid>');
		}
		return kid;
	}

	// ---- command dispatch: build the request ----
	// Each command yields either { probe: '<path>' } or
	// { request: '<name>', data: {...} }.

	let plan;
	switch (command) {
	case 'healthz':
		plan = { probe: '/healthz' };
		break;
	case 'readyz':
		plan = { probe: '/readyz' };
		break;
	case 'healthcheck':
		plan = { request: 'healthcheck', data: {} };
		break;
	case 'generate-key': {
		if (! opt.value('alg')) {
			usageError('generate-key requires --alg');
		}
		const data = { alg: opt.value('alg') };
		if (opt.value('kty') !== undefined) { data.kty = opt.value('kty'); }
		if (opt.value('crv') !== undefined) { data.crv = opt.value('crv'); }
		if (opt.value('key-length') !== undefined) { data.keyLength = opt.value('key-length'); }
		if (opt.value('nbf') !== undefined) { data.nbf = opt.value('nbf'); }
		if (opt.value('exp') !== undefined) { data.exp = opt.value('exp'); }
		const acl = aclInput();
		if (acl !== undefined) { data.acl = acl; }
		if (opt.value('return-public-key')) { data.returnPublicKey = true; }
		plan = { request: 'generate-key', data };
		break;
	}
	case 'public-key':
		plan = { request: 'public-key', data: { kid: requireKid() } };
		break;
	case 'create-jwt':
		plan = { request: 'create-jwt', data: { kid: requireKid(), data: requirePayload() } };
		break;
	case 'verify-jwt': {
		const data = { token: tokenInput() };
		if (opt.value('kid')) { data.kid = opt.value('kid'); }
		plan = { request: 'verify-jwt', data };
		break;
	}
	case 'create-jwe': {
		const data = { kid: requireKid(), data: requirePayload() };
		if (opt.value('compress') !== undefined) {
			const c = opt.value('compress');
			data.compress = ((c === 'auto') ? 'auto' : (c === 'true'));
		}
		plan = { request: 'create-jwe', data };
		break;
	}
	case 'decrypt-jwe': {
		const data = { token: tokenInput() };
		if (opt.value('kid')) { data.kid = opt.value('kid'); }
		plan = { request: 'decrypt-jwe', data };
		break;
	}
	case 'revoke-key':
		plan = { request: 'revoke-key', data: { kid: requireKid() } };
		break;
	case 'export-key':
		plan = { request: 'export-key', data: { kid: requireKid() } };
		break;
	case 'list-keys':
		plan = { request: 'list-keys', data: {} };
		break;
	case 'raw': {
		// raw <request-name> [--data <json>] — arbitrary request for
		// negative testing.
		const reqName = opt.rest()[0];
		if (! reqName) {
			usageError('raw requires a request name argument');
		}
		const data = payloadInput();
		plan = { request: reqName, data: (data === undefined) ? {} : data };
		break;
	}
	default:
		usageError(`unknown command: ${command}`);
	}

	// ---- configuration common to every call ----

	if (! opt.value('url')) {
		usageError('--url is required (or set ' + NAME + '_OPT_URL)');
	}
	// Normalize: accept a base URL, with or without a trailing /api/v1.
	let base;
	try {
		base = new URL(opt.value('url')).toString().replace(/\/+$/, '').replace(/\/api\/v1$/, '');
	} catch (_) {
		usageError('--url is not a valid URL');
	}

	let ca;
	if (opt.value('ca-file')) {
		try {
			ca = fs.readFileSync(opt.value('ca-file'));
		} catch (e) {
			usageError(`cannot read --ca-file: ${e.message}`);
		}
	}

	// ---- HTTP ----

	function httpRequest(targetUrl, method, bodyObj, authToken) {
		return new Promise(function(resolve, reject) {
			const u = new URL(targetUrl);
			const isHttps = (u.protocol === 'https:');
			const mod = isHttps ? https : http;
			const payload = (bodyObj !== undefined) ? Buffer.from(JSON.stringify(bodyObj), 'utf8') : null;
			const headers = {};
			if (payload) {
				headers['Content-Type'] = 'application/json';
				headers['Content-Length'] = payload.length;
			}
			if (authToken) {
				headers['Authorization'] = `Bearer ${authToken}`;
			}
			const reqOpts = {
				method,
				hostname: u.hostname,
				port: (u.port || (isHttps ? 443 : 80)),
				path: (u.pathname + u.search),
				headers
			};
			if (isHttps) {
				if (opt.value('insecure')) { reqOpts.rejectUnauthorized = false; }
				if (ca) { reqOpts.ca = ca; }
			}
			if (verbose) {
				process.stderr.write(`${name}: ${method} ${targetUrl}\n`);
			}
			const req = mod.request(reqOpts, function(res) {
				const chunks = [];
				res.on('data', function(c) { chunks.push(c); });
				res.on('end', function() {
					if (verbose) {
						process.stderr.write(`${name}: HTTP ${res.statusCode}\n`);
					}
					resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
				});
			});
			req.on('error', reject);
			req.setTimeout(opt.value('timeout') * 1000, function() {
				req.destroy(new Error('request timeout'));
			});
			if (payload) {
				req.write(payload);
			}
			req.end();
		});
	}

	// ---- output ----

	function toJson(v) {
		return (opt.value('compact-json') ? JSON.stringify(v) : JSON.stringify(v, null, 2));
	}

	function printResult(outputObj, envelope) {
		if (opt.value('raw')) {
			process.stdout.write(toJson(envelope) + '\n');
			return;
		}
		if (opt.value('field') !== undefined) {
			const f = opt.value('field');
			if (! (isPlainObject(outputObj) && (f in outputObj))) {
				usageError(`field not present in result: ${f}`);
			}
			const val = outputObj[f];
			if ((typeof(val) === 'object') && (val !== null)) {
				process.stdout.write(toJson(val) + '\n');
			} else {
				process.stdout.write(String(val) + '\n');
			}
			return;
		}
		process.stdout.write(toJson(outputObj) + '\n');
	}

	// ---- run ----

	// Probes: unauthenticated GET, success iff HTTP 200.
	if (plan.probe) {
		let res;
		try {
			res = await httpRequest(base + plan.probe, 'GET', undefined, null);
		} catch (e) {
			transportError(`request failed: ${e.message}`);
		}
		let body;
		try {
			body = JSON.parse(res.body);
		} catch (_) {
			body = null;
		}
		if (res.status !== 200) {
			process.stderr.write(`${name}: ${plan.probe} returned HTTP ${res.status}\n`);
			process.exit(2);
		}
		printResult(body, body);
		process.exit(0);
	}

	// Authenticated API call.
	if (! opt.value('user')) {
		usageError('--user is required (or set ' + NAME + '_OPT_USER)');
	}
	let authToken = opt.value('token');
	if ((authToken === undefined) && (opt.value('token-file') !== undefined)) {
		try {
			authToken = fs.readFileSync(opt.value('token-file'), 'utf8').trim();
		} catch (e) {
			usageError(`cannot read --token-file: ${e.message}`);
		}
	}
	if (! authToken) {
		usageError('a bearer token is required (--token, --token-file or ' + NAME + '_OPT_TOKEN)');
	}

	const sentOp = opt.value('op') || crypto.randomUUID();
	const envelope = { user: opt.value('user'), op: sentOp, request: plan.request, data: plan.data };

	let res;
	try {
		res = await httpRequest(base + '/api/v1', 'POST', envelope, authToken);
	} catch (e) {
		transportError(`request failed: ${e.message}`);
	}

	let body;
	try {
		body = JSON.parse(res.body);
	} catch (_) {
		transportError(`non-JSON response (HTTP ${res.status})`);
	}
	if (! isPlainObject(body)) {
		transportError(`unexpected response (HTTP ${res.status})`);
	}

	// A well-formed error envelope is an API operation error (exit 3),
	// at whatever HTTP status; anything else non-ok is transport.
	if (body.status === 'error') {
		if (body.op && (body.op !== sentOp)) {
			process.stderr.write(`${name}: warning: response op ${body.op} does not match sent op ${sentOp}\n`);
		}
		process.stderr.write(`${name}: API error ${body.errorCode}: ${body.message}\n`);
		if (opt.value('raw')) {
			process.stdout.write(toJson(body) + '\n');
		}
		process.exit(3);
	}
	if ((res.status !== 200) || (body.status !== 'ok')) {
		transportError(`unexpected response (HTTP ${res.status})`);
	}
	if (body.op && (body.op !== sentOp)) {
		process.stderr.write(`${name}: warning: response op ${body.op} does not match sent op ${sentOp}\n`);
	}
	printResult(body.data, body);
	process.exit(0);

};
