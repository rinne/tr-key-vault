'use strict';

const http = require('node:http');

const { isUuid, isPlainObject } = require('./basicutils');
const { ERR, ERR_MESSAGE, ApiError } = require('./errors');
const { authenticate } = require('./serverauth');
const serverHandlers = require('./serverhandlers');

// The HTTP server (SPEC.md §8): a single API entry point POST /api/v1
// dispatching on the envelope `request` field, plus unauthenticated
// GET /healthz (liveness) and GET /readyz (DB ping) for docker
// HEALTHCHECK and proxy probes. Built directly on node:http.

const API_PATH = '/api/v1';

function respond(res, httpStatus, body, close) {
	const payload = Buffer.from(JSON.stringify(body), 'utf8');
	const headers = { 'Content-Type': 'application/json; charset=utf-8',
					  'Content-Length': payload.length,
					  'Cache-Control': 'no-store',
					  'X-Content-Type-Options': 'nosniff' };
	if (close) {
		headers['Connection'] = 'close';
	}
	res.writeHead(httpStatus, headers);
	res.end(payload);
}

function errorBody(errorCode, message, op) {
	const body = { status: 'error' };
	if (op) {
		body.op = op;
	}
	body.errorCode = errorCode;
	body.message = (message || ERR_MESSAGE[errorCode] || 'Error');
	return body;
}

// Read the request body up to `limit` bytes. Resolves to a Buffer or
// rejects with 'too-large'.
function readBody(req, limit) {
	return new Promise(function(resolve, reject) {
		const chunks = [];
		let size = 0;
		let done = false;
		req.on('data', function(chunk) {
			if (done) {
				return;
			}
			size += chunk.length;
			if (size > limit) {
				done = true;
				req.pause();
				return reject(new Error('too-large'));
			}
			chunks.push(chunk);
		});
		req.on('end', function() {
			if (done) {
				return;
			}
			done = true;
			resolve(Buffer.concat(chunks));
		});
		req.on('error', function(e) {
			if (done) {
				return;
			}
			done = true;
			reject(e);
		});
	});
}

function createServer(ctx) {

	const handlers = serverHandlers(ctx);

	// The audited operation catalogue: every operation except
	// healthcheck (SPEC.md §11.2). Strict coupling: an audit append
	// failure fails the request with internal-error.
	const auditedOps = new Set(Object.keys(handlers));
	auditedOps.delete('healthcheck');

	async function handleApi(req, res) {
		if (! /^application\/json\s*(;.*)?$/i.test(req.headers['content-type'] || '')) {
			return respond(res, 400, errorBody(ERR.MALFORMED_REQUEST, 'Content-Type must be application/json'));
		}
		let raw;
		try {
			raw = await readBody(req, ctx.opt.value('max-request-body'));
		} catch (e) {
			respond(res, 400, errorBody(ERR.MALFORMED_REQUEST,
										((e.message === 'too-large') ? 'Request body too large' : undefined)), true);
			req.destroy();
			return;
		}
		let envelope;
		try {
			envelope = JSON.parse(raw.toString('utf8'));
		} catch (_) {
			return respond(res, 400, errorBody(ERR.MALFORMED_REQUEST));
		}
		if (! isPlainObject(envelope)) {
			return respond(res, 400, errorBody(ERR.MALFORMED_REQUEST));
		}
		// `op` first: a valid one is echoed in every response from
		// here on, always normalized to lower case.
		if (! isUuid(envelope.op)) {
			return respond(res, 400, errorBody(ERR.MALFORMED_REQUEST, 'Invalid op'));
		}
		const op = envelope.op.toLowerCase();
		for (const prop of Object.keys(envelope)) {
			if (! [ 'user', 'op', 'request', 'data' ].includes(prop)) {
				return respond(res, 400, errorBody(ERR.MALFORMED_REQUEST, `Unknown property: ${prop}`, op));
			}
		}
		if (! (isUuid(envelope.user) &&
			   (typeof(envelope.request) === 'string') && envelope.request &&
			   isPlainObject(envelope.data))) {
			return respond(res, 400, errorBody(ERR.MALFORMED_REQUEST, undefined, op));
		}
		// Authentication. One error path for every failure mode; the
		// distinction goes to the audit chain only.
		const auth = await authenticate(ctx, req, envelope);
		if (! auth.ok) {
			// Unauthenticated traffic (bad/absent token, unknown user,
			// user/token mismatch, out-of-window account, disallowed
			// client IP) is deliberately NOT audited: an
			// unauthenticated caller must not be able to drive
			// audit-chain writes (per-append EXCLUSIVE lock contention
			// and unbounded chain growth). Visible under --debug for
			// troubleshooting only. Authorization failures by an
			// authenticated caller ARE audited below (the `denied`
			// event).
			ctx.debug(`auth failure from ${auth.clientIp}: ${auth.reason}`);
			return respond(res, 403, errorBody(ERR.UNAUTHORIZED, undefined, op));
		}
		const user = auth.user;
		const handler = handlers[envelope.request];
		if (! handler) {
			return respond(res, 200, errorBody(ERR.UNKNOWN_OPERATION, undefined, op));
		}
		const meta = { op, clientIp: auth.clientIp };
		let result = null;
		let apiError = null;
		let httpStatus = 200;
		try {
			result = await handler(user, envelope.data, meta);
		} catch (e) {
			if (e instanceof ApiError) {
				apiError = e;
			} else {
				ctx.log(`internal error in ${envelope.request}: ${e.message}`);
				ctx.debug(e);
				apiError = new ApiError(ERR.INTERNAL_ERROR);
				httpStatus = 500;
			}
		}
		// Audit before the response is sent — strict coupling: the
		// vault never returns a success response for an unaudited
		// operation (SPEC.md §11.2).
		if (auditedOps.has(envelope.request)) {
			try {
				const fields = { userId: user.userId, op };
				if (result?.audit) {
					Object.assign(fields, result.audit);
				} else if (isUuid(envelope.data.kid)) {
					fields.kid = envelope.data.kid.toLowerCase();
				}
				fields.outcome = (apiError ? apiError.errorCode : 'ok');
				await ctx.audit.event(envelope.request, fields);
				if (apiError?.maskedDenial) {
					await ctx.audit.event('denied', { userId: user.userId, op,
													  kid: (isUuid(envelope.data.kid) ? envelope.data.kid.toLowerCase() : undefined) });
				}
			} catch (e) {
				ctx.log(`audit append failed: ${e.message}`);
				return respond(res, 500, errorBody(ERR.INTERNAL_ERROR, undefined, op));
			}
		}
		if (apiError) {
			return respond(res, httpStatus, errorBody(apiError.errorCode, apiError.message, op));
		}
		return respond(res, 200, { status: 'ok', op, data: result.data });
	}

	async function handleRequest(req, res) {
		let pathname;
		try {
			pathname = new URL(req.url, 'http://localhost').pathname;
		} catch (_) {
			return respond(res, 400, errorBody(ERR.MALFORMED_REQUEST));
		}
		switch (pathname) {
		case API_PATH:
			if (req.method !== 'POST') {
				return respond(res, 405, errorBody(ERR.METHOD_NOT_ALLOWED));
			}
			return handleApi(req, res);
		case '/healthz':
			if (req.method !== 'GET') {
				return respond(res, 405, errorBody(ERR.METHOD_NOT_ALLOWED));
			}
			return respond(res, 200, { status: 'ok' });
		case '/readyz':
			if (req.method !== 'GET') {
				return respond(res, 405, errorBody(ERR.METHOD_NOT_ALLOWED));
			}
			try {
				await ctx.db.q('SELECT 1');
				return respond(res, 200, { status: 'ok' });
			} catch (_) {
				return respond(res, 503, errorBody(ERR.INTERNAL_ERROR, 'Database not available'));
			}
		default:
			return respond(res, 404, errorBody(ERR.UNKNOWN_ENDPOINT));
		}
	}

	const server = http.createServer(function(req, res) {
		handleRequest(req, res).catch(function(e) {
			ctx.log(`request handling error: ${e.message}`);
			try {
				respond(res, 500, errorBody(ERR.INTERNAL_ERROR));
			} catch (_) {
				try { res.destroy(); } catch (_2) { /* nothing */ }
			}
		});
	});
	server.requestTimeout = ctx.opt.value('request-timeout') * 1000;
	server.headersTimeout = Math.min(server.requestTimeout, 30000);

	return server;
}

module.exports = createServer;
