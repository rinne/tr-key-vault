'use strict';

async function delay(ms) {
	return new Promise(function (resolve, reject) { setTimeout(resolve, ms); });
}

function ts() {
	return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function log(...av) {
	console.log((ts() + ':'), ...av);
}

function fatal(...av) {
	console.error((ts() + ':'), ...av);
	process.exit(1);
}

function nullish(...x) {
	for (let a of x) {
		if ((a === undefined) || (a === null)) {
			return true;
		}
	}
	return false;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isUuid(s) {
	return ((typeof(s) === 'string') && UUID_RE.test(s));
}

function isPlainObject(x) {
	return ((typeof(x) === 'object') && (x !== null) && ! Array.isArray(x));
}

function isUnixTs(x) {
	return (Number.isSafeInteger(x) && (x > 0));
}

module.exports = { delay, ts, log, fatal, nullish, isUuid, isPlainObject, isUnixTs };
