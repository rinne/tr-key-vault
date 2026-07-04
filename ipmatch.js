'use strict';

// Matching of client IP addresses against per-user allowedIP entries.
//
// Entry forms:
//   IPv4 address           1.2.3.4
//   IPv4 CIDR              1.2.3.0/24
//   IPv4 range             1.2.3.4-1.2.3.99
//   IPv6 address           2001:db8::1
//   IPv6 CIDR              2001:db8::/32
//
// IPv6 start-end ranges are deliberately excluded. An empty allowedIP
// array denies everything; allow-all must be explicit
// [ '0.0.0.0/0', '0::/0' ]. A missing allowedIP property fails closed
// (the caller's responsibility; ipAllowed() below treats a non-array
// as deny).

function parseIPv4(s) {
	if (typeof(s) !== 'string') {
		return null;
	}
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
	if (! m) {
		return null;
	}
	let v = 0;
	for (let i = 1; i <= 4; i++) {
		const o = Number.parseInt(m[i], 10);
		if (o > 255) {
			return null;
		}
		v = (v * 256) + o;
	}
	return v;
}

function parseIPv6(s) {
	if (typeof(s) !== 'string') {
		return null;
	}
	s = s.trim().toLowerCase();
	if (! s) {
		return null;
	}
	// Embedded IPv4 tail (e.g. ::ffff:1.2.3.4) -> two hex groups.
	const m4 = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
	if (m4) {
		const v4 = parseIPv4(m4[2]);
		if (v4 === null) {
			return null;
		}
		s = m4[1] + (Math.floor(v4 / 65536)).toString(16) + ':' + (v4 % 65536).toString(16);
	}
	let head, tail;
	const dc = s.indexOf('::');
	if (dc >= 0) {
		if (s.indexOf('::', dc + 1) >= 0) {
			return null;
		}
		head = s.slice(0, dc) ? s.slice(0, dc).split(':') : [];
		tail = s.slice(dc + 2) ? s.slice(dc + 2).split(':') : [];
		if ((head.length + tail.length) > 7) {
			return null;
		}
	} else {
		head = s.split(':');
		tail = [];
		if (head.length !== 8) {
			return null;
		}
	}
	const groups = head.concat(new Array(8 - head.length - tail.length).fill('0'), tail);
	let v = 0n;
	for (const g of groups) {
		if (! /^[0-9a-f]{1,4}$/.test(g)) {
			return null;
		}
		v = (v << 16n) | BigInt(Number.parseInt(g, 16));
	}
	return v;
}

// Parse a single allowedIP entry into a matcher descriptor or null on
// invalid syntax. Invalid entries never match (fail closed) but are
// reported by validateAllowedIP() for admin tooling.
function parseEntry(entry) {
	if (typeof(entry) !== 'string') {
		return null;
	}
	const s = entry.trim();
	if (/^[^\/]+\/\d{1,3}$/.test(s)) {
		const [ addr, lenStr ] = s.split('/');
		const len = Number.parseInt(lenStr, 10);
		const v4 = parseIPv4(addr);
		if (v4 !== null) {
			if (len > 32) {
				return null;
			}
			return { family: 4, type: 'cidr', addr: v4, len };
		}
		const v6 = parseIPv6(addr);
		if (v6 !== null) {
			if (len > 128) {
				return null;
			}
			return { family: 6, type: 'cidr', addr: v6, len };
		}
		return null;
	}
	if (s.includes('-')) {
		const parts = s.split('-');
		if (parts.length !== 2) {
			return null;
		}
		const start = parseIPv4(parts[0]);
		const end = parseIPv4(parts[1]);
		if ((start === null) || (end === null) || (start > end)) {
			return null;
		}
		return { family: 4, type: 'range', start, end };
	}
	const v4 = parseIPv4(s);
	if (v4 !== null) {
		return { family: 4, type: 'addr', addr: v4 };
	}
	const v6 = parseIPv6(s);
	if (v6 !== null) {
		return { family: 6, type: 'addr', addr: v6 };
	}
	return null;
}

function matchEntry(desc, family, addr) {
	if ((! desc) || (desc.family !== family)) {
		return false;
	}
	switch (desc.type) {
	case 'addr':
		return (desc.addr === addr);
	case 'range':
		return ((addr >= desc.start) && (addr <= desc.end));
	case 'cidr':
		if (family === 4) {
			if (desc.len === 0) {
				return true;
			}
			const mask = (0xffffffff >>> 0) - ((2 ** (32 - desc.len)) - 1);
			return (((addr & mask) >>> 0) === ((desc.addr & mask) >>> 0));
		} else {
			if (desc.len === 0) {
				return true;
			}
			const shift = BigInt(128 - desc.len);
			return ((addr >> shift) === (desc.addr >> shift));
		}
	default:
		return false;
	}
}

// True when `ip` (a string, IPv4 dotted quad or IPv6) is allowed by
// the allowedIP list. A non-array or empty list denies everything;
// invalid entries are skipped (they never allow anything).
function ipAllowed(ip, allowedList) {
	if (! Array.isArray(allowedList)) {
		return false;
	}
	let family, addr;
	const v4 = parseIPv4(ip);
	if (v4 !== null) {
		family = 4;
		addr = v4;
	} else {
		const v6 = parseIPv6(ip);
		if (v6 === null) {
			return false;
		}
		family = 6;
		addr = v6;
	}
	for (const entry of allowedList) {
		if (matchEntry(parseEntry(entry), family, addr)) {
			return true;
		}
	}
	return false;
}

// Returns the list of syntactically invalid entries (empty array =
// all valid). For admin tooling.
function validateAllowedIP(allowedList) {
	if (! Array.isArray(allowedList)) {
		return [ '(not an array)' ];
	}
	return allowedList.filter(function(e) { return (parseEntry(e) === null); });
}

module.exports = { ipAllowed, validateAllowedIP, parseIPv4, parseIPv6 };
