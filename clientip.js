'use strict';

// Derive the genuine client IP from the TCP socket peer and the
// X-Forwarded-For header, honoring a count of TRUSTED reverse-proxy hops.
//
// X-Forwarded-For is attacker-controllable: any client can prepend forged
// entries. We therefore trust only the rightmost `hops` entries — the ones
// appended by reverse proxies we operate. Build the list
// [socketPeer, ...XFF reversed] and pick the entry at index `hops`
// (clamped to the list length).
//
//   hops = 0  -> ignore X-Forwarded-For entirely, use the socket peer
//               (correct when the service is exposed directly, no proxy).
//   hops = 1  -> trust exactly one proxy hop (the committed stack's single
//               nginx TLS proxy): returns the real client and ignores any
//               XFF prefix the client tried to forge.
//   hops = N  -> trust N chained proxies.
//
// When XFF has fewer than `hops` entries (e.g. a direct connection in a
// dev setup), the index is clamped and we fall back to the socket peer.
function deriveClientIp(socketPeer, xffHeader, hops) {
	const list = [ normIp(socketPeer) ];
	if (xffHeader) {
		const parts = String(xffHeader)
			  .split(',')
			  .map(normIp)
			  .filter(Boolean);
		// Append reversed so list[1] is the proxy closest to us.
		for (let i = parts.length - 1; i >= 0; i--) {
			list.push(parts[i]);
		}
	}
	let idx = Number.isInteger(hops) ? hops : 0;
	if (idx < 0) idx = 0;
	if (idx > list.length - 1) idx = list.length - 1;
	return list[idx] || normIp(socketPeer) || null;
}

// Normalize a single address token: trim, and unwrap the IPv4-mapped IPv6
// form (`::ffff:1.2.3.4` -> `1.2.3.4`) so stored/compared IPs are canonical.
function normIp(s) {
	if (! s) return null;
	s = String(s).trim();
	if (! s) return null;
	const m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(s);
	return m ? m[1] : s;
}

module.exports = { deriveClientIp, normIp };
