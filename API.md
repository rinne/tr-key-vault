# tr-key-vault — API reference (v1)

The API is a single JSON-over-POST entry point plus two
unauthenticated probe endpoints. This document is the operation
reference; see [`README.md`](README.md) for the architecture, the data
model, and operational guidance.

## Endpoints

| method & path | auth | purpose |
|---|---|---|
| `POST /api/v1` | bearer | all API operations (dispatch on `request`) |
| `GET /healthz` | none | liveness (no database access) |
| `GET /readyz` | none | readiness (database ping; 503 when unavailable) |

Any other path returns `404` (errorCode 1004); a known path with the
wrong method returns `405` (1003).

## Request envelope

```jsonc
POST /api/v1
Content-Type: application/json
Authorization: Bearer <auth-token-uuid>

{
  "user": "<user-id-uuid>",     // must match the bearer token's user
  "op": "<uuid>",               // client-generated correlation id, mandatory
  "request": "<operation-name>",
  "data": { /* operation specific */ }
}
```

- `op` must be a syntactically valid UUID (else `400`). It is echoed
  in every response, always normalized to lower case. The server does
  not enforce cross-request uniqueness.
- Unknown properties in the envelope or in `data` are rejected.
- Requests and responses are always `application/json; charset=utf-8`;
  responses carry `Cache-Control: no-store`.

## Response envelope

Success:

```jsonc
{ "status": "ok", "op": "<uuid>", "data": { /* operation specific */ } }
```

Failure:

```jsonc
{ "status": "error", "op": "<uuid>", "errorCode": <int>, "message": "<string>" }
```

`op` is omitted only when no valid one was recoverable from the
request (bad JSON, missing/invalid `op`, oversized body).

## HTTP status usage

| status | when |
|---|---|
| 200 | well-formed, authenticated request — even if the operation itself fails (`status: "error"` in the body). Includes unknown `request` values (errorCode 1002). |
| 400 | malformed: bad JSON, missing/mistyped envelope fields, invalid `op`, body too large, wrong content type |
| 403 | authentication failure — bad token, unknown token, user/token mismatch, account outside its nbf/exp window, client IP not allowed. Deliberately indistinguishable. |
| 404 | unknown path |
| 405 | known path, wrong method |
| 5xx | internal error, including a failed audit append |

## Error codes

| code | name | typical HTTP |
|---|---|---|
| 1000 | malformed-request | 400 |
| 1001 | unauthorized | 403 |
| 1002 | unknown-operation | 200 |
| 1003 | method-not-allowed | 405 |
| 1004 | unknown-endpoint | 404 |
| 1100 | invalid-request-data | 200 |
| 1101 | key-not-found (also ACL-denied and out-of-window keys) | 200 |
| 1102 | incompatible-key-type | 200 |
| 1103 | invalid-input-token | 200 |
| 1104 | operation-disabled | 200 |
| 1105 | invalid-acl | 200 |
| 1106 | key-not-available (wrapping KEK not configured; authorized callers only) | 200 |
| 1107 | operation-not-permitted (user `allowedOps` gate on `generate-key`/`list-keys`) | 200 |
| 1900 | internal-error | 500 |

Messages are short fixed strings. Within 1103 the message
distinguishes `Invalid input token`, `JWT token expired` and
`JWT token not yet valid`.

**Masking:** a key that does not exist, a key the caller has no
effective class on (see `allowedOps` below), and a key outside its
validity window all return exactly `1101 Key not found`. Key existence
is only revealed to users holding at least one effective class on the
key. The single exception is `1106 Key not available` (the wrapping KEK
is not configured on this server), returned only to
otherwise-authorized callers.

## ACL operation classes

`owner`, `encrypt`, `decrypt`, `sign`, `verify`, `export-public-key`,
`export-secret-key`, `revoke-key`.

`owner` implies every other class except operations disabled by
configuration (`export-key` without `--allow-export-key`). Every key
always has at least one owner.

## Per-user capability mask (`allowedOps`)

A user may carry an optional `allowedOps` array in `vault_user.data`
that caps what that user can do, **intersected** with the per-key ACL:
a caller is authorized for a key operation iff the key ACL grants the
class (owner expands to all classes) AND (`allowedOps` is absent OR the
class ∈ `allowedOps`), with configuration disables still on top.

- **Absent** `allowedOps` = unrestricted (the default). A **present**
  array restricts to its members; the **empty array** disables
  everything.
- Alphabet: the seven ACL classes (not `owner`) plus two user-level
  pseudo-classes `generate-key` and `list-keys`.
- A key operation blocked *solely* by `allowedOps` is masked
  identically to an ACL denial (`1101 Key not found`). `generate-key`
  and `list-keys` have no target key, so when their pseudo-class is not
  granted they return `1107 operation-not-permitted`.
- `export-key` therefore has a triple gate: `--allow-export-key` AND
  the `export-secret-key` ACL class AND `export-secret-key ∈
  allowedOps`. `generate-key --returnPublicKey` is always allowed (the
  caller just created the key); the standalone `public-key` operation
  is gated by `export-public-key ∩ allowedOps`.

This makes an escrow-style setup expressible: a *writer* who owns the
escrow key but has `allowedOps` of `["generate-key","encrypt",
"export-public-key"]` can create and encrypt to keys but never decrypt
or export the secret — while a different vault user, assigned in the
key ACL at generation, can read.

---

## Operations

### healthcheck

Authenticated liveness with process uptime.

- Request `data`: `{}`
- Response `data`: `{ "uptime": <full-seconds-since-process-start> }`

### generate-key

Generate a key (or key pair) into the vault. The caller is
automatically merged into the ACL as `owner`.

Request `data`:

```jsonc
{
  "alg": "<jose-alg>",            // MANDATORY, see the matrix below
  "kty": "oct" | "EC" | "RSA",    // optional; must match alg
  "crv": "P-256"|"P-384"|"P-521", // EC only
  "keyLength": <int>,             // oct: bits; RSA: modulus bits
  "nbf": <unix-ts>,               // optional key not-before
  "exp": <unix-ts>,               // optional key expiry (> now, > nbf)
  "acl": { "<user-uuid>": [ "<class>", ... ], ... },  // optional
  "returnPublicKey": <bool>       // default false; asymmetric only
}
```

Response `data`: `{ "kid": "<uuid>" }`, plus `"key": <public-jwk>`
when `returnPublicKey` is true.

Algorithm matrix:

| kty | alg | key size |
|---|---|---|
| oct | `A128GCM` `A192GCM` `A256GCM` | implied 128/192/256 bits |
| oct | `A128GCMKW` `A192GCMKW` `A256GCMKW` | implied |
| oct | `A128KW` `A192KW` `A256KW` | implied |
| oct | `HS256` `HS384` `HS512` | default 256/384/512; `keyLength` may exceed up to 4096, multiple of 8 |
| EC | `ECDH-ES` | `crv`, default `P-521` |
| EC | `ES256` `ES384` `ES512` | implies P-256/P-384/P-521 |
| RSA | `RSA-OAEP` | default 2048; `keyLength` 2048–16384 |
| RSA | `RSA-OAEP-256` | default 4096 |
| RSA | `RS256` `RS384` `RS512` | defaults 2048/3072/4096 |

Errors: 1100 (parameters), 1105 (ACL: not an object, unknown user,
unknown class).

### public-key

Fetch the public part of an asymmetric key. Requires
`export-public-key`.

- Request `data`: `{ "kid": "<uuid>" }`
- Response `data`: `{ "key": <public-jwk> }`
- Errors: 1101, 1102 (oct key).

### create-jwt

Sign a JWT with a vault key. Requires `sign`. The key algorithm must
be one of `HS256/384/512`, `ES256/384/512`, `RS256/384/512`.

- Request `data`: `{ "kid": "<uuid>", "data": { /* JWT payload */ } }`
- Response `data`: `{ "token": "<jwt>" }`

The protected header is always exactly `{ "typ": "JWT", "alg": <key
alg>, "kid": <kid> }` — there is no caller-supplied header. The
payload passes through as-is (the vault stamps no claims); registered
claims (`exp` `nbf` `iat` `iss` `sub` `aud` `jti`) are shape-validated
(1100 on violation).

Errors: 1101, 1102, 1100, 1106.

### verify-jwt

Parse and verify a JWT. Requires `verify` on the resolved key.

- Request `data`: `{ "token": "ey…", "kid": "<uuid>" }` (`kid`
  optional)
- Response `data`: `{ "header": { ... }, "data": { ... } }`

kid resolution: when both the request `kid` and the token header
`kid` are present they must match; at least one must be present. The
token header `alg` must equal the stored key's algorithm
(algorithm-confusion guard). Signature, `exp` and `nbf` are enforced.

Errors: 1101, 1102, 1103, 1106.

### create-jwe

Encrypt a JWE with a vault key. Requires `encrypt`. The key algorithm
must be one of `A{128,192,256}GCMKW`, `A{128,192,256}KW`, `ECDH-ES`,
`RSA-OAEP`, `RSA-OAEP-256`.

- Request `data`: `{ "kid": "<uuid>", "data": <any-json>,
  "compress": false | true | "auto" }` (`compress` optional, default
  `false`; `"auto"` compresses only when it makes the token smaller)
- Response `data`: `{ "token": "<jwe>" }`

The protected header is fully server-controlled. The content
encryption is selected from the key: `A*KW`/`A*GCMKW` → matching
`A*GCM`; `RSA-OAEP`/`RSA-OAEP-256` → `A256GCM`; `ECDH-ES` →
`A128GCM`/`A192GCM`/`A256GCM` by curve. Asymmetric keys encrypt with
the public half.

Errors: 1101, 1102, 1100, 1106.

### decrypt-jwe

Decrypt a JWE. Requires `decrypt` on the resolved key. Same kid
resolution and algorithm-confusion rules as verify-jwt.

- Request `data`: `{ "token": "ey…", "kid": "<uuid>" }` (`kid`
  optional)
- Response `data`: `{ "header": { ... }, "data": <json> }`

Errors: 1101, 1102, 1103, 1106.

### revoke-key

Hard-delete a key. Requires `revoke-key`. Always audited.

- Request `data`: `{ "kid": "<uuid>" }`
- Response `data`: `{ "kid": "<uuid>", "revoked": true }`
- Errors: 1101.

### export-key

Export the secret material of a key: the oct key, or the private part
of an asymmetric pair. Double-gated: the server must run with
`--allow-export-key` (default: off → 1104 for everyone) AND the
caller must hold `export-secret-key` on the key. Always audited.

- Request `data`: `{ "kid": "<uuid>" }`
- Response `data`: `{ "key": <full-jwk> }`
- Errors: 1104, 1101, 1106.

### list-keys

List the keys the caller holds at least one ACL class on, restricted
to keys inside their validity window. No pagination.

- Request `data`: `{}`
- Response `data`:
  `{ "keys": [ { "kid": "<uuid>", "kty": "<kty>", "alg": "<alg>" }, ... ] }`

---

## Authentication summary

1. `Authorization: Bearer <token>` — the token is a UUID; the server
   stores only its sha256 digest.
2. The envelope `user` must be the token's user.
3. The account must be inside its `nbf`/`exp` window (when set).
4. The client IP (derived from `X-Forwarded-For` honoring
   `--trusted-proxy-hops` rightmost trusted hops; `0` = socket peer)
   must match the account's `allowedIP` list: IPv4 address / CIDR /
   start–end range, IPv6 address / CIDR. An empty or missing list
   denies everything; allow-all must be explicit
   `["0.0.0.0/0", "0::/0"]`.

Every failure is the same `403` / errorCode 1001.

## Audit

Every operation except `healthcheck` is recorded in a tamper-evident
tr-json-chain audit chain (same database, namespace `kv`, event types
prefixed `tr-key-vault:`), including an authenticated caller's
ACL-violation attempts (the `denied` event). Coupling is strict: if
the audit append fails, the operation fails with 1900 — the vault
never returns a success response for an unaudited operation. Audit
payloads never contain key material, tokens, or payload/token
strings.

**Authentication failures are not audited.** Unauthenticated traffic
(bad/absent token, unknown user, user/token mismatch, out-of-window
account, disallowed IP) returns `403` with no audit write, so an
unauthenticated caller cannot drive audit-chain writes.
