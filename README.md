# tr-key-vault

PostgreSQL-backed standalone key vault server. Stores cryptographic
keys (symmetric keys and asymmetric key pairs) on behalf of
authenticated users and performs JWT/JWE operations with them
server-side, so that secret key material never leaves the vault.

- **Key material never leaves the vault** (and never enters it: no
  import). The only exceptions are public keys and the explicitly
  double-gated `export-key` operation.
- Secret key material is **never stored in cleartext**: every stored
  key is embedded into a JWE (per the tr-data-escrow
  [JWE Key Embedding convention](https://www.npmjs.com/package/tr-data-escrow))
  and encrypted with a vault-level embedding key (KEK).
- Per-key, per-user, per-operation-class ACLs with uniform existence
  masking.
- Tamper-evident, hash-chained **audit log**
  ([tr-json-chain](https://www.npmjs.com/package/tr-json-chain)) with
  strict coupling: no operation ever succeeds unaudited.
- Minimal JSON-over-POST API on Node's builtin `http` (no framework),
  designed to run behind
  [timorinne/nginx-auto-tls-proxy](https://hub.docker.com/r/timorinne/nginx-auto-tls-proxy).

This README is the complete guide to the architecture and operation of
the vault; [`API.md`](API.md) is the request/response reference for the
wire protocol.

## Architecture

The vault is a single Node process (builtin `http`, no framework)
between a TLS-terminating reverse proxy and PostgreSQL. It runs in its
own container; the model deployment (`dc/`) is a docker-compose stack
of the vault, `postgres:18`, and
[`timorinne/nginx-auto-tls-proxy`](https://hub.docker.com/r/timorinne/nginx-auto-tls-proxy).

```
                     ┌──────────────────────────────────────┐
   https             │  tr-key-vault (node builtin http)    │
client ─► kv-proxy ─►│  auth ─► ACL ─► keystore ─► token    │─► PostgreSQL
        (TLS, nginx- │            │      (KEK embed/        │   vault_user
         auto-tls-   │            │       extract, cache)   │   vault_key
         proxy)      │            └─► audit (tr-json-chain) │   kv_event_*
                     └──────────────────────────────────────┘
                          ▲ KEK JWK file(s), 0600, volume-mounted

  kv-admin CLI (same image, docker exec) ─► PostgreSQL + audit chain
```

Request flow on `POST /api/v1`: parse and validate the JSON envelope →
authenticate the bearer token and bind it to the claimed user, account
validity window and client IP → dispatch on the `request` name → check
the ACL on the target key → load the key row (ACL/validity always read
fresh from the database) → unwrap its secret material under the KEK
(cached) or use the public half → run the JWT/JWE operation with
`tr-jwt`/`tr-jwe` → append the audit event → respond. Administrative
tasks (user provisioning, ACL edits, KEK rewrap, audit verification)
are done with the **kv-admin** CLI, which talks straight to the
database; there is no HTTP admin surface.

The secret half of every stored key is embedded into a JWE — following
the tr-data-escrow
[JWE Key Embedding convention](https://www.npmjs.com/package/tr-data-escrow)
— and encrypted under the active **embedding key (KEK)** before it
touches the database, so the database never holds cleartext key
material.

## Data model

Two tables, created automatically at startup by numbered SQL migrations
(tracked in `schema_migrations`):

- **`vault_user`** — `user_id` (UUID), `auth_token` (the sha256 digest
  of the bearer token, or NULL to disable API access), and a `data`
  JSON object holding `allowedIP`, optional account-validity `nbf`/`exp`
  (unix seconds), `iat`, and `auth_token_ts`.
- **`vault_key`** — `key_id` (the kid, UUID), `kty`/`alg` (cleartext
  metadata), optional key-validity `not_before`/`expires_at`,
  `public_key` (public JWK, for asymmetric keys), `embedding_key_id`
  (which KEK wrapped this row), `embedded_key` (the secret material as
  a KEK-encrypted JWE), and `acl`.

The audit tables `kv_event_chain` / `kv_event_payload` live in the same
database but are created and owned by the tr-json-chain library, never
migrated here.

## Keys, operations and algorithms

Each stored key is created for exactly one JOSE algorithm (its `alg` is
mandatory and canonical). API operations, and the ACL class each needs
on the target key:

| operation | purpose | ACL class |
|---|---|---|
| `generate-key` | create a key/keypair in the vault | — (caller becomes owner) |
| `public-key` | fetch an asymmetric key's public JWK | `export-public-key` |
| `create-jwt` / `verify-jwt` | sign / verify a JWT | `sign` / `verify` |
| `create-jwe` / `decrypt-jwe` | encrypt / decrypt a JWE | `encrypt` / `decrypt` |
| `revoke-key` | hard-delete a key | `revoke-key` |
| `export-key` | export secret key material (double-gated) | `export-secret-key` + `--allow-export-key` |
| `list-keys` | list keys the caller can use | — (per-key) |
| `healthcheck` | authenticated uptime probe | — |

Supported algorithms (full parameter matrix in [`API.md`](API.md)):

- **Signing (JWT)**: `HS256/384/512`, `ES256/384/512` (P-256/384/521),
  `RS256/384/512`.
- **Encryption (JWE)**: `A{128,192,256}GCMKW`, `A{128,192,256}KW`,
  `ECDH-ES` (EC P-256/384/521), `RSA-OAEP`, `RSA-OAEP-256`. The inner
  content encryption is chosen by the vault from the key, never by the
  caller; JOSE protected headers are entirely server-controlled.

Key material never leaves the vault except the public key
(`public-key`, or `generate-key` with `returnPublicKey`) and the
deliberately double-gated `export-key`. There is no import.

## Quick start (docker compose)

```sh
cd dc
cp docker-compose.yaml-EXAMPLE docker-compose.yaml
cp kv.env-EXAMPLE kv.env
cp kv-postgres.env-EXAMPLE kv-postgres.env
# edit: passwords, the vault's public hostname, LETSENCRYPT_EMAIL

mkdir -p volumes/kv-vault/keys
../kek-gen volumes/kv-vault/keys/kek-active.json     # P-521 KEK
# The container runs as uid/gid 4242; the key files must be readable
# by it and by nobody else:
sudo chown 4242:4242 volumes/kv-vault/keys/*.json    # (Linux hosts)

docker compose -f docker-compose.yaml up --build -d
```

Provision the first user:

```sh
docker exec kv-vault node ./kv-admin add-user --allow-all
# -> prints <user-id>
docker exec kv-vault node ./kv-admin set-token --user <user-id>
# -> prints the bearer token EXACTLY ONCE (only its sha256 is stored)
```

Call the API:

```sh
curl -s https://vault.example.com/api/v1 \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{
    "user": "<user-id>",
    "op": "'"$(uuidgen | tr A-Z a-z)"'",
    "request": "generate-key",
    "data": { "alg": "ES256", "returnPublicKey": true }
  }'
```

## Running without docker

Requirements: Node ≥ 24, PostgreSQL ≥ 11 (model configuration:
PostgreSQL 18).

```sh
npm install
./kek-gen /path/to/kek-active.json
KV_OPT_PG_HOST=... KV_OPT_PG_USER=... KV_OPT_PG_DATABASE=... \
KV_OPT_EMBEDDING_KEY_FILE=/path/to/kek-active.json \
./tr-key-vault
```

The database schema is applied automatically at startup (numbered SQL
migrations, tracked in `schema_migrations`). The tr-json-chain audit
tables (`kv_event_chain`, `kv_event_payload`) are created and owned by
that library.

## Configuration

Every option is an optist long option with a `KV_OPT_*` environment
fallback (run `./tr-key-vault --help` for the authoritative list).

| option | env | default |
|---|---|---|
| `--listen-address` | `KV_OPT_LISTEN_ADDRESS` | `0.0.0.0` |
| `--listen-port` | `KV_OPT_LISTEN_PORT` | `8888` |
| `--db-host` `--db-port` `--db-user` `--db-password` `--db-database` `--db-max-connections` `--db-tls` | `KV_OPT_PG_HOST` `…_PORT` `…_USER` `…_PASSWORD` `…_DATABASE` `…_MAX_CONNECTIONS` `…_TLS` | `127.0.0.1` / `5432` / — / — / `data` / `32` / off |
| `--embedding-key-file` | `KV_OPT_EMBEDDING_KEY_FILE` | (required) |
| `--retired-embedding-key-file` (multi) | `KV_OPT_RETIRED_EMBEDDING_KEY_FILES` (colon-separated) | — |
| `--allow-export-key` | `KV_OPT_ALLOW_EXPORT_KEY` | **off** |
| `--trusted-proxy-hops` | `KV_OPT_TRUSTED_PROXY_HOPS` | `1` |
| `--max-request-body` | `KV_OPT_MAX_REQUEST_BODY` | `1048576` |
| `--request-timeout` | `KV_OPT_REQUEST_TIMEOUT` | `30` |
| `--expiry-sweep-interval` | `KV_OPT_EXPIRY_SWEEP_INTERVAL` | `60` |
| `--key-expiry-grace` | `KV_OPT_KEY_EXPIRY_GRACE` | `0` |
| `--key-cache-max-entries` | `KV_OPT_KEY_CACHE_MAX_ENTRIES` | `1024` (0 = off) |
| `--key-cache-ttl` | `KV_OPT_KEY_CACHE_TTL` | `300` |
| `--audit-seal-key-file` | `KV_OPT_AUDIT_SEAL_KEY_FILE` | (optional) |
| `--audit-seal-interval` | `KV_OPT_AUDIT_SEAL_INTERVAL` | `3600` |
| `--debug` | `KV_OPT_DEBUG` | off |

Startup is fail-fast: bad configuration, unreadable/invalid KEK
files, an unreachable database, or an audit-chain init failure abort
the process.

**`--trusted-proxy-hops` MUST match the real deployment depth.** The
client IP for per-user `allowedIP` checks is derived from
`X-Forwarded-For`, trusting only that many rightmost entries. The
committed dc/ stack runs exactly one nginx proxy (`1`); set `0` when
the vault is reached directly. A wrong value makes `allowedIP`
spoofable.

Prefer environment/file configuration over argv in production — argv
is visible in `ps`.

## kv-admin

Administrative operations run in the same image and talk directly to
the database (there is no HTTP admin API):

```
kv-admin <command> [options]

add-user       --allow-all | --allowed-ip <entry> ... [--nbf ts] [--exp ts]
               [--allowed-ops <class> ...] [--co-owner <uuid> ...]
set-token      --user <uuid>          # prints the bearer token once
revoke-token   --user <uuid>
set-user-data  --user <uuid> [--allow-all | --allowed-ip <entry> ...]
               [--nbf ts | --clear-nbf] [--exp ts | --clear-exp]
               [--allowed-ops <class> ... | --clear-allowed-ops]
               [--co-owner <uuid> ... | --clear-co-owners]
remove-user    --user <uuid>
list-users
update-acl     --kid <uuid> --acl '<json-acl-object>'
rewrap         --embedding-key-file <file> [--retired-embedding-key-file <file> ...]
verify-audit
```

Database access uses the same `--db-*` / `KV_OPT_PG_*` options as the
server. Every command is audit-logged; a command fails if its audit
append fails.

`allowedIP` entries: IPv4 address, IPv4 CIDR, IPv4 `start-end` range,
IPv6 address, IPv6 CIDR (IPv6 ranges deliberately excluded). An empty
or missing list denies all API access; `--allow-all` writes the
explicit `["0.0.0.0/0", "0::/0"]`.

`--allowed-ops` (repeatable) sets the user's capability mask (see
[Authorization](#authorization-and-existence-masking)); classes are the
seven ACL classes (not `owner`) plus `generate-key` and `list-keys`.
`--allowed-ops none` sets the explicit empty (deny-all) mask;
`--clear-allowed-ops` removes the mask (back to unrestricted).

`--co-owner` (repeatable) sets the user's `coOwners` list: user UUIDs
auto-added as `owner` to keys the user creates **without** an explicit
ACL (see [Authorization](#authorization-and-existence-masking)).
`--clear-co-owners` removes the list. Entries are validated as UUIDs;
whether each still exists is checked at key-generation time.

## Vault embedding keys (KEKs)

The vault always wraps stored keys with exactly one **active** KEK;
any number of **retired** KEKs can still unwrap. KEKs are JWK files
(mode 0600 enforced — group/world-readable key files are refused),
generated with the bundled `kek-gen`:

```sh
./kek-gen kek-active.json                      # EC P-521 (preferred)
./kek-gen -a RSA-OAEP-256 kek-active.json      # RSA 4096
./kek-gen -a A256GCMKW kek-active.json         # symmetric (discouraged)
```

Accepted KEK types: EC P-256/P-384/P-521 (ECDH-ES), RSA `RSA-OAEP` /
`RSA-OAEP-256` (modulus ≥ 2048), oct `A{128,192,256}GCMKW` /
`A{128,192,256}KW`.

### KEK rotation runbook

1. Generate a new KEK: `kek-gen keys/kek-active-2.json`.
2. Reconfigure: the new file becomes `--embedding-key-file`, the old
   one moves to `--retired-embedding-key-file` (colon-separated in
   `KV_OPT_RETIRED_EMBEDDING_KEY_FILES`).
3. Restart the vault. Old rows keep working via the retired KEK; new
   keys wrap with the new one.
4. Re-embed old rows so the retired KEK can eventually be dropped:
   `kv-admin rewrap --embedding-key-file keys/kek-active-2.json
   --retired-embedding-key-file keys/kek-active-1.json`.
5. Once `rewrap` reports no skipped rows and the server no longer
   warns about unknown embedding keys at startup, remove the retired
   file from the configuration and destroy it.

If the vault starts with rows wrapped by a KEK it does not have, it
logs a warning and continues; authorized callers touching such keys
get the distinct error `Key not available` (1106) until the KEK is
restored.

## Authentication

Every API request (except the unauthenticated `GET /healthz` /
`GET /readyz` probes) must carry `Authorization: Bearer <token>` where
the token is a UUID, and the envelope `user` must be that token's
user. The account must be inside its `nbf`/`exp` window when set, and
the client IP — derived from `X-Forwarded-For` honoring
`--trusted-proxy-hops` (or the socket peer when that is `0`) — must
match the account's `allowedIP` list (IPv4 address / CIDR /
`start-end` range, IPv6 address / CIDR; an empty or missing list
denies everything, allow-all is the explicit `["0.0.0.0/0", "0::/0"]`).
Every failure returns the same `403` and is not audited.

## Authorization and existence masking

Each key carries an ACL mapping user UUIDs to sets of operation
classes: `owner`, `encrypt`, `decrypt`, `sign`, `verify`,
`export-public-key`, `export-secret-key`, `revoke-key`. `owner`
implies every other class except operations disabled by configuration
(`export-key` without `--allow-export-key`). Every key always keeps at
least one owner. The caller of `generate-key` is automatically added
as an owner; further ACL entries are validated (users must exist,
classes must be known) at creation and on `kv-admin update-acl`.

**Per-user capability mask (`allowedOps`).** A user may carry an
optional `allowedOps` array in `vault_user.data` that caps what they
can do: effective rights are the **intersection** of the key ACL grant
(owner expanded) and `allowedOps`, with configuration disables still on
top. An **absent** `allowedOps` is unrestricted (the default); a
present array restricts to its members; the **empty array disables
everything**. The alphabet is the seven ACL classes (not `owner`) plus
two user-level pseudo-classes `generate-key` and `list-keys`, which
must be granted explicitly once a user has any `allowedOps`.

This makes escrow-style separation expressible: a *writer* with
`allowedOps` `["generate-key","encrypt","export-public-key"]` can
create escrow keys and encrypt to them but — even as the key's owner —
can never `decrypt` or `export-key` the secret; a *different* vault
user, assigned in the key's ACL at generation, does the reading.

**Co-owners (`coOwners`).** A user may carry an optional `coOwners`
array of user UUIDs in `vault_user.data`. When that user generates a
key **without** an explicit `acl` in the request, every listed
co-owner is added to the key's ACL as `owner` — a convenience so remote
callers get shared ownership without composing an ACL each time.
Co-owners are filtered to syntactic UUIDs and to currently-existing
users (unknown or deleted ids are silently dropped). Supplying an
explicit `acl` (even an empty `{}`) suppresses `coOwners` and uses the
submitted ACL verbatim (still auto-merging the caller as owner).

**Existence masking**: a key that does not exist, a key the caller has
no *effective* class on (ACL ∩ `allowedOps`), and a key outside its
validity window all return exactly the same `1101 Key not found` — an
`allowedOps` denial is indistinguishable from an ACL denial. A key's
existence is only revealed to users with at least one effective class
on it. `generate-key` and `list-keys` have no target key to mask, so an
`allowedOps` denial of those returns `1107 operation-not-permitted`.
The one deliberate exception to key masking is `1106 Key not available`
(the wrapping KEK is not configured), returned only to an already
authorized caller.

## Key lifecycle and expiration

A key may carry `not_before` / `expires_at` timestamps. The validity
window is enforced **at read time on every access** — a not-yet-valid
or expired key is unusable for every operation and is masked as
`1101`, immediately at the boundary moment, independent of any
background job. A separate sweep (default every 60 s, with an optional
`--key-expiry-grace`) hard-deletes expired rows purely as hygiene.
`revoke-key` hard-deletes immediately. There is no key rotation or
re-issue: generate a new key instead.

This is what lets the vault back "hands-off" expiring escrows (see
below) — the key simply stops working and is reaped on its own
schedule, with nothing to track on the client side.

An in-memory cache avoids repeating the KEK-unwrap crypto for hot
keys, but it never short-circuits the database: the key row, its ACL
and its validity window are read fresh on every request, so a revoked,
re-ACLed or rewrapped key is never served from stale state.

## Audit chain

Every operation except `healthcheck` — including an authenticated
caller's ACL-violation attempts (`denied`) and every kv-admin command
— is recorded in an append-only SHA-256 hash-chained log in the same
database (tr-json-chain, namespace `kv`, event types
`tr-key-vault:*`). Coupling is strict: an operation whose audit append
fails returns `internal-error` — there is never a success response
without a recorded event. A `ts` heartbeat is appended every 60 s.

Authentication failures (bad or absent token, unknown user,
user/token mismatch, out-of-window account, disallowed IP) are
**not** audited: they return `403` with no chain write, so
unauthenticated traffic cannot drive audit-chain growth or lock
contention. Audit payloads never contain key material, tokens, or
token strings.

- Verify: `kv-admin verify-audit` (full server-side re-hash).
- DB-free verification: export with `tr-json-chain-cli` and check with
  `tr-json-chain-check` (npm package `tr-json-chain-tools`).
- Publish or cross-log the chain head periodically for external
  anchoring.

### Sealing

Optionally the chain can be cryptographically **sealed**: a private
seal JWK (`--audit-seal-key-file`) signs periodic seal events, and the
matching public key is fixed into the chain-root event.

**The seal key must be configured at the chain's FIRST init** — the
root event is immutable, so enabling sealing later means starting a
new chain. The key is fixed for the chain's lifetime. Generate with
`tr-json-chain-seal-keygen` (npm package `tr-json-chain-tools`) and
store beside the KEKs.

## User accounts

Users are provisioned with kv-admin only (there is no self-service or
HTTP user API). A user gets API access once `set-token` issues a
bearer token; only its sha256 digest is stored, so a database leak
reveals no usable credentials, and the token itself is shown exactly
once at issue. `allowedIP` and the optional account-validity
`nbf`/`exp` gate every request (see Authentication and the data model
above), the optional `allowedOps` mask caps the user's capabilities,
and the optional `coOwners` list grants shared ownership of keys the
user creates (see [Authorization](#authorization-and-existence-masking)).

## tr-data-escrow integration

[tr-data-escrow](https://www.npmjs.com/package/tr-data-escrow) stays
fully independent of this project — it does not depend on the vault
and works standalone with locally generated keys. The vault is an
**optional** backend: an individual escrow can be backed by a vault
key that is non-expiring, or expiring. Since the vault enforces and
reaps expiry autonomously, an expiring-key escrow gets **hands-off
expiration** — tr-data-escrow never has to track or act on the
deadline; once the vault key is gone the escrow is permanently
undecryptable.

As that backend the vault is used like this:

- **Writer**: `generate-key` with `"alg": "ECDH-ES"` (or `RSA-OAEP`)
  and `"returnPublicKey": true`; use the returned public JWK as the
  escrow key. The secret half never leaves the vault.
- **Reader**: recovery via `decrypt-jwe` on the escrow metadata /
  auto-key JWEs — they are ordinary tr-jwe tokens wrapped to the
  vault-held key, so the secret key stays inside the vault even
  during recovery. `export-key` is the (normally disabled) escape
  hatch.

## Client library and CLI

A separate package,
[tr-key-vault-client](https://www.npmjs.com/package/tr-key-vault-client),
provides a `KeyVaultClient` library and a `kv-client` command line
client for this API — the convenient way to call the vault from code
or the shell (operators and testing). It is not bundled with the
server; install or run it on the calling side:

```sh
npm install tr-key-vault-client
# or, without installing:
npx --package=tr-key-vault-client kv-client healthz --url https://vault.example.com/
```

See that package for its documentation. The wire protocol it speaks is
[`API.md`](API.md).

## Development

```sh
npm install
npm test        # node --test; spins up throwaway PostgreSQL clusters
                # (requires initdb/pg_ctl in PATH)
```

The suite covers the unit level (ACL, IP matching, key generation
matrix, KEK embed/extract, unwrap cache), the database layer, the
full HTTP API (auth, masking, every operation, audit coupling, KEK
rotation, proxy-hop spoof resistance), and the real binaries end to
end (boot via environment config, kv-admin, sealed audit chain,
clean shutdown).

Style: plain JavaScript, CommonJS, `'use strict'`, tabs, flat file
layout, `ctx`-object pattern. See `CLAUDE.md`.

## Security notes

- The KEK files (and the optional seal key) are the crown jewels:
  mount read-only, mode 0600, never logged, never in the database.
- A database compromise alone reveals no secret key material and no
  usable credentials; it does reveal key metadata (kty/alg), public
  keys, ACLs and the audit chain (whose payloads contain no secrets).
- The vault must not be reachable except through the reverse proxy
  (the dc/ stack publishes no vault port on the host).
- Existence masking is uniform (see API.md); algorithm-confusion
  guards are enforced on verify/decrypt; all JOSE protected headers
  are server-controlled.

## Author and license

Copyright (c) 2026 Timo J. Rinne <tri@iki.fi>

tr-key-vault is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see
<https://www.gnu.org/licenses/>. The full license text is in the
[`COPYING`](COPYING) file.
