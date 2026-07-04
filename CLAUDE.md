# tr-key-vault — repository instructions

PostgreSQL-backed key vault server for JWT/JWE/JWK operations.

**Normative documents, in order of authority: `SPEC.md` (frozen for
v1), `API.md`, `IMPLEMENTATION-PLAN.md`.** All design decisions and
their rationale are logged in `OPEN-QUESTIONS.md` — do not silently
re-decide anything recorded there; spec changes go through a new
numbered OPEN-QUESTIONS round with the user.

`SPEC.md`, `IMPLEMENTATION-PLAN.md`, `OPEN-QUESTIONS.md` and
`FUTURE-NOTES.md` are **internal working docs, git-ignored** — they
live in the working tree but are not committed. The committed,
external-facing docs are `README.md` (architecture + operation) and
`API.md` (wire protocol). When a decision changes behaviour, update
both the internal SPEC and the committed README/API.md.

## Commands

- `npm test` — full suite (`node --test --test-concurrency=1`).
  Requires `initdb`/`pg_ctl` in PATH; each DB test file boots a
  throwaway PostgreSQL cluster.
- `node --test test/<file>.test.js` — single file.
- `./tr-key-vault` — run the server (see README for required env).
- `./kv-admin <command>` — admin CLI. `./kek-gen <file>` — KEK
  generation.

## Style (scoopshot conventions)

- Plain JavaScript, CommonJS, `'use strict';`, **tab indentation**,
  single quotes, semicolons. No TypeScript, no ESM, no frameworks.
- Flat file layout at the repo root; `index.js` is the async main,
  `tr-key-vault`/`kv-admin`/`kek-gen` are thin shebang launchers.
- `ctx` object pattern: modules receive a context carrying `opt`
  (optist), `db`, `kek`, `keystore`, `audit`, `log`, `debug`.
- Configuration only via optist options with `KV_OPT_*` environment
  fallbacks (`serveropts.js`, `dbopts.js`).
- Node ≥ 24 (required by tr-jwe/tr-jwt).

## Architecture invariants (do not break)

- Secret key material is never stored in cleartext: `keystore.js`
  embeds every key via `kek.js` into a JWE (JWE-KEY-EMBEDDING
  convention) under the active KEK.
- Key material never leaves the vault except `public-key` /
  `returnPublicKey` and the double-gated `export-key`
  (`--allow-export-key` AND `export-secret-key` class). No import.
- Existence masking: missing key, ACL-denied key and out-of-window
  key are all `1101 Key not found`; `1106` only after authorization.
- Audit coupling is strict (`server.js` dispatcher, `kvadmin.js`):
  the event is appended before the response; append failure fails the
  operation. Every operation except `healthcheck` is audited. Audit
  payloads must never contain key material, tokens, or token strings.
- The nbf/exp validity window is enforced at read time on every
  access; the expiry sweep is hygiene only.
- The unwrap cache never skips the per-request DB row fetch (ACL and
  window are always fresh); it only skips KEK-unwrap crypto.
- tr-json-chain owns `kv_event_chain`/`kv_event_payload`; never
  create or migrate those tables here.
- HTTP protected headers (JWT and JWE) are fully server-controlled;
  there is deliberately no caller `header` parameter.

## Testing conventions

- Node builtin test runner, `assert/strict`. Integration harnesses in
  `test/pgtestenv.js` (throwaway cluster) and `test/fixtures.js`
  (KEK fixtures, opt stub, full in-process vault + HTTP helpers).
- `test/boot.test.js` exercises the real binaries via env config —
  keep it passing; it is the deployment smoke test.
