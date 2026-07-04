CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS vault_user (
  s BIGSERIAL PRIMARY KEY,
  user_id UUID UNIQUE NOT NULL DEFAULT GEN_RANDOM_UUID(),
  -- sha256 digest of the bearer token UUID string; NULL => API access disabled
  auth_token BYTEA UNIQUE DEFAULT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS vault_key (
  s BIGSERIAL PRIMARY KEY,
  key_id UUID UNIQUE NOT NULL,
  kty TEXT NOT NULL,
  alg TEXT NOT NULL,
  not_before TIMESTAMPTZ DEFAULT NULL,
  expires_at TIMESTAMPTZ DEFAULT NULL,
  public_key JSONB DEFAULT NULL,
  embedding_key_id TEXT NOT NULL,
  embedded_key TEXT NOT NULL,
  acl JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS vault_key_expires_at_idx
  ON vault_key (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS vault_key_embedding_key_id_idx
  ON vault_key (embedding_key_id);
