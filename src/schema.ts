// Versioned schema runs automatically in each Durable Object.
export const schemaV1 = "CREATE TABLE users (\n  id TEXT PRIMARY KEY,\n  email TEXT NOT NULL UNIQUE COLLATE NOCASE,\n  name TEXT NOT NULL,\n  role TEXT NOT NULL DEFAULT 'family' CHECK(role IN ('admin','family')),\n  active INTEGER NOT NULL DEFAULT 1,\n  created_at INTEGER NOT NULL\n);\nCREATE TABLE passkeys (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL REFERENCES users(id),\n  public_key BLOB NOT NULL,\n  counter INTEGER NOT NULL DEFAULT 0,\n  transports TEXT NOT NULL DEFAULT '[]',\n  device_type TEXT NOT NULL,\n  backed_up INTEGER NOT NULL DEFAULT 0,\n  created_at INTEGER NOT NULL,\n  last_used_at INTEGER\n);\nCREATE INDEX passkeys_user_idx ON passkeys(user_id);\nCREATE TABLE invites (\n  token_hash TEXT PRIMARY KEY,\n  email TEXT NOT NULL COLLATE NOCASE,\n  role TEXT NOT NULL CHECK(role IN ('admin','family')),\n  expires_at INTEGER NOT NULL,\n  used_at INTEGER,\n  created_by TEXT\n);\nCREATE TABLE challenges (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  kind TEXT NOT NULL CHECK(kind IN ('register','login')),\n  challenge TEXT NOT NULL,\n  expires_at INTEGER NOT NULL,\n  registration_user_id TEXT,\n  display_name TEXT\n);\nCREATE TABLE sessions (\n  token_hash TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL REFERENCES users(id),\n  expires_at INTEGER NOT NULL,\n  created_at INTEGER NOT NULL\n);\nCREATE INDEX sessions_user_idx ON sessions(user_id);\n\nCREATE UNIQUE INDEX invites_single_bootstrap ON invites(role) WHERE role = 'admin';\n";

export const schemaV2 = `
CREATE TABLE oidc_codes (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT NOT NULL,
 nonce TEXT, challenge TEXT NOT NULL, auth_time INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE oidc_requests (
 id TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, client_id TEXT NOT NULL,
 redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, state TEXT NOT NULL, nonce TEXT,
 challenge TEXT NOT NULL, previous_session_hash TEXT, require_reauth INTEGER NOT NULL,
 max_age INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE oidc_tokens (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 scope TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE oidc_keys (
 kid TEXT PRIMARY KEY, private_jwk TEXT NOT NULL, public_jwk TEXT NOT NULL,
 active INTEGER NOT NULL, created_at INTEGER NOT NULL, retired_at INTEGER
);
CREATE UNIQUE INDEX oidc_one_active_key ON oidc_keys(active) WHERE active=1;
CREATE TABLE rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at INTEGER NOT NULL);
`;

// Existing invitations remain valid; zero timestamps predate rate-limit accounting.
export const schemaV3 = `
ALTER TABLE invites ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX invites_recipient_created_idx ON invites(email,created_by,created_at);
`;

export const schemaV4 = `
CREATE TABLE email_logins (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 browser_hash TEXT NOT NULL, code_hash TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL
);
CREATE INDEX email_logins_user_idx ON email_logins(user_id);
`;
