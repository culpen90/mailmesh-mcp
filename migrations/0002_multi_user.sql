PRAGMA foreign_keys = ON;
PRAGMA defer_foreign_keys = ON;

CREATE TABLE mailmesh_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  display_name TEXT NOT NULL,
  password_algorithm TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_iterations INTEGER NOT NULL CHECK (password_iterations >= 0),
  auth_version INTEGER NOT NULL DEFAULT 1 CHECK (auth_version > 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (
    (
      id = 'mailmesh-owner' AND password_algorithm = '' AND password_hash = '' AND
      password_salt = '' AND password_iterations = 0
    ) OR (
      password_algorithm = 'pbkdf2-sha256-hmac-pepper-v1' AND password_iterations = 50000 AND
      length(password_hash) = 43 AND length(password_salt) = 22
    )
  )
);

-- Keep the established identity so existing MCP grants and linked mailboxes can
-- be upgraded in place. The administrator configures its password after deploy.
INSERT INTO mailmesh_users (
  id, username, display_name, password_algorithm, password_hash, password_salt,
  password_iterations, auth_version, enabled, created_at, updated_at
) VALUES (
  'mailmesh-owner', 'owner', 'MailMesh Owner', '', '', '', 0, 1, 1,
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

DROP INDEX IF EXISTS idx_email_accounts_provider_email;
DROP INDEX IF EXISTS idx_email_accounts_enabled;

CREATE TABLE email_accounts_v2 (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES mailmesh_users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('gmail', 'microsoft', 'imap')),
  email TEXT NOT NULL,
  label TEXT NOT NULL,
  encrypted_credentials TEXT NOT NULL,
  provider_config TEXT NOT NULL DEFAULT '{}',
  scopes TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_error TEXT
);

INSERT INTO email_accounts_v2 (
  id, user_id, provider, email, label, encrypted_credentials,
  provider_config, scopes, enabled, created_at, updated_at, last_error
)
SELECT
  id, 'mailmesh-owner', provider, email, label, encrypted_credentials,
  provider_config, scopes, enabled, created_at, updated_at, last_error
FROM email_accounts;

DROP TABLE email_accounts;
ALTER TABLE email_accounts_v2 RENAME TO email_accounts;

CREATE UNIQUE INDEX idx_email_accounts_user_provider_email
  ON email_accounts(user_id, provider, email);
CREATE INDEX idx_email_accounts_user_enabled
  ON email_accounts(user_id, enabled, provider);

DROP INDEX IF EXISTS idx_oauth_states_expires_at;

CREATE TABLE oauth_states_v2 (
  state_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES mailmesh_users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('gmail', 'microsoft')),
  label TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

INSERT INTO oauth_states_v2 (
  state_hash, user_id, provider, label, code_verifier, expires_at, created_at
)
SELECT
  state_hash, 'mailmesh-owner', provider, label, code_verifier, expires_at, created_at
FROM oauth_states;

DROP TABLE oauth_states;
ALTER TABLE oauth_states_v2 RENAME TO oauth_states;

CREATE INDEX idx_oauth_states_expires_at
  ON oauth_states(expires_at);
CREATE INDEX idx_oauth_states_user_id
  ON oauth_states(user_id);
