PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS email_accounts (
  id TEXT PRIMARY KEY,
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_accounts_provider_email
  ON email_accounts(provider, email);
CREATE INDEX IF NOT EXISTS idx_email_accounts_enabled
  ON email_accounts(enabled, provider);

CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash TEXT PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('gmail', 'microsoft')),
  label TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at
  ON oauth_states(expires_at);
