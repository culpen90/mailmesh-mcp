PRAGMA foreign_keys = ON;

-- Stop before publishing any private mailbox or reopening a disabled owner.
-- Wrangler applies each migration as a batch and rolls it back on error.
CREATE TABLE workspace_migration_guard (
  private_mailboxes INTEGER NOT NULL
    CONSTRAINT unlink_private_mailboxes_before_workspace_migration CHECK (private_mailboxes = 0),
  disabled_owner_mailboxes INTEGER NOT NULL
    CONSTRAINT review_disabled_owner_mailboxes_before_workspace_migration CHECK (disabled_owner_mailboxes = 0)
);

INSERT INTO workspace_migration_guard (private_mailboxes, disabled_owner_mailboxes)
SELECT
  count(*) FILTER (WHERE user_id <> 'mailmesh-owner'),
  count(*) FILTER (WHERE user_id = 'mailmesh-owner' AND NOT EXISTS (
    SELECT 1 FROM mailmesh_users WHERE id = 'mailmesh-owner' AND enabled = 1
  ))
FROM email_accounts;

DROP TABLE workspace_migration_guard;

CREATE TABLE workspace_email_accounts (
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

INSERT INTO workspace_email_accounts (
  id, provider, email, label, encrypted_credentials, provider_config,
  scopes, enabled, created_at, updated_at, last_error
)
SELECT
  id, provider, email, label, encrypted_credentials, provider_config,
  scopes, enabled, created_at, updated_at, last_error
FROM email_accounts
WHERE user_id = 'mailmesh-owner';

DROP TABLE email_accounts;
ALTER TABLE workspace_email_accounts RENAME TO email_accounts;

CREATE UNIQUE INDEX idx_email_accounts_provider_email ON email_accounts(provider, email);
CREATE INDEX idx_email_accounts_enabled ON email_accounts(enabled, provider);

-- A pending link was approved under the previous access model. Start new links
-- under the workspace model, keeping the existing callback URLs.
DROP TABLE oauth_states;
CREATE TABLE oauth_states (
  state_hash TEXT PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('gmail', 'microsoft')),
  label TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_oauth_states_expires_at ON oauth_states(expires_at);

-- Existing MCP grants use a retired authorization format. Their tombstones
-- can be discarded alongside the old identities.
DROP TABLE mcp_grant_revocations;
CREATE TABLE mcp_grant_revocations (
  grant_id TEXT NOT NULL PRIMARY KEY,
  revoked_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_mcp_grant_revocations_expires_at ON mcp_grant_revocations(expires_at);

DROP TABLE mailmesh_users;

CREATE TABLE mcp_workspace (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  auth_version INTEGER NOT NULL CHECK (auth_version BETWEEN 1 AND 9007199254740991)
);

INSERT INTO mcp_workspace (id, auth_version) VALUES (1, 1);
