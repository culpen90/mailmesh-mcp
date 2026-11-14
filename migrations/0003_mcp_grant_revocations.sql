PRAGMA foreign_keys = ON;

-- KV grant deletion can race an in-flight refresh. Keep an authoritative,
-- tenant-scoped D1 tombstone long enough to outlive the maximum refresh grant
-- and every access token it could mint.
CREATE TABLE mcp_grant_revocations (
  user_id TEXT NOT NULL REFERENCES mailmesh_users(id) ON DELETE CASCADE,
  grant_id TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (user_id, grant_id)
);

CREATE INDEX idx_mcp_grant_revocations_expires_at
  ON mcp_grant_revocations(expires_at);
