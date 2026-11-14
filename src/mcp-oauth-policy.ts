export const MAILMESH_MCP_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
export const MAILMESH_MCP_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MCP_GRANT_PRINCIPAL = "mailmesh-workspace";

// A targeted-revocation tombstone must outlive the refresh grant plus the last
// access token it could mint. Keep an additional day for clock/cleanup margin.
export const MCP_GRANT_REVOCATION_RETENTION_SECONDS =
  MAILMESH_MCP_REFRESH_TOKEN_TTL_SECONDS + MAILMESH_MCP_ACCESS_TOKEN_TTL_SECONDS + 24 * 60 * 60;

export const MCP_GRANT_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
export const SHARED_CLIENT_ACCESS_ACKNOWLEDGEMENT_VERSION = 1;
