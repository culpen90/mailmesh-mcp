# Security policy

MailMesh grants access to private email. Treat a deployed instance like a password manager or mail client backend.

## Supported version

Only the latest version on the default branch is supported.

## Reporting a vulnerability

Do not include mailbox contents, bearer tokens, OAuth credentials, IMAP passwords, D1 exports, or encryption keys in a public issue. Report the minimum reproduction details privately to the repository owner.

## Deployment checklist

- Keep `MAILMESH_TOKEN`, `TOKEN_ENCRYPTION_KEY`, and provider client secrets in Cloudflare Worker secrets.
- Keep the MCP OAuth dynamic-registration callback allowlist, body cap, and rate limits intact. Public OAuth setup consumes KV writes.
- Preserve PKCE S256, exact `/mcp` resource audience checks, official client callback origins and paths, one-use consent state, the versioned shared-client acknowledgment, and workspace grant validation when changing MCP OAuth.
- Never commit `.dev.vars`; it is ignored by Git.
- Use HTTPS for every deployed callback and MCP request.
- Restrict Cloudflare account access with multi-factor authentication.
- Prefer OAuth or IMAP app passwords over a primary mailbox password.
- Leave `WRITE_MODE=read-only` unless drafts are explicitly required.
- Treat `MAILMESH_TOKEN` as full workspace operator authority. Keep it in operator-controlled clients and rotate it after any suspected disclosure. Revoke all OAuth grants if an exposed token may have been used to approve connections.
- Relink provider accounts when rotating `TOKEN_ENCRYPTION_KEY`.
- Apply `0004_workspace.sql` and activate the matching Worker during the same maintenance window. Restore the matching D1 point before routing traffic back to the previous Worker.
- Each approved MCP client can access every enabled mailbox in the workspace, including accounts linked after approval. Anyone who can use the saved connection can exercise that access.
- Keep generic IMAP configuration behind the operator bearer.
- Review Cloudflare logs before enabling detailed request logging; email queries and message IDs can be sensitive.

## OAuth connection revocation

- `GET /admin/mcp-connections` and its `DELETE` routes require the operator bearer. The list returns connection IDs, client display names, scopes, and timestamps.
- `DELETE /admin/mcp-connections/CONNECTION_ID` records a D1 revocation before best-effort KV cleanup. MCP requests and token exchanges enforce the revocation even if an in-flight refresh rewrites KV.
- `DELETE /admin/mcp-connections` increments the D1 workspace authorization version before best-effort KV cleanup. Earlier grants fail authorization immediately.
- Rotate the Worker secret to invalidate direct access via `MAILMESH_TOKEN`. Email already returned may persist in client conversations, exports, or logs.
