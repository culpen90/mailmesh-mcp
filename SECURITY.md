# Security policy

MailMesh grants access to private email. Treat a deployed instance like a password manager or mail client backend.

## Supported version

Only the latest version on the default branch is supported.

## Reporting a vulnerability

Do not include mailbox contents, bearer tokens, OAuth credentials, IMAP passwords, D1 exports, or encryption keys in a public issue. Report the minimum reproduction details privately to the repository owner.

## Deployment checklist

- Keep `MAILMESH_TOKEN`, `TOKEN_ENCRYPTION_KEY`, and provider client secrets in Cloudflare Worker secrets.
- Keep the MCP OAuth dynamic-registration callback allowlist, body cap, partitioned OAuth limiter, and separate password-attempt limiter intact; public OAuth setup consumes KV writes.
- Preserve PKCE S256, exact `/mcp` resource audience checks, one-use consent state, password-backed user identity, and tenant-bound grant props when changing MCP OAuth.
- Never commit `.dev.vars`; it is ignored by Git.
- Use HTTPS for every deployed callback and MCP request.
- Restrict Cloudflare account access with multi-factor authentication.
- Prefer OAuth or IMAP app passwords over a primary mailbox password.
- Leave `WRITE_MODE=read-only` unless drafts are explicitly required.
- Rotate the MailMesh token and provider credentials after any suspected disclosure. Treat `MAILMESH_TOKEN` as full-instance operator authority and `TOKEN_ENCRYPTION_KEY` as both the credential-encryption key and password-verifier pepper; rotating the latter requires password resets and provider relinking for every user.
- Never split traffic between the v1 and v2 Workers. After the multi-user migration, fix forward or restore D1 to a pre-migration Time Travel point before routing traffic to v1; an app-only rollback is tenant-unsafe.
- Keep every mailbox D1 read and mutation scoped by the authenticated `user_id`; an opaque account ID is never authorization.
- Do not expose generic IMAP self-service to untrusted users without an outbound-host allowlist and DNS-rebinding protection.
- Reconnect ChatGPT and Claude after rotating the MailMesh token if you also revoke their OAuth grants in `OAUTH_KV`.
- Review Cloudflare logs before enabling detailed request logging; email queries and message IDs can be sensitive.
