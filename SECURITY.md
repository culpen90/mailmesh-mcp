# Security policy

MailMesh grants access to private email. Treat a deployed instance like a password manager or mail client backend.

## Supported version

Only the latest version on the default branch is supported.

## Reporting a vulnerability

Do not include mailbox contents, bearer tokens, OAuth credentials, IMAP passwords, D1 exports, or encryption keys in a public issue. Report the minimum reproduction details privately to the repository owner.

## Deployment checklist

- Keep `MAILMESH_TOKEN`, `TOKEN_ENCRYPTION_KEY`, and provider client secrets in Cloudflare Worker secrets.
- Keep the MCP OAuth dynamic-registration callback allowlist, body cap, and shared registration/consent rate limit intact; public OAuth setup consumes KV writes.
- Preserve PKCE S256, exact `/mcp` resource audience checks, one-use consent state, and the static-token approval step when changing MCP OAuth.
- Never commit `.dev.vars`; it is ignored by Git.
- Use HTTPS for every deployed callback and MCP request.
- Restrict Cloudflare account access with multi-factor authentication.
- Prefer OAuth or IMAP app passwords over a primary mailbox password.
- Leave `WRITE_MODE=read-only` unless drafts are explicitly required.
- Rotate the MailMesh token and provider credentials after any suspected disclosure.
- Reconnect ChatGPT and Claude after rotating the MailMesh token if you also revoke their OAuth grants in `OAUTH_KV`.
- Review Cloudflare logs before enabling detailed request logging; email queries and message IDs can be sensitive.
