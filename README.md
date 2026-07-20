# MailMesh MCP

MailMesh is a private, single-user MCP server for Cloudflare Workers. It links multiple Gmail, Microsoft 365/Outlook, and IMAP mailboxes and gives an LLM one normalized set of email tools.

It queries each provider live. It does not copy, index, train on, or cache mailbox contents. Sending is deliberately unsupported; draft creation can be enabled for Gmail and Microsoft accounts, and the user still has to review and send the draft in their mail app.

## MCP tools

- `list_email_accounts` — list linked accounts without exposing credentials
- `list_email_mailboxes` — list Gmail labels, Outlook folders, and IMAP mailboxes
- `search_email` — search selected or all accounts and merge results by date; pending Gmail scheduled sends are excluded unless `include_scheduled` is true
- `get_email` — retrieve one size-capped message and attachment metadata
- `create_email_draft` — optional; creates a draft but never sends it

All email text is labeled as untrusted external content. Provider credentials are AES-GCM encrypted before being written to D1. ChatGPT and Claude connect through OAuth 2.1 with PKCE; the private `MAILMESH_TOKEN` remains the owner credential for approving OAuth consent and using the account-management API.

## Why this fits Workers Free

The Worker is stateless and uses Cloudflare's current Streamable HTTP MCP handler. D1 stores only linked-account configuration and encrypted credentials. Workers KV stores OAuth client/grant metadata and hashes of codes and tokens; it does not contain mailbox content or recoverable OAuth secrets. Search is live and paginated, accounts are queried sequentially, message bodies are capped, and attachments are not downloaded. OAuth setup writes are body-capped and rate-limited. The one-user workload fits the free allocations for [Workers](https://developers.cloudflare.com/workers/platform/limits/), [D1](https://developers.cloudflare.com/d1/platform/pricing/), and [Workers KV](https://developers.cloudflare.com/kv/platform/pricing/).

## Local setup

Requirements: Node.js 20 or newer and a free Cloudflare account.

```bash
npm install
cp .dev.vars.example .dev.vars
```

Generate the two required secrets and paste them into `.dev.vars`:

```bash
openssl rand -hex 32
openssl rand -base64 32
```

- The hex value becomes `MAILMESH_TOKEN`.
- The base64 value becomes `TOKEN_ENCRYPTION_KEY`. It must decode to exactly 32 bytes.

Initialize the local D1 database and start the Worker:

```bash
npm run db:local
npm run dev
```

The local endpoints are:

- MCP: `http://localhost:8787/mcp`
- OAuth authorization: `http://localhost:8787/authorize`
- OAuth token and registration: `http://localhost:8787/token` and `http://localhost:8787/register`
- Health: `http://localhost:8787/health`
- Account management: `http://localhost:8787/admin/*`

Every private request uses this header:

```text
Authorization: Bearer YOUR_MAILMESH_TOKEN
```

## Link email accounts

### Generic IMAP, including hosted email services

Use the exact IMAP hostname your email provider supplies. TLS on port 993 is required.

```bash
curl -X POST http://localhost:8787/admin/accounts/imap \
  -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "label": "Work mail",
    "email": "you@example.com",
    "host": "imap.example.com",
    "port": 993,
    "username": "you@example.com",
    "password": "APP_PASSWORD_OR_MAIL_PASSWORD",
    "defaultMailbox": "INBOX"
  }'
```

Prefer a provider-issued app password. If a provider requires weakening multi-factor authentication to enable IMAP, do not do that just for MailMesh; use Gmail or Microsoft OAuth instead when available.

### Gmail OAuth

1. In Google Cloud, enable the Gmail API and create an OAuth 2.0 Web application client.
2. Add `https://mailmesh-mcp.culpen0-workers.workers.dev/oauth/callback/gmail` as an authorized redirect URI. For local-only testing, also add `http://localhost:8787/oauth/callback/gmail`.
3. Put `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.dev.vars` locally or Worker secrets in production.
4. Ask MailMesh for a one-time authorization URL:

```bash
curl -X POST http://localhost:8787/admin/oauth/start \
  -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"provider":"gmail","label":"Personal Gmail"}'
```

Open the returned `authorizationUrl` in a browser and approve access. The callback stores the tokens encrypted and shows the linked address.

### Connect Gmail from any computer

Open this permanent page on the computer where you want to sign into Google:

`https://mailmesh-mcp.culpen0-workers.workers.dev/connect`

Paste the private `MAILMESH_TOKEN`, optionally add a label, and choose **Continue with Google**. The page sends the token only in an authorization header to the MailMesh Worker over HTTPS, clears the field, does not place it in the URL, and does not save it in browser storage.

On the original Mac, this copies the token from Keychain without printing it:

```bash
security find-generic-password -s "MailMesh MCP bearer token" -w | pbcopy
```

Move the token to your other computer through a password manager or another private transfer method. Do not send it by email or include it in a URL. The same page can be reused for every additional Gmail account.

### Microsoft 365 or Outlook OAuth

1. Register a Web application in Microsoft Entra ID and choose the account types you intend to use.
2. Add `https://mailmesh-mcp.culpen0-workers.workers.dev/oauth/callback/microsoft` as a redirect URI. For local-only testing, also add `http://localhost:8787/oauth/callback/microsoft`.
3. Put `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET` in `.dev.vars` or Worker secrets.
4. Start the link flow:

```bash
curl -X POST http://localhost:8787/admin/oauth/start \
  -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"provider":"microsoft","label":"Microsoft mail"}'
```

Open the returned `authorizationUrl` and complete consent.

List or remove linked accounts:

```bash
curl -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  http://localhost:8787/admin/accounts

curl -X DELETE -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  http://localhost:8787/admin/accounts/ACCOUNT_ID
```

## Deploy to Cloudflare Workers

Log in, create the free D1 database and OAuth KV namespace, and apply the D1 migration:

```bash
npx wrangler login
npx wrangler d1 create mailmesh --binding DB --update-config
npx wrangler kv namespace create mailmesh-oauth --binding OAUTH_KV --update-config
npm run db:remote
```

Before deploying, change `PUBLIC_BASE_URL` in `wrangler.jsonc` to the final HTTPS Worker or custom-domain origin. Then add the required production secrets:

```bash
npx wrangler secret put MAILMESH_TOKEN
npx wrangler secret put TOKEN_ENCRYPTION_KEY
```

Add only the provider credentials you need:

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put MICROSOFT_CLIENT_ID
npx wrangler secret put MICROSOFT_CLIENT_SECRET
```

Verify and deploy:

```bash
npm run check
npm run deploy
```

The deployed MCP URL is `https://mailmesh-mcp.culpen0-workers.workers.dev/mcp`.

## Connect an LLM client

Use this remote MCP URL in ChatGPT or Claude:

`https://mailmesh-mcp.culpen0-workers.workers.dev/mcp`

Choose OAuth if the client asks for an authentication method. The client registers itself, opens the MailMesh consent page, and uses PKCE. Paste the private `MAILMESH_TOKEN` into that MailMesh page and approve read-only access. The token is sent only to your Worker in an authorization header; ChatGPT or Claude receives separate one-hour OAuth access tokens and a rotating refresh token.

MailMesh's dynamic-registration policy accepts the official hosted callback domains used by ChatGPT/OpenAI and Claude. Other clients can continue using the private static bearer header.

For a client with native remote MCP and custom-header support, configure the Worker URL and an `Authorization: Bearer ...` header.

For stdio-only clients, use the current [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) adapter:

```json
{
  "mcpServers": {
    "mailmesh": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mailmesh-mcp.culpen0-workers.workers.dev/mcp",
        "--header",
        "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer YOUR_MAILMESH_TOKEN"
      }
    }
  }
}
```

You can also connect the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) to the local or remote `/mcp` URL and add the same authorization header.

With a local or deployed Worker running, perform a non-destructive protocol smoke test:

```bash
export MAILMESH_TOKEN="YOUR_MAILMESH_TOKEN"
npm run smoke -- http://localhost:8787/mcp
unset MAILMESH_TOKEN
```

To exercise discovery, dynamic registration, PKCE, consent, token exchange, both MCP authentication modes, the admin boundary, and refresh rotation against a test deployment:

```bash
export MAILMESH_TOKEN="YOUR_MAILMESH_TOKEN"
npm run oauth-smoke -- http://localhost:8787
unset MAILMESH_TOKEN
```

This initializes a real Streamable HTTP MCP client, lists the tools, and invokes `list_email_accounts`.

## Configuration

| Binding or variable | Required | Purpose |
| --- | --- | --- |
| `DB` | yes | D1 binding for encrypted account records and short-lived OAuth state |
| `OAUTH_KV` | yes | KV binding for MCP OAuth client registrations, grants, and token hashes |
| `OAUTH_FLOW_RATE_LIMITER` | yes | Workers rate-limit binding protecting unauthenticated OAuth setup writes |
| `MAILMESH_TOKEN` | yes | Single-user bearer token; store as a Worker secret |
| `TOKEN_ENCRYPTION_KEY` | yes | Base64-encoded 32-byte AES key; store as a Worker secret |
| `PUBLIC_BASE_URL` | OAuth only | Exact public origin used in provider redirect URIs |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Gmail only | Google OAuth web client |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` | Microsoft only | Microsoft OAuth web client |
| `WRITE_MODE` | no | `read-only` by default; set to `drafts` to expose draft creation |
| `MAX_ACCOUNTS_PER_QUERY` | no | Defaults to 10, capped at 20 |
| `MAX_RESULTS_PER_QUERY` | no | Defaults to 30, capped at 50 |
| `MAX_MESSAGE_BYTES` | no | Defaults to 262,144 bytes, capped at 1 MiB |

Switching `WRITE_MODE` from `read-only` to `drafts` changes the OAuth scopes. Re-link Gmail and Microsoft accounts after changing it. MailMesh does not expose a send tool in either mode.

## Security notes

- Anyone with `MAILMESH_TOKEN` can approve a client or read every linked mailbox. Use a long random value, never put it in a URL, and rotate it if exposed.
- Losing `TOKEN_ENCRYPTION_KEY` makes stored account credentials unrecoverable. Leaking it together with the D1 database exposes them. Back it up in a password manager.
- Gmail/Microsoft and MCP consent state is single-use and expires after ten minutes. MCP OAuth access tokens, refresh tokens, authorization codes, and client secrets are stored in KV only as hashes; grant props are encrypted by the OAuth provider.
- MCP OAuth uses authorization code flow with PKCE S256, an exact `/mcp` resource audience, one-hour access tokens, and 30-day rotating refresh tokens. Registered ChatGPT and Claude clients do not silently expire.
- Dynamic registration and consent creation share a ten-request-per-minute Cloudflare rate limit and registration bodies are capped at 16 KiB.
- MCP OAuth tokens have only `mail:read` access and cannot use `/admin`, add/remove accounts, or start a Gmail connection. The server remains deployed with `WRITE_MODE=read-only`.
- IMAP passwords are more sensitive than scoped OAuth tokens. Prefer app passwords and revoke them when removing MailMesh.
- Message bodies and attachments are not stored. Attachment content is not exposed to the LLM.
- The server creates no drafts unless `WRITE_MODE=drafts`, and it never sends, deletes, moves, or marks messages read.
