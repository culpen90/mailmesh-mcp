# MailMesh MCP

MailMesh is a private MCP server for Cloudflare Workers. Each deployment has one workspace with shared access to its linked Gmail, Microsoft 365/Outlook, and IMAP mailboxes.

MailMesh queries each provider live and does not store mailbox contents. If draft creation is enabled for Gmail or Microsoft, review and send the draft in your mail app.

## MCP tools

- `list_email_accounts` — list linked accounts without exposing credentials
- `list_email_mailboxes` — list Gmail labels, Outlook folders, and IMAP mailboxes
- `search_email` — search selected or all accounts and merge results by date. Set `include_scheduled` to include pending Gmail scheduled sends.
- `get_email` — retrieve one size-capped message and attachment metadata
- `create_email_draft` — optional; creates a draft but never sends it

All email text is labeled as untrusted external content. Provider credentials are AES-GCM encrypted before being written to D1. Operators use the deployment's `MAILMESH_TOKEN` for mailbox management, direct MCP access, and approving OAuth connections. ChatGPT and Claude use separate OAuth 2.1 tokens issued through PKCE.

Each approved MCP client can access every enabled mailbox linked to the workspace, including mailboxes linked after approval. Anyone who can use the client's saved connection can exercise that access.

## Workers Free design

The Worker is stateless and uses Cloudflare's Streamable HTTP MCP handler. D1 stores linked-account configuration, encrypted provider credentials, and workspace authorization state. Workers KV stores OAuth client and grant metadata and hashes of codes and tokens. Search is live and paginated, accounts are queried sequentially, message bodies are capped, and attachments are excluded. Public OAuth setup is rate-limited. Capacity depends on activity and is subject to the [Workers](https://developers.cloudflare.com/workers/platform/limits/), [D1](https://developers.cloudflare.com/d1/platform/pricing/), and [Workers KV](https://developers.cloudflare.com/kv/platform/pricing/) allocations.

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
- Link a mailbox: `http://localhost:8787/connect`
- Operator administration: `http://localhost:8787/admin/*`

Operator requests use this header:

```text
Authorization: Bearer YOUR_MAILMESH_TOKEN
```

## Link email accounts

### Generic IMAP

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

Open the returned `authorizationUrl` in a browser and approve access. The callback stores the tokens encrypted and confirms that the account was linked.

### Connect Gmail or Microsoft from any computer

Open this page on the computer where you want to sign in to your email provider:

`https://mailmesh-mcp.culpen0-workers.workers.dev/connect`

Enter the deployment's `MAILMESH_TOKEN`, optionally add a label, and choose Google or Microsoft. The page sends the token in an authorization header to the MailMesh Worker over HTTPS and clears the token field. Complete the provider's consent flow to link the mailbox to this deployment.

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

List, relabel, or remove linked accounts:

```bash
curl -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  http://localhost:8787/admin/accounts

curl -X PATCH \
  -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"label":"Personal Gmail"}' \
  http://localhost:8787/admin/accounts/ACCOUNT_ID

curl -X DELETE -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  http://localhost:8787/admin/accounts/ACCOUNT_ID
```

## Manage OAuth connections

Use the operator token to list or revoke workspace connections:

```bash
curl -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  http://localhost:8787/admin/mcp-connections

# Disconnect one listed OAuth grant.
curl -X DELETE -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  http://localhost:8787/admin/mcp-connections/CONNECTION_ID

# Invalidate all existing OAuth grants for this deployment.
curl -X DELETE -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  http://localhost:8787/admin/mcp-connections
```

Deleting one connection records its revocation in D1 before best-effort KV cleanup. Deleting the collection increments the workspace's authorization version, invalidating all earlier grants. MCP requests and token refreshes enforce both controls. Rotate the Worker secret to invalidate direct access via `MAILMESH_TOKEN`. Email already returned may persist in client conversations.

## Deploy to Cloudflare Workers

### Create a deployment

Sign in to Cloudflare, create the D1 database and OAuth KV namespace, and apply the D1 migrations:

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

For a new deployment, verify and deploy normally:

```bash
npm run check
npm run deploy
```

### Upgrade an existing deployment

`0004_workspace.sql` preserves the former reserved owner's linked mailboxes, including account IDs, encrypted credentials, and metadata. It removes the previous MailMesh users and their password records. The migration stops if anyone other than the reserved owner still has a linked mailbox, including a disabled mailbox, or if the reserved owner is disabled and still has linked mailboxes.

If the migration stops, review the affected mailboxes while the old Worker is active. Unlink any mailboxes that should stay outside the workspace before retrying. The old release supports `DELETE /api/accounts/ACCOUNT_ID` with the mailbox owner's Basic credentials, and the reserved owner's mailboxes can be managed through `/admin/accounts`. To move an approved mailbox to the workspace, explicitly arrange its relinking through the old deployment or have the provider's account holder link it after the cutover.

The schema and Worker must be cut over together. Verify the new Worker and upload it without serving it. During a maintenance window, pause mailbox changes, record a D1 Time Travel restore point, apply the migration, and route all traffic to the new version once the migration succeeds:

```bash
npm run check
npx wrangler versions upload \
  --tag workspace-cutover \
  --message "Workspace schema cutover"

# During the maintenance window:
npx wrangler d1 time-travel info mailmesh --json
npx wrangler d1 migrations apply mailmesh --remote &&
npx wrangler versions deploy \
  --version-tag workspace-cutover \
  --percentage 100 \
  --message "Activate workspace schema" \
  --yes
```

After activation, restart any pending Gmail or Microsoft link flow, reconnect each OAuth MCP client, and restart any search using a previous pagination cursor. Restore the matching D1 point before routing traffic back to the previous Worker.

The deployed MCP URL is `https://mailmesh-mcp.culpen0-workers.workers.dev/mcp`.

## Connect an LLM client

Use this remote MCP URL in ChatGPT or Claude:

`https://mailmesh-mcp.culpen0-workers.workers.dev/mcp`

Choose OAuth if the client asks for an authentication method. The client registers itself, opens the MailMesh consent page, and uses PKCE. Enter the deployment's `MAILMESH_TOKEN` on the MailMesh page, review the access disclosure, acknowledge it, and approve. The client receives a separate one-hour OAuth access token and a rotating refresh token.

MailMesh's dynamic-registration policy accepts the official hosted callback origins and paths used by ChatGPT/OpenAI and Claude.

Operators can use direct access with a trusted client that supports remote MCP and custom headers. Configure the Worker URL and an `Authorization: Bearer ...` header.

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

You can also connect to the local or remote `/mcp` URL using the operator header in [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

With a local or deployed Worker running, perform a non-destructive protocol smoke test:

```bash
export MAILMESH_TOKEN="YOUR_MAILMESH_TOKEN"
npm run smoke -- http://localhost:8787/mcp
unset MAILMESH_TOKEN
```

Run the OAuth smoke test against a test deployment to check discovery, registration, PKCE, consent, both MCP authentication modes, access to operator routes, refresh rotation, and targeted revocation:

```bash
export MAILMESH_TOKEN="YOUR_MAILMESH_TOKEN"
npm run oauth-smoke -- http://localhost:8787
unset MAILMESH_TOKEN
```

This initializes a real Streamable HTTP MCP client, lists the tools, and invokes `list_email_accounts`.

## Configuration

| Binding or variable | Required | Purpose |
| --- | --- | --- |
| `DB` | yes | D1 binding for encrypted account records, provider OAuth state, and MCP grant revocation |
| `OAUTH_KV` | yes | KV binding for MCP OAuth client registrations, grants, and token hashes |
| `OAUTH_FLOW_RATE_LIMITER` | yes | Per-operation and connecting-address limit protecting unauthenticated OAuth setup writes |
| `MAILMESH_TOKEN` | yes | Operator bearer for the workspace, stored as a Worker secret |
| `TOKEN_ENCRYPTION_KEY` | yes | Base64-encoded 32-byte AES key for provider credentials, stored as a Worker secret |
| `PUBLIC_BASE_URL` | yes | Exact origin for MCP OAuth and provider redirect URIs |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Gmail only | Google OAuth web client |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` | Microsoft only | Microsoft OAuth web client |
| `WRITE_MODE` | no | `read-only` by default; set to `drafts` to expose draft creation |
| `MAX_ACCOUNTS_PER_QUERY` | no | Defaults to 10, capped at 20 |
| `MAX_RESULTS_PER_QUERY` | no | Defaults to 30, capped at 50 |
| `MAX_MESSAGE_BYTES` | no | Defaults to 262,144 bytes, capped at 1 MiB |

Switching `WRITE_MODE` from `read-only` to `drafts` changes the provider scopes and MCP grant capabilities. Re-link Gmail and Microsoft accounts, then reconnect each OAuth MCP client after changing it. MailMesh does not expose a send tool in either mode.

## Security notes

- `MAILMESH_TOKEN` grants full operator access to the workspace. Use a long random value, send it only in an authorization header, and rotate it if exposed. Keep it in operator-controlled clients.
- Losing `TOKEN_ENCRYPTION_KEY` makes stored provider credentials unrecoverable. Leaking the key with D1 exposes those credentials. Rotation requires relinking the provider accounts. Back the key up in a password manager.
- Gmail/Microsoft and MCP consent state is single-use and expires after ten minutes. When approving an MCP connection, the operator acknowledges that the whole client account can use it. The acknowledgment version and time are recorded with the grant. KV stores MCP OAuth access tokens, refresh tokens, authorization codes, and client secrets as hashes. The OAuth provider encrypts the grant props.
- MCP OAuth uses authorization code flow with PKCE S256, an exact `/mcp` resource audience, one-hour access tokens, and 30-day rotating refresh tokens. Registered ChatGPT and Claude clients do not silently expire.
- Cloudflare limits dynamic registration, consent creation, and consent approval to ten requests per minute for each operation and connecting address. Registration bodies are capped at 16 KiB, and redirect URIs are pinned to official HTTPS origins and supported paths.
- MCP OAuth tokens require `mail:read` and are scoped to `/mcp`. Draft creation additionally requires an enabled linked mailbox, the provider compose scope, and an OAuth grant approved in draft mode or the operator bearer.
- IMAP passwords are more sensitive than scoped OAuth tokens. Prefer app passwords and revoke them when removing MailMesh.
- Message bodies and attachments are not stored. Attachment content is not exposed to the LLM.
- The server creates no drafts unless the deployment mode, MCP grant, and linked provider account all allow it. It never sends, deletes, moves, or marks messages read.
