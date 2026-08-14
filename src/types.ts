import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export type EmailProvider = "gmail" | "microsoft" | "imap";

export interface Env {
  DB: D1Database;
  OAUTH_KV: KVNamespace;
  OAUTH_FLOW_RATE_LIMITER: RateLimit;
  AUTH_RATE_LIMITER?: RateLimit;
  OAUTH_PROVIDER?: OAuthHelpers;
  MAILMESH_TOKEN: string;
  TOKEN_ENCRYPTION_KEY: string;
  PUBLIC_BASE_URL: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  MICROSOFT_CLIENT_ID?: string;
  MICROSOFT_CLIENT_SECRET?: string;
  WRITE_MODE?: "read-only" | "drafts";
  MAX_ACCOUNTS_PER_QUERY?: string;
  MAX_RESULTS_PER_QUERY?: string;
  MAX_MESSAGE_BYTES?: string;
}

export interface AccountRecord {
  id: string;
  userId: string;
  provider: EmailProvider;
  email: string;
  label: string;
  encryptedCredentials: string;
  providerConfig: Record<string, unknown>;
  scopes: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastError: string | null;
}

export interface PublicAccount {
  id: string;
  provider: EmailProvider;
  email: string;
  label: string;
  enabled: boolean;
  scopes: string[];
  createdAt: string;
  updatedAt: string;
  lastError: string | null;
}

export interface OAuthCredentials {
  kind: "oauth";
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  tokenType: string;
  scope: string;
}

export interface ImapCredentials {
  kind: "imap";
  username: string;
  password: string;
}

export type StoredCredentials = OAuthCredentials | ImapCredentials;

export interface ImapProviderConfig {
  host: string;
  port: number;
  tls: true;
  defaultMailbox: string;
}

export interface EmailAddress {
  name?: string;
  email: string;
}

export interface EmailAttachment {
  id?: string;
  filename: string;
  mimeType: string;
  size?: number;
  inline: boolean;
}

export interface Mailbox {
  id: string;
  name: string;
  type?: string;
  unreadCount?: number;
  totalCount?: number;
}

export interface MessageSummary {
  id: string;
  threadId?: string;
  accountId: string;
  accountEmail: string;
  accountLabel: string;
  provider: EmailProvider;
  mailboxIds: string[];
  subject: string;
  from: EmailAddress | null;
  to: EmailAddress[];
  cc: EmailAddress[];
  receivedAt: string;
  sentAt?: string;
  isRead: boolean;
  hasAttachments: boolean;
  snippet: string;
  size?: number;
  webUrl?: string;
}

export interface MessageDetail extends MessageSummary {
  bcc: EmailAddress[];
  replyTo: EmailAddress[];
  messageId?: string;
  inReplyTo?: string;
  bodyText: string;
  bodyHtml?: string;
  bodyTruncated: boolean;
  attachments: EmailAttachment[];
  warning: string;
}

export interface SearchFilters {
  query?: string;
  mailbox?: string;
  from?: string;
  to?: string;
  after?: string;
  before?: string;
  unreadOnly?: boolean;
  hasAttachments?: boolean;
  includeScheduled?: boolean;
}

export interface ProviderSearchPage {
  messages: MessageSummary[];
  nextCursor?: string;
}

export interface UnifiedSearchCursor {
  v: 2;
  userId: string;
  fingerprint: string;
  accounts: Record<string, string | null>;
}

export interface UserRecord {
  id: string;
  username: string;
  displayName: string;
  passwordAlgorithm: string;
  passwordHash: string;
  passwordSalt: string;
  passwordIterations: number;
  authVersion: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface PublicUser {
  id: string;
  username: string;
  displayName: string;
  enabled: boolean;
  passwordConfigured: boolean;
  authVersion: number;
  createdAt: string;
  updatedAt: string;
}

export interface AdminAccount extends PublicAccount {
  userId: string;
}

export interface DraftInput {
  to: EmailAddress[];
  cc?: EmailAddress[];
  bcc?: EmailAddress[];
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  replyToMessageId?: string;
}

export interface DraftResult {
  id: string;
  accountId: string;
  provider: EmailProvider;
  status: "draft";
  webUrl?: string;
}

export interface ProviderAdapter {
  listMailboxes(): Promise<Mailbox[]>;
  search(filters: SearchFilters, cursor: string | undefined, limit: number): Promise<ProviderSearchPage>;
  getMessage(messageId: string): Promise<MessageDetail>;
  createDraft?(input: DraftInput): Promise<DraftResult>;
}

export interface ProviderContext {
  env: Env;
  account: AccountRecord;
  credentials: StoredCredentials;
  maxMessageBytes: number;
}

export interface ToolErrorShape {
  error: {
    code: string;
    message: string;
    retryable: boolean;
    accountId?: string;
    provider?: EmailProvider;
  };
}
