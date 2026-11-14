import { decryptCredentials } from "./crypto";
import { getAccount, listAccounts, toPublicAccount } from "./db";
import { asMailMeshError, MailMeshError } from "./errors";
import { GmailProvider } from "./providers/gmail";
import { ImapProvider } from "./providers/imap";
import { MicrosoftProvider } from "./providers/microsoft";
import type {
  AccountRecord,
  DraftInput,
  DraftResult,
  Env,
  Mailbox,
  MessageDetail,
  MessageSummary,
  ProviderAdapter,
  PublicAccount,
  SearchFilters,
  ToolErrorShape,
  UnifiedSearchCursor,
} from "./types";
import { decodeCursor, encodeCursor } from "./utils/cursor";
import { positiveInteger } from "./utils/limits";
import { searchFingerprint } from "./utils/search";

export interface AccountMailboxResult {
  account: PublicAccount;
  mailboxes: Mailbox[];
}

export interface PartialAccountError extends ToolErrorShape {
  error: ToolErrorShape["error"] & { accountId: string };
}

export interface UnifiedSearchResult {
  messages: MessageSummary[];
  nextCursor?: string;
  errors: PartialAccountError[];
  searchedAccountIds: string[];
  requestedLimit: number;
  appliedLimit: number;
}

export interface ListMailboxesResult {
  accounts: AccountMailboxResult[];
  errors: PartialAccountError[];
}

function validateSearchDates(filters: SearchFilters): void {
  const after = filters.after ? new Date(filters.after) : null;
  const before = filters.before ? new Date(filters.before) : null;
  if (after && Number.isNaN(after.getTime())) {
    throw new MailMeshError("invalid_search", "after must be a valid ISO 8601 date or date-time", 400);
  }
  if (before && Number.isNaN(before.getTime())) {
    throw new MailMeshError("invalid_search", "before must be a valid ISO 8601 date or date-time", 400);
  }
  if (after && before && after.getTime() >= before.getTime()) {
    throw new MailMeshError("invalid_search", "after must be earlier than before", 400);
  }
}

function errorForAccount(error: unknown, account: AccountRecord): PartialAccountError {
  const normalized = asMailMeshError(error);
  return {
    error: {
      ...normalized.toToolError().error,
      accountId: account.id,
      provider: account.provider,
    },
  };
}

export class MailService {
  constructor(private readonly env: Env) {}

  async accounts(): Promise<PublicAccount[]> {
    return (await listAccounts(this.env.DB)).map(toPublicAccount);
  }

  private async selectedAccounts(accountIds?: string[]): Promise<AccountRecord[]> {
    const configured = await listAccounts(this.env.DB, true);
    const maximum = positiveInteger(this.env.MAX_ACCOUNTS_PER_QUERY, 10, 20);
    if (!accountIds?.length) {
      if (configured.length > maximum) {
        throw new MailMeshError(
          "too_many_accounts",
          `${configured.length} accounts are enabled; select account_ids or raise MAX_ACCOUNTS_PER_QUERY (maximum 20)`,
          400,
        );
      }
      return configured;
    }

    const uniqueIds = [...new Set(accountIds)];
    if (uniqueIds.length > maximum) {
      throw new MailMeshError(
        "too_many_accounts",
        `At most ${maximum} accounts can be queried in one call on the Workers free tier`,
        400,
      );
    }

    const byId = new Map(configured.map((account) => [account.id, account]));
    const missing = uniqueIds.filter((id) => !byId.has(id));
    if (missing.length) {
      throw new MailMeshError("account_not_found", `Unknown or disabled account: ${missing.join(", ")}`, 404);
    }
    return uniqueIds.map((id) => byId.get(id)).filter((account): account is AccountRecord => account !== undefined);
  }

  private async adapter(account: AccountRecord): Promise<ProviderAdapter> {
    const credentials = await decryptCredentials(account.encryptedCredentials, this.env.TOKEN_ENCRYPTION_KEY);
    const context = {
      env: this.env,
      account,
      credentials,
      maxMessageBytes: positiveInteger(this.env.MAX_MESSAGE_BYTES, 262_144, 1_048_576),
    };

    switch (account.provider) {
      case "gmail":
        return new GmailProvider(context);
      case "microsoft":
        return new MicrosoftProvider(context);
      case "imap":
        return new ImapProvider(context);
    }
  }

  async listMailboxes(accountIds?: string[]): Promise<ListMailboxesResult> {
    const accounts = await this.selectedAccounts(accountIds);
    const result: ListMailboxesResult = { accounts: [], errors: [] };

    // Sequential account access avoids exceeding the free plan's six simultaneous outgoing connections.
    for (const account of accounts) {
      try {
        result.accounts.push({ account: toPublicAccount(account), mailboxes: await (await this.adapter(account)).listMailboxes() });
      } catch (error) {
        result.errors.push(errorForAccount(error, account));
      }
    }
    return result;
  }

  async search(
    filters: SearchFilters,
    accountIds: string[] | undefined,
    requestedLimit: number,
    cursor?: string,
  ): Promise<UnifiedSearchResult> {
    validateSearchDates(filters);
    const accounts = await this.selectedAccounts(accountIds);
    const maximum = positiveInteger(this.env.MAX_RESULTS_PER_QUERY, 30, 50);
    const limit = Math.min(Math.max(1, Math.trunc(requestedLimit)), maximum);
    const fingerprint = await searchFingerprint(filters, accounts.map((account) => account.id), limit);
    let cursorState: UnifiedSearchCursor = { v: 3, fingerprint, accounts: {} };

    if (cursor) {
      cursorState = await decodeCursor<UnifiedSearchCursor>(cursor, this.env.TOKEN_ENCRYPTION_KEY);
      if (
        cursorState.v !== 3 ||
        cursorState.fingerprint !== fingerprint ||
        !cursorState.accounts ||
        typeof cursorState.accounts !== "object"
      ) {
        throw new MailMeshError("invalid_cursor", "The cursor does not match this search request", 400);
      }
    }

    const result: UnifiedSearchResult = {
      messages: [],
      errors: [],
      searchedAccountIds: accounts.map((account) => account.id),
      requestedLimit: limit,
      appliedLimit: limit,
    };
    if (!accounts.length) return result;

    const nextAccountCursors: Record<string, string | null> = {};
    const activeAccountCount = accounts.filter(
      (account) => !cursor || cursorState.accounts[account.id] !== null,
    ).length;
    if (activeAccountCount === 0) return result;
    // Always request at least one result from every active account. This can
    // raise a very small caller limit, but avoids silently skipping accounts or
    // advancing provider cursors past messages that were never returned.
    const appliedLimit = Math.max(limit, activeAccountCount);
    result.appliedLimit = appliedLimit;
    const baseAllocation = Math.floor(appliedLimit / activeAccountCount);
    let remainder = appliedLimit % activeAccountCount;

    // Provider calls are intentionally sequential. Gmail can fan out message-detail requests internally.
    for (const account of accounts) {
      const priorCursor = cursorState.accounts[account.id];
      if (cursor && priorCursor === null) continue;
      const accountLimit = Math.max(1, baseAllocation + (remainder-- > 0 ? 1 : 0));
      try {
        const page = await (await this.adapter(account)).search(
          filters,
          priorCursor ?? undefined,
          accountLimit,
        );
        result.messages.push(...page.messages);
        nextAccountCursors[account.id] = page.nextCursor ?? null;
      } catch (error) {
        result.errors.push(errorForAccount(error, account));
        if (typeof priorCursor === "string" && priorCursor) nextAccountCursors[account.id] = priorCursor;
      }
    }

    result.messages.sort((left, right) => Date.parse(right.receivedAt) - Date.parse(left.receivedAt));
    result.messages = result.messages.slice(0, appliedLimit);
    if (Object.values(nextAccountCursors).some((value) => value !== null)) {
      result.nextCursor = await encodeCursor(
        { v: 3, fingerprint, accounts: nextAccountCursors },
        this.env.TOKEN_ENCRYPTION_KEY,
      );
    }
    return result;
  }

  async getMessage(accountId: string, messageId: string): Promise<MessageDetail> {
    const account = await getAccount(this.env.DB, accountId);
    if (!account?.enabled) throw new MailMeshError("account_not_found", "The email account was not found or is disabled", 404);
    return (await this.adapter(account)).getMessage(messageId);
  }

  async createDraft(accountId: string, input: DraftInput): Promise<DraftResult> {
    if (this.env.WRITE_MODE !== "drafts") {
      throw new MailMeshError(
        "writes_disabled",
        "Draft creation is disabled. Set WRITE_MODE=drafts and reconnect the OAuth account with write scope.",
        403,
      );
    }
    const account = await getAccount(this.env.DB, accountId);
    if (!account?.enabled) throw new MailMeshError("account_not_found", "The email account was not found or is disabled", 404);
    const adapter = await this.adapter(account);
    if (!adapter.createDraft) {
      throw new MailMeshError("drafts_unsupported", `${account.provider} draft creation is not supported`, 400);
    }
    return adapter.createDraft(input);
  }
}
