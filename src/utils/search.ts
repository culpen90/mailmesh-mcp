import type { SearchFilters } from "../types";
import { base64UrlEncodeBytes } from "./base64";

export async function searchFingerprint(
  filters: SearchFilters,
  accountIds: string[],
  limit: number,
): Promise<string> {
  const canonical = JSON.stringify({
    accountIds,
    limit,
    query: filters.query ?? null,
    mailbox: filters.mailbox ?? null,
    from: filters.from ?? null,
    to: filters.to ?? null,
    after: filters.after ?? null,
    before: filters.before ?? null,
    unreadOnly: filters.unreadOnly ?? null,
    hasAttachments: filters.hasAttachments ?? null,
    includeScheduled: filters.includeScheduled ?? false,
  });
  const bytes = new TextEncoder().encode(canonical);
  return base64UrlEncodeBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}
