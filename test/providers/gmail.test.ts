import { afterEach, describe, expect, it, vi } from "vitest";
import { GmailProvider } from "../../src/providers/gmail";
import type { EmailProvider, ProviderContext } from "../../src/types";
import { base64UrlToUtf8, utf8ToBase64Url } from "../../src/utils/base64";

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function providerContext(provider: EmailProvider = "gmail", maxMessageBytes = 1024): ProviderContext {
  return {
    env: {
      DB: {} as D1Database,
      OAUTH_KV: {} as KVNamespace,
      OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
      MAILMESH_TOKEN: "test-token",
      TOKEN_ENCRYPTION_KEY: "test-encryption-key",
      PUBLIC_BASE_URL: "https://mailmesh.test",
      GOOGLE_CLIENT_ID: "google-client",
      WRITE_MODE: "drafts",
    },
    account: {
      id: "gmail-1",
      provider,
      email: "owner@example.com",
      label: "Personal",
      encryptedCredentials: "encrypted",
      providerConfig: {},
      scopes: "https://www.googleapis.com/auth/gmail.modify",
      enabled: true,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      lastError: null,
    },
    credentials: {
      kind: "oauth",
      accessToken: "access-token",
      refreshToken: "refresh-token",
      expiresAt: Date.now() + 3_600_000,
      tokenType: "Bearer",
      scope: "https://www.googleapis.com/auth/gmail.modify",
    },
    maxMessageBytes,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GmailProvider", () => {
  it("searches a page and normalizes message metadata", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer access-token");
      if (url.includes("/messages?")) {
        return json({ messages: [{ id: "message-1" }], nextPageToken: "gmail-next" });
      }
      return json({
        id: "message-1",
        threadId: "thread-1",
        labelIds: ["INBOX", "UNREAD"],
        snippet: "A short preview",
        internalDate: "1767225600000",
        sizeEstimate: 321,
        payload: {
          headers: [
            { name: "Subject", value: "Status report" },
            { name: "From", value: "Ada <ada@example.com>" },
            { name: "To", value: "owner@example.com" },
            { name: "Date", value: "Thu, 1 Jan 2026 00:00:00 +0000" },
          ],
        },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await new GmailProvider(providerContext()).search({ query: "status" }, undefined, 10);

    expect(result.nextCursor).toBe("gmail-next");
    expect(result.messages).toEqual([
      expect.objectContaining({
        id: "message-1",
        threadId: "thread-1",
        provider: "gmail",
        accountId: "gmail-1",
        subject: "Status report",
        from: { name: "Ada", email: "ada@example.com" },
        isRead: false,
        hasAttachments: false,
      }),
    ]);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain("q=status");
  });

  it("caps decoded body bytes and returns attachment metadata without downloading attachments", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => json({
      id: "message-2",
      labelIds: ["INBOX"],
      internalDate: "1767225600000",
      payload: {
        headers: [{ name: "Subject", value: "Large message" }],
        parts: [
          {
            mimeType: "text/plain",
            headers: [{ name: "Content-Type", value: "text/plain; charset=UTF-8" }],
            body: { data: utf8ToBase64Url("hello world"), size: 11 },
          },
          {
            mimeType: "application/pdf",
            filename: "report.pdf",
            headers: [{ name: "Content-Disposition", value: "attachment" }],
            body: { attachmentId: "attachment-1", size: 4000 },
          },
        ],
      },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new GmailProvider(providerContext("gmail", 5)).getMessage("message-2");

    expect(result.bodyText).toBe("hello");
    expect(result.bodyTruncated).toBe(true);
    expect(result.warning).toContain("5 bytes");
    expect(result.attachments).toEqual([
      {
        id: "attachment-1",
        filename: "report.pdf",
        mimeType: "application/pdf",
        size: 4000,
        inline: false,
      },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("creates a draft through the drafts endpoint and never calls send", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toContain("/drafts");
      expect(String(input)).not.toContain("/send");
      expect(init?.method).toBe("POST");
      const payload = JSON.parse(String(init?.body)) as { message: { raw: string } };
      const source = base64UrlToUtf8(payload.message.raw);
      expect(source).toContain("To: recipient@example.com");
      expect(source).toContain("Subject: Safe draft");
      return json({ id: "draft-1" });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await new GmailProvider(providerContext()).createDraft({
      to: [{ email: "recipient@example.com" }],
      subject: "Safe draft",
      bodyText: "This stays a draft.",
    });

    expect(result).toEqual({ id: "draft-1", accountId: "gmail-1", provider: "gmail", status: "draft" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
