import { afterEach, describe, expect, it, vi } from "vitest";
import { MicrosoftProvider } from "../../src/providers/microsoft";
import type { ProviderContext } from "../../src/types";

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function providerContext(maxMessageBytes = 1024): ProviderContext {
  return {
    env: {
      DB: {} as D1Database,
      OAUTH_KV: {} as KVNamespace,
      OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
      MAILMESH_TOKEN: "test-token",
      TOKEN_ENCRYPTION_KEY: "test-encryption-key",
      PUBLIC_BASE_URL: "https://mailmesh.test",
      MICROSOFT_CLIENT_ID: "microsoft-client",
      WRITE_MODE: "drafts",
    },
    account: {
      id: "microsoft-1",
      provider: "microsoft",
      email: "owner@example.com",
      label: "Work",
      encryptedCredentials: "encrypted",
      providerConfig: { tenantId: "organizations" },
      scopes: "Mail.ReadWrite offline_access",
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
      scope: "Mail.ReadWrite offline_access",
    },
    maxMessageBytes,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("MicrosoftProvider", () => {
  it("searches messages, preserves a provider cursor, and normalizes metadata", async () => {
    const nextLink = "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=opaque";
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      expect(url).toContain("%24search");
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer access-token");
      expect(new Headers(init?.headers).get("prefer")).toBe('IdType="ImmutableId"');
      expect(new Headers(init?.headers).get("consistencylevel")).toBe("eventual");
      return json({
        value: [{
          id: "message-1",
          conversationId: "conversation-1",
          parentFolderId: "inbox-id",
          subject: "Quarterly status",
          from: { emailAddress: { name: "Ada", address: "ada@example.com" } },
          toRecipients: [{ emailAddress: { address: "owner@example.com" } }],
          receivedDateTime: "2026-01-01T12:00:00Z",
          isRead: true,
          hasAttachments: true,
          bodyPreview: "Preview",
          size: 500,
          webLink: "https://outlook.office.com/mail/message-1",
        }],
        "@odata.nextLink": nextLink,
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await new MicrosoftProvider(providerContext()).search({ query: "quarterly" }, undefined, 10);

    expect(result.nextCursor).toBe(nextLink);
    expect(result.messages).toEqual([
      expect.objectContaining({
        id: "message-1",
        threadId: "conversation-1",
        provider: "microsoft",
        mailboxIds: ["inbox-id"],
        from: { name: "Ada", email: "ada@example.com" },
        subject: "Quarterly status",
        isRead: true,
        hasAttachments: true,
      }),
    ]);
  });

  it("rejects an untrusted pagination URL before making a request", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      new MicrosoftProvider(providerContext()).search({}, "https://attacker.example/v1.0/me/messages", 10),
    ).rejects.toMatchObject({ code: "invalid_cursor", status: 400 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("walks nested mail folders within a bounded number of Graph calls", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/childFolders")) {
        return json({ value: [{ id: "child-id", displayName: "Project", childFolderCount: 0 }] });
      }
      return json({
        value: [{
          id: "inbox-id",
          displayName: "Inbox",
          unreadItemCount: 2,
          totalItemCount: 9,
          childFolderCount: 1,
        }],
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await new MicrosoftProvider(providerContext()).listMailboxes();

    expect(result).toEqual([
      { id: "inbox-id", name: "Inbox", unreadCount: 2, totalCount: 9 },
      { id: "child-id", name: "Project" },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("caps the message body and fetches attachment metadata only", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/attachments")) {
        return json({ value: [{ id: "attachment-1", name: "report.pdf", contentType: "application/pdf", size: 3000 }] });
      }
      return json({
        id: "message-2",
        subject: "Large message",
        receivedDateTime: "2026-01-01T00:00:00Z",
        body: { contentType: "html", content: "<p>Hello world</p>" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await new MicrosoftProvider(providerContext(12)).getMessage("message-2");

    expect(result.bodyHtml).toBe("<p>Hello wor");
    expect(result.bodyText).toBe("Hello wor");
    expect(result.bodyTruncated).toBe(true);
    expect(result.attachments).toEqual([
      {
        id: "attachment-1",
        filename: "report.pdf",
        mimeType: "application/pdf",
        size: 3000,
        inline: false,
      },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("creates and patches a reply draft without calling a send endpoint", async () => {
    const calls: Array<{ url: string; method: string }> = [];
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      calls.push({ url: String(input), method: init?.method ?? "GET" });
      if (String(input).endsWith("/createReply")) return json({ id: "draft-2" });
      const body = JSON.parse(String(init?.body)) as { toRecipients: unknown[]; body: { content: string } };
      expect(body.toRecipients).toHaveLength(1);
      expect(body.body.content).toBe("This remains a draft.");
      return json({ id: "draft-2", webLink: "https://outlook.office.com/mail/draft-2" });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await new MicrosoftProvider(providerContext()).createDraft({
      to: [{ email: "recipient@example.com" }],
      subject: "Re: Safe reply",
      bodyText: "This remains a draft.",
      replyToMessageId: "message-2",
    });

    expect(result).toEqual({
      id: "draft-2",
      accountId: "microsoft-1",
      provider: "microsoft",
      status: "draft",
      webUrl: "https://outlook.office.com/mail/draft-2",
    });
    expect(calls).toEqual([
      { url: "https://graph.microsoft.com/v1.0/me/messages/message-2/createReply", method: "POST" },
      { url: "https://graph.microsoft.com/v1.0/me/messages/draft-2", method: "PATCH" },
    ]);
    expect(calls.every(({ url }) => !url.endsWith("/send"))).toBe(true);
  });
});
