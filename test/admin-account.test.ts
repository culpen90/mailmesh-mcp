import { beforeEach, describe, expect, it, vi } from "vitest";

const { updateAccountLabelMock } = vi.hoisted(() => ({
  updateAccountLabelMock: vi.fn(),
}));

vi.mock("../src/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/db")>();
  return {
    ...actual,
    updateAccountLabel: updateAccountLabelMock,
  };
});

import { handleAdminRequest } from "../src/admin";
import type { AccountRecord, Env } from "../src/types";

const origin = "https://mailmesh.example.com";
const ownerToken = "owner-token-with-enough-entropy";

function env(): Env {
  return {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: ownerToken,
    TOKEN_ENCRYPTION_KEY: "unused-in-account-admin-test",
    PUBLIC_BASE_URL: origin,
    WRITE_MODE: "drafts",
  };
}

function account(label = "Personal Gmail"): AccountRecord {
  return {
    id: "gmail-account",
    provider: "gmail",
    email: "person@example.com",
    label,
    encryptedCredentials: "encrypted",
    providerConfig: {},
    scopes: "https://www.googleapis.com/auth/gmail.compose",
    enabled: true,
    createdAt: "2026-07-20T00:00:00.000Z",
    updatedAt: "2026-07-29T00:00:00.000Z",
    lastError: null,
  };
}

describe("account label administration", () => {
  beforeEach(() => {
    updateAccountLabelMock.mockReset();
    updateAccountLabelMock.mockResolvedValue(account());
  });

  it("updates only the requested account label through the authenticated admin route", async () => {
    const response = await handleAdminRequest(new Request(`${origin}/admin/accounts/gmail-account`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${ownerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ label: "  Personal Gmail  " }),
    }), env());
    const body = await response?.json() as { account?: { id?: string; label?: string } };

    expect(response?.status).toBe(200);
    expect(body.account).toMatchObject({ id: "gmail-account", label: "Personal Gmail" });
    expect(updateAccountLabelMock).toHaveBeenCalledWith(
      expect.anything(),
      "gmail-account",
      "Personal Gmail",
    );
  });

  it("rejects empty labels without touching the database", async () => {
    const response = await handleAdminRequest(new Request(`${origin}/admin/accounts/gmail-account`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${ownerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ label: "   " }),
    }), env());

    expect(response?.status).toBe(400);
    expect(updateAccountLabelMock).not.toHaveBeenCalled();
  });

  it("returns not found when the requested account does not exist", async () => {
    updateAccountLabelMock.mockResolvedValueOnce(null);
    const response = await handleAdminRequest(new Request(`${origin}/admin/accounts/missing-account`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${ownerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ label: "Primary account" }),
    }), env());

    expect(response?.status).toBe(404);
  });

  it("advertises only PATCH and DELETE for an individual account", async () => {
    const response = await handleAdminRequest(new Request(`${origin}/admin/accounts/gmail-account`, {
      method: "PUT",
      headers: { authorization: `Bearer ${ownerToken}` },
    }), env());

    expect(response?.status).toBe(405);
    expect(response?.headers.get("allow")).toBe("PATCH, DELETE");
  });
});
