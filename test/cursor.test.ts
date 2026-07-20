import { describe, expect, it } from "vitest";
import { encodeCursor, decodeCursor } from "../src/utils/cursor";

const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));

describe("signed cursors", () => {
  it("round-trips cursor state", async () => {
    const value = { v: 1, fingerprint: "search", accounts: { account_1: "next-page" } };
    const cursor = await encodeCursor(value, key);
    await expect(decodeCursor(cursor, key)).resolves.toEqual(value);
  });

  it("rejects modified state", async () => {
    const cursor = await encodeCursor({ v: 1, fingerprint: "search", accounts: {} }, key);
    const [payload, signature] = cursor.split(".");
    await expect(decodeCursor(`${payload}a.${signature}`, key)).rejects.toMatchObject({ code: "invalid_cursor" });
  });

  it("rejects malformed cursors", async () => {
    await expect(decodeCursor("not-a-cursor", key)).rejects.toMatchObject({ code: "invalid_cursor" });
  });
});
