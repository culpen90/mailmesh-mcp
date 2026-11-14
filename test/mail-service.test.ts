import { describe, expect, it } from "vitest";
import { searchFingerprint } from "../src/utils/search";

describe("MailService search cursor binding", () => {
  it("binds cursors to scheduled-message inclusion without distinguishing omitted and false", async () => {
    const accounts = ["gmail-1"];
    const omitted = await searchFingerprint({ query: "lottery" }, accounts, 20);
    const excluded = await searchFingerprint(
      { query: "lottery", includeScheduled: false },
      accounts,
      20,
    );
    const included = await searchFingerprint(
      { query: "lottery", includeScheduled: true },
      accounts,
      20,
    );

    expect(excluded).toBe(omitted);
    expect(included).not.toBe(omitted);
  });
});
