import { describe, expect, it } from "vitest";
import { htmlToText, sanitizeHeaderValue, truncateUtf8 } from "../src/utils/text";

describe("email text helpers", () => {
  it("converts common HTML email markup without executable content", () => {
    expect(htmlToText("<style>x{}</style><p>Hello&nbsp;<b>there</b></p><script>alert(1)</script>"))
      .toBe("Hello there");
  });

  it("removes header newlines", () => {
    expect(sanitizeHeaderValue("Hello\r\nBcc: attacker@example.com")).toBe("Hello Bcc: attacker@example.com");
  });

  it("truncates on UTF-8 byte length", () => {
    expect(truncateUtf8("abc😀def", 5)).toEqual({ value: "abc", truncated: true });
  });
});
