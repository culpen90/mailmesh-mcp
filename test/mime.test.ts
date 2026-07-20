import { describe, expect, it } from "vitest";
import { decodeMimeWords, parseAddressList, parseMimeMessage } from "../src/utils/mime";

describe("MIME utilities", () => {
  it("decodes adjacent encoded words and quoted address names", () => {
    expect(decodeMimeWords("=?UTF-8?Q?Cloudflare?= =?UTF-8?Q?_=E2=9C=93?=")).toBe("Cloudflare ✓");
    expect(parseAddressList('=?UTF-8?Q?J=C3=B6rg,_Jr.?= <joerg@example.com>, Other <other@example.net>')).toEqual([
      { name: "Jörg, Jr.", email: "joerg@example.com" },
      { name: "Other", email: "other@example.net" },
    ]);
  });

  it("parses nested multipart bodies and attachment metadata", () => {
    const raw = [
      "From: =?UTF-8?Q?J=C3=B6rg?= <joerg@example.com>",
      "To: User <user@example.net>",
      "Subject: =?UTF-8?B?VGVzdCDinJM=?=",
      "Date: Mon, 20 Jul 2026 12:00:00 -0400",
      "Message-ID: <message@example.com>",
      'Content-Type: multipart/mixed; boundary="mesh"',
      "",
      "preamble",
      "--mesh",
      'Content-Type: multipart/alternative; boundary="alternative"',
      "",
      "--alternative",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      "Hello=2C MailMesh=21",
      "--alternative",
      "Content-Type: text/html; charset=utf-8",
      "",
      "<p>Hello, <strong>MailMesh!</strong></p>",
      "--alternative--",
      "--mesh",
      "Content-Type: application/pdf; name*=UTF-8''r%C3%A9sum%C3%A9.pdf",
      "Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf",
      "Content-Transfer-Encoding: base64",
      "",
      "JVBERi0xLjQ=",
      "--mesh--",
      "epilogue",
    ].join("\r\n");

    const parsed = parseMimeMessage(raw);
    expect(parsed.subject).toBe("Test ✓");
    expect(parsed.from).toEqual({ name: "Jörg", email: "joerg@example.com" });
    expect(parsed.date).toBe("2026-07-20T16:00:00.000Z");
    expect(parsed.bodyText).toBe("Hello, MailMesh!");
    expect(parsed.bodyHtml).toContain("<strong>MailMesh!</strong>");
    expect(parsed.hasAttachments).toBe(true);
    expect(parsed.attachments).toEqual([
      expect.objectContaining({ filename: "résumé.pdf", mimeType: "application/pdf", size: 8, inline: false }),
    ]);
    expect(parsed.truncated).toBe(false);
  });

  it("bounds extracted text and marks intentionally partial messages", () => {
    const parsed = parseMimeMessage(
      "Content-Type: text/plain; charset=utf-8\r\n\r\nabcdefghijklmnopqrstuvwxyz",
      { maxTextBytes: 10, truncated: true },
    );
    expect(parsed.bodyText).toBe("abcdefghij");
    expect(parsed.truncated).toBe(true);
  });
});
