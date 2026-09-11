import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { htmlToPlainText } from "./htmlToText.js";
import { buildLoginCodeEmail } from "./email.js";

// The single most important case. These emails exist to deliver ONE thing —
// a sign-in code, a report link. A converter that keeps a link's label and
// drops its href produces text that reads fine and is useless.
test("htmlToPlainText keeps link URLs, not just their labels", () => {
  const out = htmlToPlainText('<a href="https://seclayer.app/r/abc">View report</a>');
  assert.ok(out.includes("https://seclayer.app/r/abc"), out);
  assert.ok(out.includes("View report"), out);
});

test("htmlToPlainText does not print the URL twice when the label already is the URL", () => {
  const url = "https://seclayer.app/r/1";
  assert.equal(htmlToPlainText(`<a href="${url}">${url}</a>`), url);
});

// A stylesheet's contents landing in the body looks like obfuscation to a spam
// filter — actively worse than having no text part.
test("htmlToPlainText drops style and script contents entirely", () => {
  const out = htmlToPlainText("<style>.x{color:red}</style><script>alert(1)</script><p>Real</p>");
  assert.equal(out, "Real");
});

test("htmlToPlainText turns block boundaries into line breaks", () => {
  assert.equal(htmlToPlainText("<p>First</p><p>Second</p>"), "First\nSecond");
  assert.equal(htmlToPlainText("<h1>Title</h1>a<br>b"), "Title\na\nb");
});

test("htmlToPlainText decodes the entities these templates produce", () => {
  assert.equal(
    htmlToPlainText("<p>Tom &amp; Jerry &quot;q&quot; &#39;x&#39; &mdash; end</p>"),
    `Tom & Jerry "q" 'x' — end`,
  );
  assert.equal(htmlToPlainText("<p>a&nbsp;b</p>"), "a b");
});

test("htmlToPlainText strips inline markup without eating the words around it", () => {
  assert.equal(htmlToPlainText("Your code is <strong>057001</strong>."), "Your code is 057001.");
});

test("htmlToPlainText collapses the blank lines email markup leaves behind", () => {
  const out = htmlToPlainText("<div><div><p>A</p></div></div><div><p>B</p></div>");
  assert.doesNotMatch(out, /\n\n\n/);
});

test("htmlToPlainText returns empty string for empty or markup-only input", () => {
  assert.equal(htmlToPlainText(""), "");
  assert.equal(htmlToPlainText("<div></div>"), "");
});

// The guarantee, not just the helper: sendEmail must never put `undefined` in
// the text field. `text` is optional on SendEmailInput, so a sender that omits
// it would otherwise ship HTML-only — which scores worse with spam filters
// before a human sees it and renders blank in text-only clients.
test("sendEmail always supplies a text part, derived when a caller omits one", () => {
  const src = fs.readFileSync(path.join(process.cwd(), "server", "email.ts"), "utf-8");
  assert.match(
    src,
    /text:\s*input\.text\?\.trim\(\)\s*\|\|\s*htmlToPlainText\(input\.html\)/,
    "sendEmail must fall back to a derived text part rather than sending `text: undefined`",
  );
});

// The code email carries a hand-written text body, which must stay better than
// what the fallback would produce: the code readable on its own line, and no
// markup leaking through.
test("the sign-in code email's text part states the code plainly", () => {
  const mail = buildLoginCodeEmail("057001", 10);
  assert.ok(mail.text.includes("057 001"), mail.text);
  assert.doesNotMatch(mail.text, /<[a-z/]/i, "no markup in the text part");
  // And the derived fallback would also carry it, if the hand-written one ever
  // went away — so neither path can lose the one thing the email is for.
  assert.ok(htmlToPlainText(mail.html).includes("057 001"));
});
