/**
 * A plain-text alternative derived from an email's HTML.
 *
 * Both senders here already pass a hand-written `text`, but the field is
 * optional on SendEmailInput, so a message with no text part is one new sender
 * away. Deriving it centrally makes that impossible rather than unlikely.
 *
 * Mail with no text alternative — `multipart/alternative` with
 * no text part at all. That is a long-standing spam heuristic: real senders at
 * scale always ship both, and mail with no text alternative scores worse before
 * a human ever sees it. It also renders as nothing in text-only clients, in
 * accessibility tooling, and in the preview pane of anything that refuses HTML.
 *
 * This is the FALLBACK, not the goal. A hand-written text body is better than
 * anything derived from markup, and the senders that matter most supply one.
 * What this guarantees is that a text part can never be MISSING — including
 * from a sender someone adds next year without thinking about it, which is
 * exactly how the gap appeared in the first place.
 *
 * Deliberately not a general HTML-to-text library: the input is our own
 * templates, so it only has to handle the tags those use. A dependency for this
 * would be more surface than the problem deserves.
 */

const ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
  "&apos;": "'",
  "&nbsp;": " ",
  "&mdash;": "—",
  "&ndash;": "–",
};

function decodeEntities(s: string): string {
  return s
    .replace(/&[a-z#0-9]+;/gi, (e) => ENTITIES[e.toLowerCase()] ?? e)
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCodePoint(Number(n)));
}

export function htmlToPlainText(html: string): string {
  let s = html;

  // Drop anything whose CONTENT is not readable prose. Style blocks especially:
  // without this, a stylesheet's text ends up in the message body, which looks
  // like obfuscation to a spam filter — worse than having no text part at all.
  s = s.replace(/<(style|script|head|title)[\s\S]*?<\/\1>/gi, " ");
  s = s.replace(/<!--[\s\S]*?-->/g, " ");

  // Links become "label (url)". Stripping the tag and keeping only the label
  // would silently delete the one thing most of these emails exist to convey —
  // the verify link, the report URL, the unsubscribe address.
  s = s.replace(
    /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi,
    (_m, href: string, label: string) => {
      const text = label.replace(/<[^>]+>/g, "").trim();
      if (!text) return href;
      // A link whose label already IS the URL should not be printed twice.
      return text === href ? href : `${text} (${href})`;
    },
  );

  // Block boundaries become line breaks before tags are stripped, or every
  // paragraph runs into the next as one wall of text.
  s = s.replace(/<br\s*\/?>/gi, "\n");
  s = s.replace(/<\/(p|div|tr|h[1-6]|li|table|section|header|footer)\s*>/gi, "\n");
  s = s.replace(/<li\b[^>]*>/gi, "- ");
  s = s.replace(/<\/td\s*>/gi, " ");

  s = s.replace(/<[^>]+>/g, "");
  s = decodeEntities(s);

  return s
    .split("\n")
    // Collapse runs of spaces WITHIN a line only — collapsing across lines
    // would undo the breaks recovered above.
    .map((line) => line.replace(/[ \t ]+/g, " ").trim())
    .join("\n")
    // At most one blank line between blocks. Email templates are full of
    // structural markup that otherwise leaves a dozen empty lines.
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
