// Pluggable transactional email. Uses Resend's HTTP API when RESEND_API_KEY is
// configured (works behind egress policies that block raw SMTP); otherwise logs
// the message to the console so local/demo sign-in flows still work.
import { htmlToPlainText } from './htmlToText.js';
import { db } from './db.js';
import type { MailKind } from './emailSuppression.js';

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM || 'Seclayer <onboarding@resend.dev>';

// onboarding@resend.dev and the seclayer.app From address are both send-only —
// nothing reads mail sent back to them, so a customer's reply to a magic-link
// or digest email vanishes silently unless this is set to an inbox a human
// actually reads. Left unset, no reply_to header is attached, which is honest
// rather than pointing replies at a black hole.
const REPLY_TO_EMAIL = process.env.REPLY_TO_EMAIL?.trim() || undefined;

export function isEmailConfigured(): boolean {
  return !!RESEND_API_KEY;
}

export interface SendEmailInput {
  to: string;
  subject: string;
  html: string;
  text?: string;
  /**
   * What this message is FOR, which decides whether a spam complaint stops it.
   *
   * Defaults to 'account' — the safe direction. A message whose kind nobody
   * thought about is far more likely to be a sign-in code than a digest, and
   * wrongly suppressing one locks somebody out of their account, while wrongly
   * sending one bulk message is an annoyance.
   */
  kind?: MailKind;
}

export async function sendEmail(input: SendEmailInput): Promise<void> {
  // Bounced and complained-about addresses are skipped before anything is sent.
  // A hard bounce stops everything; a complaint stops only bulk mail, so a
  // sign-in code still reaches someone who marked a digest as spam.
  //
  // Fails OPEN: if the lookup throws, we send. A database blip that silently
  // stopped every sign-in code in the system would be far worse than one extra
  // message to an address that bounced.
  const kind = input.kind ?? 'account';
  let suppressed = false;
  try {
    suppressed = (await db.isEmailSuppressed(input.to, kind));
  } catch (err) {
    console.error('[email] Could not check the suppression list; sending anyway:', err);
  }

  if (suppressed) {
    if (kind === 'bulk') {
      // A digest that is not sent is exactly the intended outcome, and the
      // caller has nothing useful to do about it.
      console.warn('[email] Skipping bulk message to a suppressed address.');
      return;
    }
    // ACCOUNT mail throws instead of returning quietly. Only a hard bounce
    // reaches here (a complaint never blocks account mail), so the mailbox does
    // not exist and the message has nowhere to go. Returning silently would let
    // the caller answer "your sign-in code is on its way" and strand the user
    // at a prompt they can never satisfy — which is precisely what happened in
    // testing before this branch existed.
    throw new Error('That address is on the suppression list after a permanent delivery failure.');
  }

  if (!RESEND_API_KEY) {
    // Dev/demo fallback: surface the message (and any link) in server logs.
    console.log(
      `\n[email:console] To: ${input.to}\n[email:console] Subject: ${input.subject}\n[email:console] ${input.text || input.html}\n`,
    );
    return;
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: EMAIL_FROM,
      ...(REPLY_TO_EMAIL ? { reply_to: REPLY_TO_EMAIL } : {}),
      to: input.to,
      subject: input.subject,
      html: input.html,
      // Never omitted. A hand-written text body wins where the wording matters
      // and both current senders supply one, but `text` is optional on the
      // input type — so it is derived from the HTML rather than left undefined
      // when a caller skips it. Mail with no text alternative scores worse with
      // spam filters before a human sees it, and shows as blank in text-only
      // clients.
      text: input.text?.trim() || htmlToPlainText(input.html),
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Email send failed (${res.status}): ${body}`);
  }
}

/**
 * The one-time sign-in code email.
 *
 * The code is rendered as text, never as a link: a code that is also a
 * clickable URL would reintroduce the exact problem codes were adopted to
 * solve, where mail security scanners follow every link in a message
 * automatically.
 *
 * It is spaced as "123 456" for legibility, and the mail says so, because
 * normalizeLoginCode strips the separators — a user typing the space back in
 * must not burn one of their five attempts on punctuation.
 */
export function buildLoginCodeEmail(code: string, ttlMinutes: number): { subject: string; html: string; text: string } {
  const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
  // In the SUBJECT too: most clients preview enough of it that the code can be
  // read without opening the mail, which is the fastest path back to the tab
  // already waiting for it.
  return {
    subject: `${spaced} is your Seclayer sign-in code`,
    text:
      `Your Seclayer sign-in code is ${spaced}\n\n` +
      `Enter it on the sign-in page. It expires in ${ttlMinutes} minutes and can be used once.\n\n` +
      `Spaces do not matter. If you did not request this, you can safely ignore this email — ` +
      `someone entering your address cannot sign in without this code.`,
    html: `
      <div style="font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#18181b">
        <h2 style="color:#16a34a;margin:0 0 16px">Your sign-in code</h2>
        <p style="margin:0 0 20px;line-height:1.5">Enter this code on the Seclayer sign-in page.</p>
        <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:6px;background:#f4f4f5;border:1px solid #e4e4e7;border-radius:8px;padding:16px 24px;text-align:center;color:#18181b">${spaced}</div>
        <p style="margin:20px 0 0;font-size:13px;color:#71717a;line-height:1.5">It expires in ${ttlMinutes} minutes and can be used once. Spaces do not matter.</p>
        <p style="margin:16px 0 0;font-size:12px;color:#71717a;line-height:1.5">If you did not request this, you can safely ignore this email — someone entering your address cannot sign in without this code.</p>
      </div>`,
  };
}

/**
 * The scan-is-ready email.
 *
 * Seclayer had no per-scan notification at all: it emailed sign-in codes and the
 * periodic digest, and `notifyScanComplete` was webhook-only (`if (!webhook)
 * return`). So a user who ran a scan, or whose monitored target was rescanned,
 * was never told the report existed unless they came back and looked.
 *
 * The link is a SHARE TOKEN (/r/<token>), not the dashboard URL, for the reason
 * SecScan's report email was changed to one: a dashboard link requires being
 * signed in as the report's owner, which fails on the most common way people
 * open mail — on a phone, logged out or signed into another account — and
 * renders as a dead end. A share token resolves with no session.
 *
 * kind: 'bulk' — this is a notification, not account-critical mail. Someone who
 * marked a Seclayer notification as spam should stop receiving these, while
 * their sign-in codes keep working. See server/emailSuppression.ts.
 */
export function buildScanReadyEmail(opts: {
  targetUrl: string;
  grade: string;
  score: number;
  findingCount: number;
  reportUrl: string;
}): { subject: string; html: string; text: string } {
  const { targetUrl, grade, score, findingCount, reportUrl } = opts;
  const host = (() => {
    try { return new URL(targetUrl).host; } catch { return targetUrl; }
  })();
  const countLine =
    findingCount === 0
      ? 'No active findings.'
      : `${findingCount} active finding${findingCount === 1 ? '' : 's'}.`;

  return {
    subject: `Grade ${grade} for ${host} — your Seclayer report is ready`,
    text:
      `Your Seclayer scan of ${targetUrl} is complete.\n\n` +
      `Grade ${grade} (score ${score}/100). ${countLine}\n\n` +
      `Read the full report:\n${reportUrl}\n\n` +
      `This link opens without signing in, so it works on any device. ` +
      `Anyone with the link can read this one report — you can revoke it from the report page.`,
    html: `
      <div style="font-family:system-ui,-apple-system,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#18181b">
        <h2 style="color:#16a34a;margin:0 0 8px">Your report is ready</h2>
        <p style="margin:0 0 20px;color:#52525b;font-size:14px">Seclayer finished scanning <strong style="color:#18181b">${host}</strong>.</p>
        <div style="display:flex;gap:12px;margin:0 0 20px">
          <div style="flex:1;background:#f4f4f5;border:1px solid #e4e4e7;border-radius:8px;padding:14px;text-align:center">
            <div style="font-size:28px;font-weight:700;line-height:1;color:#18181b">${grade}</div>
            <div style="font-size:11px;color:#71717a;margin-top:4px">GRADE</div>
          </div>
          <div style="flex:1;background:#f4f4f5;border:1px solid #e4e4e7;border-radius:8px;padding:14px;text-align:center">
            <div style="font-size:28px;font-weight:700;line-height:1;color:#18181b">${score}</div>
            <div style="font-size:11px;color:#71717a;margin-top:4px">SCORE / 100</div>
          </div>
        </div>
        <p style="margin:0 0 20px;font-size:14px;line-height:1.5">${countLine}</p>
        <a href="${reportUrl}" style="display:inline-block;background:#16a34a;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;font-weight:600">Read the full report</a>
        <p style="margin:20px 0 0;font-size:12px;color:#71717a;line-height:1.5">This link opens without signing in, so it works on any device. Anyone with the link can read this one report — you can revoke it from the report page.</p>
        <p style="margin:12px 0 0;font-size:12px;color:#71717a;word-break:break-all">${reportUrl}</p>
      </div>`,
  };
}
