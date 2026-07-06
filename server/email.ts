// Pluggable transactional email. Uses Resend's HTTP API when RESEND_API_KEY is
// configured (works behind egress policies that block raw SMTP); otherwise logs
// the message to the console so local/demo magic-link flows still work.

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM || 'Seclayer <onboarding@resend.dev>';

export function isEmailConfigured(): boolean {
  return !!RESEND_API_KEY;
}

export interface SendEmailInput {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export async function sendEmail(input: SendEmailInput): Promise<void> {
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
      to: input.to,
      subject: input.subject,
      html: input.html,
      text: input.text,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Email send failed (${res.status}): ${body}`);
  }
}

// Builds the magic-link login email.
export function buildMagicLinkEmail(link: string): { subject: string; html: string; text: string } {
  return {
    subject: 'Your Seclayer sign-in link',
    text: `Sign in to Seclayer by opening this link (valid for 15 minutes):\n\n${link}\n\nIf you did not request this, you can safely ignore this email.`,
    html: `
      <div style="font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#18181b">
        <h2 style="color:#16a34a;margin:0 0 16px">Sign in to Seclayer</h2>
        <p style="margin:0 0 20px;line-height:1.5">Click the button below to securely sign in. This link is valid for 15 minutes and can be used once.</p>
        <a href="${link}" style="display:inline-block;background:#16a34a;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;font-weight:600">Sign in to Seclayer</a>
        <p style="margin:24px 0 0;font-size:12px;color:#71717a;line-height:1.5">If the button does not work, copy and paste this URL into your browser:<br>${link}</p>
        <p style="margin:16px 0 0;font-size:12px;color:#71717a">If you did not request this, you can safely ignore this email.</p>
      </div>`,
  };
}
