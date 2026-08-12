// Weekly monitoring-digest worker. On an hourly tick it mails each opted-in
// user a summary of their monitored targets — but at most once every 7 days per
// user (tracked via users.lastDigestAt). Reuses the existing sendEmail transport
// (Resend when configured, console in dev). Returns the interval handle;
// runDueDigests is exported so a test can drive one pass directly.
import { db } from "./db.js";
import { config } from "./config.js";
import { sendEmail } from "./email.js";
import { buildDigest, type DigestInput } from "./digest.js";

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

export async function runDueDigests(now: Date = new Date()): Promise<void> {
  for (const user of (await db.listDigestRecipients())) {
    try {
      if (user.lastDigestAt && now.getTime() - new Date(user.lastDigestAt).getTime() < WEEK_MS) {
        continue; // already mailed within the last week
      }
      const targets = (await db.listMonitoredTargets(user.id));
      if (targets.length === 0) continue; // nothing to report; don't send an empty digest

      const inputs: DigestInput[] = await Promise.all(targets.map(async (t) => {
        // The most recent COMPLETED scan (excludeId "" matches nothing) and the
        // one before it, for the change counts.
        const latest = (await db.getPreviousCompletedScan(user.id, t.url, ""));
        const previous = latest ? (await db.getPreviousCompletedScan(user.id, t.url, latest.id)) : undefined;
        return { url: t.url, latest, previous };
      }));

      const digest = buildDigest(inputs, config.appUrl || "https://seclayerio.ai");
      if (!digest) { (await db.markDigestSent(user.id, now.toISOString())); continue; }

      await sendEmail({ to: user.email, subject: digest.subject, text: digest.text, html: digest.html });
      (await db.markDigestSent(user.id, now.toISOString()));
    } catch (err) {
      // One user's failure must never stop the rest of the run.
      console.warn(`[digest] failed for ${user.email}:`, err);
    }
  }
}

export function startDigestWorker(): NodeJS.Timeout {
  const interval = setInterval(() => {
    runDueDigests().catch((e) => console.error("[digest] tick error:", e));
  }, 60 * 60 * 1000);
  interval.unref();
  return interval;
}
