/**
 * Which Resend delivery events stop which mail.
 *
 * Kept as a pure function, separate from the database work in db.ts, because it
 * is the part most likely to be wrong and the part whose mistakes are silent —
 * nobody notices an ignored bounce until reputation has already slipped, and
 * nobody notices a complaint suppressing the wrong thing until someone cannot
 * log in.
 */

export type SuppressionScope = 'all' | 'bulk';
export type SuppressionReason = 'hard_bounce' | 'complaint' | 'manual';

/** What a message is FOR, which decides whether a complaint stops it. */
export type MailKind = 'account' | 'bulk';

/** Map a Resend webhook event to a suppression, or null if it warrants none. */
export function suppressionForEvent(
  type: string,
  data: Record<string, unknown>,
): { email: string; scope: SuppressionScope; reason: SuppressionReason; detail?: string } | null {
  const to = data["to"];
  const email =
    typeof to === "string" ? to : Array.isArray(to) && typeof to[0] === "string" ? (to[0] as string) : "";
  if (!email) return null;

  if (type === 'email.complained') {
    return { email, scope: 'bulk', reason: 'complaint', detail: 'marked as spam' };
  }

  if (type === 'email.bounced') {
    const bounce = (data["bounce"] ?? {}) as Record<string, unknown>;
    const bounceType = String(bounce["type"] ?? "").toLowerCase();
    const subType = String(bounce["subType"] ?? bounce["sub_type"] ?? "").toLowerCase();
    const message = typeof bounce["message"] === "string" ? (bounce["message"] as string) : undefined;

    // ONLY permanent failures. A soft bounce is a full mailbox or a temporary
    // server problem; it resolves by itself, and suppressing on one would cut
    // off a real user whose inbox was briefly over quota.
    const permanent = bounceType === "hard" || bounceType === "permanent";
    if (!permanent) return null;

    // Amazon SES (which Resend sits on) reports a suppression-list bounce for
    // an address ITS list already holds, which says nothing about this address
    // being dead for us. Treated as permanent anyway: SES will not deliver to
    // it regardless, so continuing to try only burns reputation.
    return {
      email,
      scope: "all",
      reason: "hard_bounce",
      detail: message ?? (subType ? `${bounceType}/${subType}` : bounceType),
    };
  }

  return null;
}
