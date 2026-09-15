// Guard: no narrative prose may quote a posture score or grade.
//
// The score is NOT a fixed property of a finished scan. Every read path
// recalculates it deterministically from the surviving findings
// (db.getScanWithSuppressedFindings -> recalculateScore), so the moment a user
// marks a finding as a false positive the displayed score changes — while any
// number baked into prose at write time stays frozen. The reader then sees a
// box saying one thing and a paragraph saying another.
//
// The prompt asks the model not to state a number (see server/reportPrompt.ts),
// but a prompt is a request, not a guarantee, so this enforces it on the way
// out. Whole sentences are dropped rather than the number being spliced out:
// deleting mid-sentence produces mangled grammar, and an executive summary with
// one fewer sentence still reads correctly.
//
// The score box itself is the single source of truth, and it is always right,
// because it is derived at the moment it is rendered.

// Matches a claim about a numeric score or a letter grade:
//   "85/100", "85 out of 100", "score of 85", "scored 85", "score: 85",
//   "grade of B", "grade B", "a B grade"
const SCORE_CLAIM =
  /\b\d{1,3}\s*(?:\/|out\s+of)\s*100\b|\bscor\w*\s*(?:of|is|at|:)?\s*\d{1,3}\b|\bgrade\s*(?:of\s*)?[A-F]\b|\b[A-F]\s+grade\b/i;

// True when the text makes a score/grade claim that could drift out of step
// with the recalculated score box.
export function mentionsScore(text: string): boolean {
  return SCORE_CLAIM.test(text || "");
}

// Below this, what survived is too thin to serve as a summary and the caller's
// deterministic fallback reads better than a stub.
const MIN_USEFUL_LENGTH = 40;

// Drop every sentence that quotes a score or grade. Returns `fallback` when
// nothing usable survives (or the input was empty), so a caller always gets
// real prose back rather than an empty string.
export function stripScoreClaims(text: string, fallback: string): string {
  const input = (text || "").trim();
  if (!input) return fallback;
  if (!SCORE_CLAIM.test(input)) return input;

  // Split on sentence boundaries, keeping the terminator with its sentence.
  const kept = input
    .split(/(?<=[.!?])\s+/)
    .filter((sentence) => sentence.trim() && !SCORE_CLAIM.test(sentence))
    .join(" ")
    .trim();

  return kept.length >= MIN_USEFUL_LENGTH ? kept : fallback;
}
