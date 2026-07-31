// Canonical form of a scan target so the SAME site is recognized across scans no
// matter how it was typed — with or without a scheme, a trailing slash, or host
// casing. Scans store the raw user input (e.g. "vibe-scan.replit.app" one time,
// "https://vibe-scan.replit.app" the next), so a naive `a === b` comparison would
// treat those as different targets and pick the wrong previous-scan baseline for
// the "what changed since last scan" diff. Normalizing both sides fixes that.
//
// http:// and https:// are intentionally kept distinct — they are genuinely
// different origins — but a missing scheme defaults to https, which is the case
// that actually causes the mismatch in practice.
export function normalizeTargetUrl(raw: string): string {
  let u = (raw || '').trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try {
    const p = new URL(u);
    const path = p.pathname.replace(/\/+$/, ''); // "/x/" and "/x" are the same target
    return `${p.protocol}//${p.host.toLowerCase()}${path}${p.search}`;
  } catch {
    return u.replace(/\/+$/, '').toLowerCase();
  }
}

// True when two raw target strings refer to the same site (scheme/slash/case
// insensitive). Used to match a report against its previous baseline.
export function sameTarget(a: string, b: string): boolean {
  return normalizeTargetUrl(a) === normalizeTargetUrl(b);
}
