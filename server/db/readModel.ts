// Suppression read-model: returns a scan with the user's suppression rules
// applied and the score recalculated. A PURE transform — it never writes, so
// reads have no side effects and the stored scan record is never mutated.
import { Scan, Finding, SuppressionRule } from '../../src/types.js';
import { scoreFindings } from '../scoring.js';
import { cleanUrl } from './util.js';

export function makeReadModel(deps: { listSuppressions: (userId: string) => SuppressionRule[] }) {
  const getScanWithSuppressedFindings = (scan: Scan): Scan => {
    if (!scan || !scan.findings) return scan;
    const rules = deps.listSuppressions(scan.userId);
    const scanUrlClean = cleanUrl(scan.url);

    const findings = scan.findings.map((finding) => {
      const rule = rules.find((r) => cleanUrl(r.targetUrl) === scanUrlClean && r.findingTitle === finding.title);
      if (rule) {
        return { ...finding, isFalsePositive: true, suppressionReason: rule.reason, suppressedAt: rule.createdAt };
      }
      // Strip any stale suppression metadata if no rule currently matches.
      const { isFalsePositive, suppressionReason, suppressedAt, ...rest } = finding;
      return rest as Finding;
    });

    const { score, severity } = scoreFindings(findings);
    return { ...scan, findings, score, severity };
  };

  return { getScanWithSuppressedFindings };
}
