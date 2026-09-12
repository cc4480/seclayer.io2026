// Compliance mapping: which control each finding is EVIDENCE FOR.
//
// ── Read this before using any of it in a report or a sales deck ──
//
// This maps findings to control identifiers. It does NOT determine compliance,
// and nothing here may be presented as though it does. The distinction is the
// difference between a useful artifact and a misleading one:
//
//  • A scan sees one thing: the HTTP surface of a running application at one
//    moment. SOC 2 and ISO 27001 are overwhelmingly about what it cannot see —
//    written policy, personnel screening, change management, vendor review,
//    incident response, physical security, access reviews. Most of every
//    framework below is invisible to any scanner.
//  • So a clean scan is NOT a passed control, and a finding is NOT a failed
//    audit. A finding is evidence an auditor can weigh; its absence is the
//    absence of that evidence, nothing more.
//  • Only a licensed CPA firm issues a SOC 2 report. Only a QSA signs off PCI
//    DSS. Only an accredited body certifies ISO 27001.
//
// What it IS good for: a customer's security reviewer asking "show me you test
// for injection" can be handed findings mapped to PCI DSS 6.2.4 and ASVS V5.3 —
// real, checkable work. Overstating it would destroy that value.
//
// ── Why OWASP Top 10 is the key here ──
// Seclayer's Finding carries no cweId (SecScan's does, and its mapping keys on
// that). What every Seclayer finding DOES carry is `owasp`: findings.ts applies
// mapOwasp() in both finalization loops and it always returns a category, so
// coverage is total. The trade is precision — A05 "Security Misconfiguration"
// spans more ground than a specific CWE — so the controls listed per category
// stay at the level the category genuinely supports rather than guessing
// narrower. The seven-pillar `category` (SAST/DAST/IAST/SCA/EASM/API_SEC/
// RED_TEAM) is deliberately NOT used: it describes which engine found a thing,
// not what the weakness is, so it maps to nothing meaningful.

export interface FrameworkMeta {
  id: string;
  name: string;
  version: string;
  note: string;
}

// Kept identical to SecScan's table on purpose: the two products must not state
// different versions or different caveats for the same framework.
export const FRAMEWORKS: Record<string, FrameworkMeta> = {
  soc2: {
    id: "soc2",
    name: "SOC 2",
    version: "2017 TSC (rev. 2022)",
    note:
      "Trust Services Criteria. Most criteria cover policy, personnel and process that no scan can observe; " +
      "these findings are technical evidence for the subset an application scan can speak to.",
  },
  pci: {
    id: "pci",
    name: "PCI DSS",
    version: "4.0.1",
    note:
      "Applies only if the environment stores, processes or transmits cardholder data. " +
      "Requirement 11.3.2 expects external vulnerability scanning by an ASV; this scan is not an ASV scan.",
  },
  iso27001: {
    id: "iso27001",
    name: "ISO/IEC 27001",
    version: "2022 Annex A",
    note:
      "Annex A controls. Certification is granted by an accredited body against the management system as a whole, " +
      "not against a scan result.",
  },
  asvs: {
    id: "asvs",
    name: "OWASP ASVS",
    version: "4.0.3",
    note:
      "Application Security Verification Standard — the framework designed for exactly this kind of testing, " +
      "so the mapping is tightest and the coverage most meaningful.",
  },
};

export interface ControlRef {
  framework: keyof typeof FRAMEWORKS;
  control: string;
  title: string;
}

// OWASP Top 10 2021 category → the controls a finding in it is evidence for.
// Keyed on the "A0N" prefix so a change to the human-readable suffix in
// owasp.ts cannot silently break the lookup.
const OWASP_CONTROLS: Record<string, ControlRef[]> = {
  A01: [
    { framework: "asvs", control: "V4.1.1", title: "Access control enforced server-side" },
    { framework: "asvs", control: "V4.2.1", title: "Object-level authorisation enforced" },
    { framework: "pci", control: "7.2.1", title: "Access assigned by need-to-know" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  A02: [
    { framework: "asvs", control: "V9.1.1", title: "TLS used for all client connectivity" },
    { framework: "asvs", control: "V6.1.1", title: "Sensitive data not stored in cleartext" },
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
    { framework: "pci", control: "3.5.1", title: "Stored account data rendered unreadable" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
    { framework: "soc2", control: "CC6.7", title: "Transmission of data is protected" },
  ],
  A03: [
    { framework: "asvs", control: "V5.3.3", title: "Output encoding prevents cross-site scripting" },
    { framework: "asvs", control: "V5.3.4", title: "Parameterised database queries" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  // Not currently emitted by mapOwasp, mapped anyway so adding it later needs no
  // change here — an unmapped category would silently drop out of the view.
  A04: [
    { framework: "asvs", control: "V1.1.1", title: "Secure development lifecycle" },
    { framework: "iso27001", control: "A.8.25", title: "Secure development lifecycle" },
  ],
  A05: [
    { framework: "asvs", control: "V14.1.1", title: "Secure build and deployment configuration" },
    { framework: "asvs", control: "V14.4.1", title: "Security headers configured" },
    { framework: "pci", control: "2.2.1", title: "Configuration standards applied to system components" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  A06: [
    { framework: "asvs", control: "V14.2.1", title: "Dependencies free of known vulnerabilities" },
    { framework: "pci", control: "6.3.3", title: "Third-party components patched" },
    { framework: "iso27001", control: "A.8.8", title: "Management of technical vulnerabilities" },
  ],
  A07: [
    { framework: "asvs", control: "V2.2.1", title: "Authentication cannot be bypassed or spoofed" },
    { framework: "asvs", control: "V3.4.1", title: "Session cookies hardened" },
    { framework: "pci", control: "8.3.1", title: "Strong authentication required for access" },
    { framework: "iso27001", control: "A.5.17", title: "Authentication information" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — authentication enforced" },
  ],
  A08: [
    { framework: "asvs", control: "V14.2.3", title: "Third-party assets integrity-checked" },
    { framework: "pci", control: "6.4.3", title: "Payment page scripts are authorised and integrity-assured" },
    { framework: "iso27001", control: "A.5.21", title: "Managing ICT supply chain security" },
    { framework: "soc2", control: "CC8.1", title: "Change management" },
  ],
  A09: [
    { framework: "asvs", control: "V7.1.3", title: "Security events logged" },
    { framework: "iso27001", control: "A.8.15", title: "Logging" },
    { framework: "soc2", control: "CC7.2", title: "Monitoring — anomalies identified" },
  ],
  A10: [
    { framework: "asvs", control: "V12.6.1", title: "Server-side request forgery protection" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
};

/**
 * The controls a finding is evidence for. Empty when nothing maps — an honest
 * empty list beats inventing a control reference to fill a column.
 */
export function controlsForFinding(finding: { owasp?: string | null }): ControlRef[] {
  const prefix = /^(A\d{2})/.exec(String(finding.owasp ?? ""))?.[1];
  return (prefix && OWASP_CONTROLS[prefix]) || [];
}

export interface FrameworkCoverage {
  framework: FrameworkMeta;
  controls: Array<{ control: string; title: string; findings: number }>;
}

/**
 * Group findings by framework and control.
 *
 * Reports "controls with findings against them". It deliberately does NOT
 * report a pass rate or percentage: the denominator would have to be the
 * framework's full control set, most of which no scan can assess, and any
 * percentage from that is a fabrication that reads as an audit score.
 */
export function summariseCompliance(
  findings: Array<{ owasp?: string | null }>,
): FrameworkCoverage[] {
  const acc = new Map<string, Map<string, { title: string; findings: number }>>();

  for (const f of findings) {
    for (const ref of controlsForFinding(f)) {
      if (!acc.has(ref.framework)) acc.set(ref.framework, new Map());
      const controls = acc.get(ref.framework)!;
      const existing = controls.get(ref.control);
      if (existing) existing.findings++;
      else controls.set(ref.control, { title: ref.title, findings: 1 });
    }
  }

  return [...acc.entries()]
    .map(([fw, controls]) => ({
      framework: FRAMEWORKS[fw]!,
      controls: [...controls.entries()]
        .map(([control, v]) => ({ control, title: v.title, findings: v.findings }))
        .sort((a, b) => b.findings - a.findings || a.control.localeCompare(b.control)),
    }))
    .sort((a, b) => a.framework.name.localeCompare(b.framework.name));
}

/**
 * The sentence any compliance view must carry. Exported so it cannot drift
 * between the report, the PDF and the API — and so removing it is a visible,
 * deliberate act rather than an oversight. Identical to SecScan's.
 */
export const COMPLIANCE_DISCLAIMER =
  "This mapping shows which controls these findings are evidence for. It is not a compliance " +
  "assessment, an audit, or an attestation. An application scan observes the HTTP surface of a " +
  "running system at one point in time; SOC 2, PCI DSS and ISO 27001 are largely concerned with " +
  "policy, process and personnel that no scan can see. A clean scan is not a passed control. " +
  "Only a licensed CPA firm issues a SOC 2 report, only a QSA validates PCI DSS, and only an " +
  "accredited certification body certifies ISO 27001.";
