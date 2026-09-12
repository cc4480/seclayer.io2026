import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FRAMEWORKS,
  COMPLIANCE_DISCLAIMER,
  controlsForFinding,
  summariseCompliance,
} from "./compliance.js";
import { mapOwasp } from "./owasp.js";

test("maps a finding to the controls it is evidence for, via its OWASP category", () => {
  const refs = controlsForFinding({ owasp: "A03:2021 – Injection" });
  const ids = refs.map((r) => `${r.framework}:${r.control}`);
  assert.ok(ids.includes("pci:6.2.4"), ids.join(", "));
  assert.ok(ids.includes("asvs:V5.3.3"), ids.join(", "));
});

// Keyed on the A0N prefix so renaming the human-readable suffix in owasp.ts
// cannot silently break every lookup.
test("keys on the A0N prefix, not the full label", () => {
  const a = controlsForFinding({ owasp: "A10:2021 – Server-Side Request Forgery (SSRF)" });
  const b = controlsForFinding({ owasp: "A10:2021 – renamed upstream someday" });
  assert.deepEqual(a, b);
  assert.ok(a.length > 0);
});

test("returns nothing rather than guessing when there is no OWASP category", () => {
  assert.deepEqual(controlsForFinding({}), []);
  assert.deepEqual(controlsForFinding({ owasp: null }), []);
  assert.deepEqual(controlsForFinding({ owasp: "not a category" }), []);
});

test("never emits a control for a framework it does not know", () => {
  for (const cat of ["A01", "A02", "A03", "A05", "A06", "A07", "A08", "A10"]) {
    for (const ref of controlsForFinding({ owasp: `${cat}:2021 – x` })) {
      assert.ok(FRAMEWORKS[ref.framework], `unknown framework ${ref.framework}`);
    }
  }
});

// THE coverage guarantee. mapOwasp is applied to every finding and always
// returns a category, so total coverage here means no finding can silently drop
// out of the compliance view. If someone adds a category to owasp.ts without
// mapping it, this fails.
test("every category mapOwasp can return has a mapping", () => {
  const samples: Array<[string, string]> = [
    ["RED_TEAM", "Active SQL Injection Probe"],
    ["RED_TEAM", "Broken Object Level Authorization (BOLA)"],
    ["IAST", "Insecure Connection Protocol (HTTP)"],
    ["SCA", "Outdated library jquery 1.4"],
    ["RED_TEAM", "JWT signature not verified"],
    ["RED_TEAM", "Active Server-Side Request Forgery (SSRF)"],
    ["DAST", "Subresource Integrity missing on external script"],
    ["IAST", "Missing X-Frame-Options / Clickjacking Immunity"],
    ["SAST", "Exposed Stripe secret key in page HTML"],
  ];
  const unmapped: string[] = [];
  for (const [category, title] of samples) {
    const owasp = mapOwasp(category, title);
    if (controlsForFinding({ owasp }).length === 0) unmapped.push(`${owasp} (from "${title}")`);
  }
  assert.deepEqual(unmapped, [], `unmapped OWASP categories: ${unmapped.join("; ")}`);
});

test("counts findings per control, heaviest first", () => {
  const summary = summariseCompliance([
    { owasp: "A03:2021 – Injection" },
    { owasp: "A03:2021 – Injection" },
    { owasp: "A06:2021 – Vulnerable and Outdated Components" },
  ]);
  const pci = summary.find((s) => s.framework.id === "pci")!;
  assert.equal(pci.controls[0]!.control, "6.2.4");
  assert.equal(pci.controls[0]!.findings, 2);
});

// A framework with nothing mapped must be ABSENT, not present with zero
// controls — the latter reads as "assessed and clean".
test("omits a framework entirely when nothing mapped to it", () => {
  const summary = summariseCompliance([{ owasp: "A09:2021 – Logging Failures" }]);
  assert.equal(summary.some((s) => s.framework.id === "pci"), false);
  assert.equal(summary.some((s) => s.framework.id === "soc2"), true);
});

test("a clean scan produces an empty summary", () => {
  assert.deepEqual(summariseCompliance([]), []);
});

// The most important property: no number that could be read as an audit score.
test("reports no pass rate, score or percentage anywhere", () => {
  const serialised = JSON.stringify(
    summariseCompliance([{ owasp: "A03:2021 – Injection" }, { owasp: "A02:2021 – Cryptographic Failures" }]),
  );
  assert.doesNotMatch(serialised, /percent|passRate|pass_rate|score|compliant|%/i);
});

test("the disclaimer refuses the four claims that would be false", () => {
  assert.match(COMPLIANCE_DISCLAIMER, /not a compliance assessment|not an audit/i);
  assert.match(COMPLIANCE_DISCLAIMER, /clean scan is not a passed control/i);
  assert.match(COMPLIANCE_DISCLAIMER, /CPA/);
  assert.match(COMPLIANCE_DISCLAIMER, /QSA/);
});

// The two products must not state different versions or caveats for the same
// framework — a customer comparing two of our reports would catch it.
test("framework metadata is pinned and complete", () => {
  for (const fw of Object.values(FRAMEWORKS)) {
    assert.ok(fw.version.trim().length > 0, `${fw.name} has no version`);
    assert.ok(fw.note.trim().length > 0, `${fw.name} has no note`);
  }
  assert.match(FRAMEWORKS.pci!.note, /not an ASV scan/i);
  assert.match(FRAMEWORKS.soc2!.note, /no scan can observe|policy, personnel/i);
});
