import { test } from "node:test";
import assert from "node:assert/strict";
import { PROBES as RED_TEAM_PROBES } from "./redTeamProbes.js";
import { PROBES as AGGRESSIVE_PROBES } from "./aggressiveProbes.js";
import { PROBE_DESCRIPTORS } from "./probeDescriptors.js";

// The live ticker looks a descriptor up by the probe function's own name
// (Function.prototype.name). A probe with no descriptor emits NOTHING when it
// fires — the user watches a scan that silently skips a technique. So every
// probe the orchestrators actually run must have one, and the check has to read
// the real PROBES arrays rather than a hand-copied list that could drift.

const ALL_PROBES = [...RED_TEAM_PROBES, ...AGGRESSIVE_PROBES];

test("every orchestrated probe has a ticker descriptor", () => {
  const missing = ALL_PROBES.map((p) => p.name).filter((n) => !PROBE_DESCRIPTORS[n]);
  assert.deepEqual(
    missing,
    [],
    `these probes run but have no descriptor, so the ticker shows nothing when they fire: ${missing.join(", ")}`,
  );
});

test("every probe function actually carries a name to key on", () => {
  // An anonymous or arrow-assigned probe would look up PROBE_DESCRIPTORS[""] and
  // silently miss, so the lookup key must be a real identifier.
  for (const p of ALL_PROBES) {
    assert.ok(p.name && p.name.length > 1, `a probe has no usable function name: ${String(p)}`);
  }
});

test("each descriptor is complete — label, payload and why all present", () => {
  for (const [name, d] of Object.entries(PROBE_DESCRIPTORS)) {
    assert.ok(d.label?.trim(), `${name}: empty label`);
    assert.ok(d.payload?.trim(), `${name}: empty payload — the ticker's "firing" line would read blank`);
    assert.ok(d.why?.trim(), `${name}: empty why`);
  }
});

// Regression guard for the specific drift found on 2026-09-12: the SSTI
// descriptor claimed a static "{{7*7}}" while the probe fires a RANDOM product
// and the receipt shows that random number. A ticker payload that names a fixed
// value a randomised probe never sends is a lie the user can catch by reading
// the result line. Any randomised probe must advertise its shape, not a literal.
test("the SSTI descriptor advertises a shape, not a fixed product it never sends", () => {
  const d = PROBE_DESCRIPTORS["probeSsti"];
  assert.ok(d, "probeSsti descriptor missing");
  assert.doesNotMatch(
    d.payload,
    /7\s*\*\s*7|\b49\b/,
    "SSTI fires a randomised a*b, so the descriptor must not name 7*7 or 49",
  );
});
