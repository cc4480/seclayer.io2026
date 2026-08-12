import React, { useState } from 'react';
import { Code, Globe, Zap, Package, Grid, Server, Terminal, ArrowLeft, Radar } from 'lucide-react';

interface DocsPageProps {
  onNavigate: (view: string, arg?: string) => void;
}

const PILLARS = [
  {
    key: 'SAST', name: 'Static Analysis', icon: Code, mode: 'Passive',
    what: 'Scans every HTML/JS/CSS file the target actually serves to a browser for exposed-secret signatures — API keys, cloud credentials, private key blocks — and flags high-entropy strings that look like live secrets rather than placeholders.',
    why: 'A leaked key in shipped client code is a full account or infrastructure compromise, and it\'s one of the most common real-world breach vectors precisely because nobody reviews the bundle after it\'s built.',
  },
  {
    key: 'DAST', name: 'Dynamic Audit', icon: Globe, mode: 'Passive recon + active fuzz (gated)',
    what: 'Crawls the site to map real links, forms, and JS-discovered endpoints; probes for commonly-exposed sensitive paths (config files, dotfiles, backup archives); and, once ownership is verified, fuzzes discovered parameters with a range of injection classes. When the target exposes an OpenAPI/Swagger schema (auto-discovered or supplied), it also fuzzes every declared API operation — reads under active probing, state-changing operations only under the aggressive opt-in.',
    why: 'Most exploitable bugs live in endpoints and parameters nobody documented. Mapping the real, crawled surface — not a guessed one — is what makes the active probes that follow actually relevant to this specific app.',
  },
  {
    key: 'IAST', name: 'Interactive Policies', icon: Zap, mode: 'Passive',
    what: 'Checks the security-relevant HTTP response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and related policy headers) and session-cookie flags (Secure, HttpOnly, SameSite).',
    why: 'These are cheap to fix and catastrophic to skip — a missing frame-ancestors policy or an unflagged session cookie turns an otherwise solid app into a clickjacking or session-theft target.',
  },
  {
    key: 'SCA', name: 'Composition Review', icon: Package, mode: 'Passive',
    what: 'Fingerprints client-loaded JavaScript libraries by version and checks each against known-vulnerable version ranges.',
    why: 'You inherit every CVE in every library you ship, whether you wrote the code or not. This is the fastest way to find out you\'re still running a library version with a public exploit.',
  },
  {
    key: 'EASM', name: 'Attack Surface', icon: Grid, mode: 'Passive',
    what: 'Resolves DNS, enumerates common subdomains, identifies the authoritative nameserver, and reads server/framework signature headers the target discloses about itself.',
    why: 'You can\'t secure what you don\'t know is exposed. A forgotten staging subdomain or an oversharing Server header is frequently the actual way in, not the app you meant to test.',
  },
  {
    key: 'API_SEC', name: 'API Security Testing', icon: Server, mode: 'Active (gated)',
    what: 'Probes for exposed GraphQL introspection and tests object-level authorization by comparing what two distinct identities can read from the same resource pattern — a real BOLA/IDOR check, not a guess from a single request.',
    why: 'Broken object-level authorization is consistently the #1 API vulnerability class in the wild, and it\'s invisible to a scanner that only ever tests as one user.',
  },
  {
    key: 'RED_TEAM', name: 'Red Team Active Probes', icon: Terminal, mode: 'Active (gated)',
    what: 'Attempts real exploitation — SQL injection, reflected XSS, OS command injection, and server-side request forgery (including blind, out-of-band SSRF) — against the root URL and every parameter the crawler discovered.',
    why: 'This is the difference between "the header is missing" and "we got the database to error on our injected quote." Only a real attempt tells you whether a gap is theoretical or exploitable today.',
  },
];

const TOC = [
  { id: 'overview', label: 'Overview' },
  { id: 'pillars', label: 'The seven pillars' },
  { id: 'evidence', label: 'PROVEN vs DETECTED' },
  { id: 'ownership', label: 'Domain ownership' },
  { id: 'scoring', label: 'Scoring & grading' },
  { id: 'network-recon', label: 'Network Reconnaissance (nmap)' },
  { id: 'ai-reports', label: 'AI-generated reports' },
  { id: 'mcp-api', label: 'MCP & API access' },
  { id: 'data', label: 'Data handling & privacy' },
  { id: 'closed-source', label: 'Why closed source' },
  { id: 'safety', label: 'Safety & responsible use' },
];

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-24 py-10 border-b border-[#27272a] last:border-b-0">
      <h2 className="text-xl sm:text-2xl font-mono font-bold tracking-tight text-white mb-4">{title}</h2>
      <div className="space-y-4 text-[#a1a1aa] text-sm font-mono leading-relaxed">{children}</div>
    </section>
  );
}

export default function DocsPage({ onNavigate }: DocsPageProps) {
  const [activePillar, setActivePillar] = useState<string | null>(null);

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa]">
      <div className="max-w-6xl mx-auto px-6 py-16">
        <button
          onClick={() => onNavigate('landing')}
          className="flex items-center space-x-2 text-[#52525b] hover:text-[#22c55e] text-xs font-mono uppercase tracking-widest mb-8 cursor-pointer transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
          <span>Back home</span>
        </button>

        <div className="mb-12">
          <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">Documentation</p>
          <h1 className="text-3xl sm:text-4xl font-mono font-bold tracking-tighter text-white mb-4">How Seclayer actually works</h1>
          <p className="text-[#a1a1aa] text-sm font-mono max-w-2xl leading-relaxed">
            Seclayer is closed source, deliberately — the active-exploitation modules described below are real,
            working exploit probes, and publishing their exact payloads and signatures would just hand out an
            evasion manual. What follows is everything short of that: what each module checks, why it matters,
            how evidence and scoring work, and how your data is handled.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-12">
          {/* Sticky table of contents */}
          <nav className="hidden lg:block">
            <div className="sticky top-24 space-y-1">
              {TOC.map((item) => (
                <a
                  key={item.id}
                  href={`#${item.id}`}
                  className="block text-xs font-mono text-[#71717a] hover:text-[#22c55e] py-1.5 transition-colors"
                >
                  {item.label}
                </a>
              ))}
            </div>
          </nav>

          <div className="min-w-0">
            <Section id="overview" title="Overview">
              <p>
                Point Seclayer at a public URL and it runs the same pipeline every time: resolve and validate the
                target, run passive black-box recon (HTTP headers, DNS, TLS, exposed files, tech fingerprinting,
                crawling), and — once you've proven you own the domain — attempt real exploitation across the
                gated active modules. Results compile into a report with a 0–100 posture score, a letter grade,
                per-finding evidence, and an AI-generated (or local, deterministic) executive summary.
              </p>
              <p>
                Every finding, active or passive, ships with a plain-English impact statement, a fix tailored to
                the detected stack, and a ready-to-paste remediation prompt for whatever AI coding agent you hand
                it to.
              </p>
            </Section>

            <Section id="pillars" title="The seven pillars">
              <p className="mb-2">
                Every report is organized into seven AppSec categories. Passive pillars run on any public target;
                active pillars only fire after domain-ownership verification (see below).
              </p>
              <div className="space-y-3 mt-4">
                {PILLARS.map((p) => {
                  const Icon = p.icon;
                  const open = activePillar === p.key;
                  return (
                    <div key={p.key} className="bg-[#0c0c0e] border border-[#27272a] rounded-lg overflow-hidden">
                      <button
                        onClick={() => setActivePillar(open ? null : p.key)}
                        className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left cursor-pointer hover:bg-black/30 transition-colors"
                        aria-expanded={open}
                      >
                        <div className="flex items-center space-x-3">
                          <Icon className="w-4 h-4 text-[#22c55e] shrink-0" aria-hidden="true" />
                          <span className="text-white text-xs font-mono font-bold">{p.key}</span>
                          <span className="text-[#71717a] text-xs font-mono hidden sm:inline">{p.name}</span>
                        </div>
                        <span className="text-[9px] font-mono uppercase tracking-wider text-[#52525b] border border-[#27272a] rounded px-2 py-0.5 shrink-0">{p.mode}</span>
                      </button>
                      {open && (
                        <div className="px-5 pb-5 pt-0 space-y-3 animate-fade-in">
                          <p className="text-xs"><span className="text-[#22c55e] uppercase tracking-wider text-[10px] block mb-1">What it checks</span>{p.what}</p>
                          <p className="text-xs"><span className="text-[#22c55e] uppercase tracking-wider text-[10px] block mb-1">Why it matters</span>{p.why}</p>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </Section>

            <Section id="evidence" title="PROVEN vs DETECTED">
              <p>
                Every active finding carries one of two evidence tiers, and the label is never asserted without
                backing:
              </p>
              <p>
                <strong className="text-white">PROVEN</strong> — the exploit was demonstrated end-to-end and
                Seclayer captured a replayable receipt: the real request sent, the real response received, and
                the exact bytes that prove it, quoted verbatim. A blind, out-of-band SSRF is proven the same way
                — Seclayer runs its own collaborator endpoint and a real callback from the target is the receipt.
              </p>
              <p>
                <strong className="text-white">DETECTED</strong> — a real signal was observed that's worth
                reporting, but wasn't (or couldn't be) demonstrated end-to-end. It's not a demotion or a lesser
                finding; it's the honest badge for what was actually seen.
              </p>
              <p>
                This is the mechanism behind the low-false-positive promise: a finding only wears the strongest
                label when there's a receipt to back it up.
              </p>
            </Section>

            <Section id="ownership" title="Domain ownership verification">
              <p>
                Passive recon runs against any public URL you submit. Active exploitation — every probe in RED_TEAM
                and API_SEC, plus active fuzzing in DAST — stays locked until you prove you control the target
                domain, via either a DNS TXT record or a file at a well-known path on the target host, each
                containing a token Seclayer generates for that verification attempt.
              </p>
              <p>
                This exists for one reason: without it, Seclayer would be a ready-made anonymous attack proxy
                against any site on the internet. With it, active exploitation only ever runs against
                infrastructure someone has demonstrated they own.
              </p>
            </Section>

            <Section id="scoring" title="Scoring & grading">
              <p>
                Every scan gets a 0–100 posture score and a letter grade (A/B/C/D/F), derived from one shared
                module so the number, the grade, and every risk label on the report always agree with each other.
              </p>
              <p>
                Severity drives the deduction (critical hits hardest, then high, medium, low; info-level findings
                never affect the score), but the deduction is weighted by evidence: a CONFIRMED finding — a real
                exploit receipt, or a high-confidence direct observation — always deducts its full weight. An
                unconfirmed, heuristic-only finding is damped by its confidence, and a whole pile of heuristics
                alone is capped from ever driving the grade past a D on their own.
              </p>
              <p>
                One more rule sits on top: the grade is anchored to the worst CONFIRMED severity on the report. A
                single proven critical always fails the grade, no matter how clean everything else scores — a real
                vulnerability can never be diluted away by a good average.
              </p>
            </Section>

            <Section id="network-recon" title="Network Reconnaissance (nmap)">
              <p className="flex items-center gap-2 text-white">
                <Radar className="w-4 h-4 text-[#22c55e]" aria-hidden="true" />
                <span>A fully independent scan, separate from the seven pillars above.</span>
              </p>
              <p>
                Network Reconnaissance runs a real, full-depth nmap sweep of a verified target — every port,
                service and version fingerprint, an OS guess, and NSE vulnerability-script results — as its own
                scan type, with its own history. It never touches the seven AppSec pillars, and it never affects
                your 0–100 posture score: the two are structurally kept apart end to end.
              </p>
              <p>
                It shares the same domain-ownership verification gate as the RED_TEAM and API_SEC pillars — no
                separate authorization step to learn. Vulnerability-script hits are always shown as{' '}
                <strong className="text-white">DETECTED</strong>, the same evidence tier used everywhere else on
                the report for a real signal that wasn't demonstrated end-to-end: nmap's NSE scripts match on
                service banners and version strings, which is a strong signal, not a replayable exploit receipt.
              </p>
              <p>
                Self-hosted only. Nmap is a real system binary, not something a serverless platform can run, so
                this capability is only present when Seclayer is deployed via the included Docker image — it's
                cleanly absent everywhere else, including the hosted seclayer.io, with no error and no broken UI.
              </p>
            </Section>

            <Section id="ai-reports" title="AI-generated reports">
              <p>
                Every scan produces a complete executive summary out of the box, generated locally and
                deterministically from the actual findings — no AI key required, and nothing about the report's
                accuracy depends on one.
              </p>
              <p>
                If you add your own DeepSeek API key (billed to your own DeepSeek account), Seclayer upgrades the
                executive summary and live scan narration to a fuller AI-generated report. It's strictly an
                upgrade to presentation, never a requirement to get a real, actionable report.
              </p>
            </Section>

            <Section id="mcp-api" title="MCP & API access">
              <p>
                Seclayer runs on the same scanning core behind three surfaces: the web dashboard, a plain HTTP API,
                and a standard stdio Model Context Protocol (MCP) server — usable from Cursor, Claude Code,
                Windsurf, or any other MCP-compatible client.
              </p>
              <p>
                Generate an API key from the console, wire it into your agent's MCP config or call the HTTP API
                directly, and trigger a scan or read back a report in natural language — the same evidence-backed
                output as the dashboard, whichever surface asked for it.
              </p>
            </Section>

            <Section id="data" title="Data handling & privacy">
              <p>
                Scan reports, findings, and evidence receipts belong to your account and are private by default —
                nobody else can see them. You can optionally mint a read-only public share link for one specific
                report; it exposes only that report, never your account or scan history, and you can revoke it at
                any time.
              </p>
              <p>
                If you generate a developer API key, the raw secret is shown exactly once at creation and is never
                retrievable again — only a masked preview is stored. A personal DeepSeek key, if you add one, is
                stored to generate your reports and is never displayed back to you in full.
              </p>
            </Section>

            <Section id="closed-source" title="Why closed source">
              <p>
                Seclayer shares its scanning and scoring engine with an open passive-only sibling project, but the
                active-exploitation modules stay closed. The reasoning is narrow and specific: those modules are
                real, working exploit code. Publishing the exact detection signatures, payload lists, and timing
                thresholds would do two harmful things at once — teach a target how to evade detection, and hand
                out an offensive toolkit that no longer requires going through the ownership-verification gate.
              </p>
              <p>
                Everything else about how the product works — what each module checks, why, how evidence and
                scoring are derived, what's gated and why — is documented here in full. Closed source is about
                protecting the exploit mechanics specifically, not about opacity everywhere else.
              </p>
            </Section>

            <Section id="safety" title="Safety & responsible use">
              <p>
                Only scan targets you own or are explicitly authorized to test. Active exploitation is gated behind
                domain-ownership verification for exactly this reason, but that gate is a technical backstop, not a
                substitute for authorization — running any penetration test, active or passive, against
                infrastructure you don't have permission to test can violate the law and the target's terms of
                service regardless of what any tool allows you to click.
              </p>
            </Section>
          </div>
        </div>
      </div>
    </div>
  );
}
