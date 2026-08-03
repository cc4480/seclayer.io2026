import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

// Answers are kept factually anchored to what the product actually does (see
// docs/prd.md + the /docs page) — no invented capabilities, no vanity numbers.
const FAQS: { q: string; a: string }[] = [
  {
    q: 'What does Seclayer actually do?',
    a: 'Point it at a public URL and it runs a real black-box penetration test — HTTP probes, DNS and attack-surface recon, and (once you prove you own the target) live exploit attempts across seven AppSec categories. You get back a plain-English report with a posture score, an impact statement per finding, a stack-tailored fix, and a ready-to-paste prompt for your AI coding agent.',
  },
  {
    q: 'Is it safe or legal to scan a site I don’t own?',
    a: 'Passive checks (headers, DNS, tech fingerprinting, exposed-secret scanning) run against any public URL. Active exploitation — SQL injection, XSS, command injection, SSRF, BOLA probes, and the rest of the red-team suite — only unlocks once you prove ownership of the target’s domain via a DNS TXT record or a well-known file. That gate is what stops the platform being used as an anonymous attack proxy against a site you don’t control.',
  },
  {
    q: 'What’s the difference between a PROVEN and a DETECTED finding?',
    a: 'PROVEN means the exploit was demonstrated end-to-end and Seclayer captured a replayable receipt — the exact request and response, with the proof quoted verbatim from what came back. DETECTED means a real signal was observed that’s worth reporting, but wasn’t demonstrated end-to-end. Both are real and both count toward your score — PROVEN just wears a badge it can back up with evidence.',
  },
  {
    q: 'Do I need a DeepSeek API key?',
    a: 'No. Every scan ships a complete report with a real, deterministic local summary — no AI key required. Add your own DeepSeek key, billed to your own DeepSeek account, if you want a deeper AI-generated executive narrative and live scan commentary. It’s an upgrade, never a requirement.',
  },
  {
    q: 'What happens to my scan data — is it private?',
    a: 'Scan reports are private to your account by default. You can optionally mint a read-only public share link for one specific report and revoke it at any time; a share link only ever exposes that single report, never your account or scan history.',
  },
  {
    q: 'Why is Seclayer closed source?',
    a: 'The active-exploitation modules are real, working exploit probes. Publishing the exact detection signatures and payload logic would hand attackers a manual for evading detection, or a ready-made offensive toolkit outside the ownership-verification gate. See the Documentation page for a detailed, honest account of what each module checks and why — it stops short of the literal payloads and signatures.',
  },
  {
    q: 'Do scan credits expire?',
    a: 'No — purchased credits never expire, and each scan consumes exactly one. During the current free beta, every scan is free and doesn’t consume a credit at all.',
  },
  {
    q: 'Can I run Seclayer from my AI coding agent?',
    a: 'Yes. Seclayer ships as a standard stdio MCP server — works the same in Cursor, Claude Code, Windsurf, or any MCP-compatible client — alongside the web dashboard and a plain HTTP API. Generate an API key from the console and your agent can trigger a scan and read the report in natural language before you deploy.',
  },
  {
    q: 'How is this different from a generic vulnerability scanner?',
    a: 'Most scanners produce a wall of theoretical findings from a checklist and leave you to verify each one. Seclayer confirms every finding against a real signature match — and where possible, a live exploit receipt — so what you get is precision over noise: fewer findings, but ones you can trust and act on immediately.',
  },
  {
    q: 'What if I disagree with a finding?',
    a: 'Mark it as a false positive directly from the report, with a reason. It’s excluded from your score and severity immediately, and Seclayer won’t resurface it on future scans of the same target.',
  },
];

export default function FaqSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  return (
    <div id="faq" className="max-w-4xl mx-auto py-24 px-6 scroll-mt-20">
      <div className="text-center mb-12">
        <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">Frequently Asked Questions</p>
        <h2 className="text-3xl font-mono tracking-tighter font-bold text-white">What people ask before their first scan</h2>
        <p className="text-[#a1a1aa] text-xs font-mono mt-3 max-w-md mx-auto">
          Read the full <a href="/docs" className="text-[#22c55e] hover:underline">Documentation</a> for how each scan module actually works.
        </p>
      </div>

      <div className="space-y-3">
        {FAQS.map((item, i) => {
          const open = openIndex === i;
          return (
            <div key={item.q} className="bg-[#0c0c0e] border border-[#27272a] rounded-lg overflow-hidden">
              <button
                onClick={() => setOpenIndex(open ? null : i)}
                className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left cursor-pointer hover:bg-black/30 transition-colors"
                aria-expanded={open}
              >
                <span className="text-white text-xs sm:text-sm font-mono font-bold">{item.q}</span>
                <ChevronDown className={`w-4 h-4 text-[#52525b] shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden="true" />
              </button>
              {open && (
                <div className="px-5 pb-5 pt-0 animate-fade-in">
                  <p className="text-[#a1a1aa] text-xs font-mono leading-relaxed">{item.a}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* FAQPage structured data — the same Q&A shown above, so search engines
          can render a rich-result snippet from content that's actually on the page. */}
      <script
        type="application/ld+json"
        // eslint-disable-next-line react/no-danger
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            '@context': 'https://schema.org',
            '@type': 'FAQPage',
            mainEntity: FAQS.map((item) => ({
              '@type': 'Question',
              name: item.q,
              acceptedAnswer: { '@type': 'Answer', text: item.a },
            })),
          }),
        }}
      />
    </div>
  );
}
