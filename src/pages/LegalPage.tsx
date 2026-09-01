import React from 'react';
import { ArrowLeft, Shield, FileText } from 'lucide-react';

// Privacy Policy and Terms of Service, rendered from one component because they
// share a layout and differ only in content. Both are real, indexable pages at
// stable paths (/privacy, /terms) rather than anchors inside the docs: Google's
// OAuth consent screen requires a reachable privacy-policy URL, and linking an
// anchor into a larger page is both weaker legally and fragile if the docs are
// reorganized.
//
// Deliberately plain: these are read, not marketed at.

interface LegalPageProps {
  kind: 'privacy' | 'terms';
  onNavigate: (view: string, arg?: string) => void;
}

const LAST_UPDATED = 'September 1, 2026';
const CONTACT = 'c.c4480131515@gmail.com';

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="py-8 border-b border-[#27272a] last:border-b-0">
      <h2 className="text-lg sm:text-xl font-mono font-bold tracking-tight text-white mb-4">{title}</h2>
      <div className="space-y-4 text-[#a1a1aa] text-sm font-sans leading-relaxed">{children}</div>
    </section>
  );
}

function Privacy() {
  return (
    <>
      <Section title="What this covers">
        <p>
          Seclayer is a black-box security scanner. You give it a URL, it probes that target from the
          outside and returns a report. This policy explains what we store to make that work, and what
          we do not.
        </p>
      </Section>

      <Section title="What we collect">
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong className="text-zinc-200">Your email address.</strong> Sign-in is passwordless — either a
            one-time link emailed to you, or Sign in with Google. We never receive or store a password.
            When you sign in with Google we receive only your email address and basic profile information;
            we do not get access to your Google account, Gmail, Drive, or contacts.
          </li>
          <li>
            <strong className="text-zinc-200">Scan data.</strong> The target URLs you submit, the findings
            produced, and the evidence supporting them (request/response excerpts captured from the target).
          </li>
          <li>
            <strong className="text-zinc-200">Account records.</strong> Credit balance, transactions, API keys
            (stored hashed — the raw value is shown once at creation and never again), and domain-ownership
            verifications.
          </li>
          <li>
            <strong className="text-zinc-200">Server logs.</strong> Standard request logs including IP address,
            used to operate the service and enforce rate limits.
          </li>
        </ul>
      </Section>

      <Section title="What we do not do">
        <ul className="list-disc pl-5 space-y-2">
          <li>We do not sell or rent your data.</li>
          <li>We do not use your scan data to advertise to you.</li>
          <li>We do not share reports with other users. Reports are private to your account by default.</li>
        </ul>
      </Section>

      <Section title="Third parties we send data to">
        <p>Operating the service means a few processors necessarily see some data:</p>
        <ul className="list-disc pl-5 space-y-2">
          <li><strong className="text-zinc-200">Railway</strong> — hosting and infrastructure.</li>
          <li><strong className="text-zinc-200">Resend</strong> — delivers sign-in emails. Receives your email address.</li>
          <li><strong className="text-zinc-200">DeepSeek</strong> — writes the report narrative. Receives the scan findings for the report being generated. It does not receive your email address or account details.</li>
          <li><strong className="text-zinc-200">Google</strong> — only if you choose Sign in with Google.</li>
          <li><strong className="text-zinc-200">Stripe</strong> — only if credit purchases are enabled. Card details go to Stripe directly; we never see or store them.</li>
        </ul>
      </Section>

      <Section title="Share links">
        <p>
          You can mint a read-only public link for a single report. Anyone with that link can read that one
          report — it exposes nothing else about your account or scan history. You can revoke it at any time,
          and no share link exists unless you create one.
        </p>
      </Section>

      <Section title="Retention and deletion">
        <p>
          Scans and account records are kept until you delete them or ask us to close your account. Sign-in
          links expire after 15 minutes and can be used once. Sessions expire after 30 days.
        </p>
        <p>
          To delete your account and its data, email{' '}
          <a href={`mailto:${CONTACT}`} className="text-[#22c55e] hover:underline">{CONTACT}</a> from the
          address on the account.
        </p>
      </Section>

      <Section title="Your rights">
        <p>
          You can request a copy of your data, correction of it, or its deletion, by emailing{' '}
          <a href={`mailto:${CONTACT}`} className="text-[#22c55e] hover:underline">{CONTACT}</a>. If you are in
          the EEA or UK, the GDPR gives you these rights explicitly; we honour the same requests regardless of
          where you are.
        </p>
      </Section>

      <Section title="Changes">
        <p>
          If this policy changes materially, we will update the date at the top of this page. Continuing to use
          Seclayer after a change means the updated policy applies.
        </p>
      </Section>
    </>
  );
}

function Terms() {
  return (
    <>
      <Section title="The agreement">
        <p>
          By using Seclayer you agree to these terms. If you are using it for an organization, you are
          confirming you have authority to accept on its behalf.
        </p>
      </Section>

      <Section title="Only scan what you are allowed to scan">
        <p className="text-zinc-200">
          This is the most important term on this page.
        </p>
        <p>
          Seclayer sends real traffic — including active exploit probes — at whatever target you point it at.
          You may only scan systems you own or have explicit, documented permission to test. Scanning a system
          without authorization is illegal in most jurisdictions, including under the Computer Fraud and Abuse
          Act in the United States and the Computer Misuse Act in the United Kingdom.
        </p>
        <p>
          Because of this, active exploit probing is gated: it only runs against a domain once you have proven
          ownership of it through DNS or a well-known file. Unverified targets get passive reconnaissance only.
          Do not attempt to circumvent that gate.
        </p>
        <p>
          You are solely responsible for the targets you submit and for any consequences of scanning them. You
          agree to indemnify us against claims arising from targets you were not authorized to test.
        </p>
      </Section>

      <Section title="What the service does and does not promise">
        <p>
          Seclayer reports what its probes could observe from outside the target at the time of the scan. A
          clean report is evidence that these specific checks did not find these specific issues — it is not a
          guarantee that a system is secure, and it is not a substitute for a manual penetration test, a code
          audit, or a compliance assessment.
        </p>
        <p>
          Findings may include false positives, and absence of a finding is not proof of absence of a
          vulnerability. Act on reports with judgment.
        </p>
      </Section>

      <Section title="Acceptable use">
        <ul className="list-disc pl-5 space-y-2">
          <li>Do not use Seclayer to attack, disrupt, or degrade any system.</li>
          <li>Do not use it as a proxy to obscure the origin of traffic you send at third parties.</li>
          <li>Do not attempt to break out of, overload, or reverse-engineer the service itself.</li>
          <li>Do not share your API key. It carries your account's authority and credits.</li>
        </ul>
        <p>We may suspend or terminate an account that violates these terms, without refund.</p>
      </Section>

      <Section title="Credits and payment">
        <p>
          Where payment is enabled, scans consume credits purchased in advance. Credits are not refundable
          except where required by law, and do not expire while the account is open. A scan that fails for a
          reason on our side is refunded automatically.
        </p>
        <p>During free beta, scans consume no credits and nothing is charged.</p>
      </Section>

      <Section title="Availability">
        <p>
          The service is provided as-is, without any warranty. We do not promise it will be uninterrupted or
          error-free, and we may change or discontinue features. To the maximum extent permitted by law, our
          total liability to you for any claim relating to the service is limited to the amount you paid us in
          the twelve months before the claim.
        </p>
      </Section>

      <Section title="Your content">
        <p>
          You keep ownership of your scan data and reports. You grant us only the permission needed to operate
          the service — storing your reports, and processing findings to generate the written analysis.
        </p>
      </Section>

      <Section title="Changes and contact">
        <p>
          We may update these terms; the date at the top of this page reflects the last change. Questions go to{' '}
          <a href={`mailto:${CONTACT}`} className="text-[#22c55e] hover:underline">{CONTACT}</a>.
        </p>
      </Section>
    </>
  );
}

export default function LegalPage({ kind, onNavigate }: LegalPageProps) {
  const isPrivacy = kind === 'privacy';
  const Icon = isPrivacy ? Shield : FileText;

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa]">
      <div className="max-w-3xl mx-auto px-6 py-16">
        <button
          onClick={() => onNavigate('landing')}
          className="flex items-center space-x-2 text-[#52525b] hover:text-[#22c55e] text-xs font-mono uppercase tracking-widest mb-8 cursor-pointer transition-colors"
          id="legal-back-home"
        >
          <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
          <span>Back home</span>
        </button>

        <div className="flex items-center space-x-3 mb-2">
          <div className="p-2 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e]">
            <Icon className="w-5 h-5" aria-hidden="true" />
          </div>
          <h1 className="text-2xl sm:text-3xl font-mono font-bold tracking-tight text-white">
            {isPrivacy ? 'Privacy Policy' : 'Terms of Service'}
          </h1>
        </div>
        <p className="text-[#52525b] text-xs font-mono mb-4">Last updated: {LAST_UPDATED}</p>

        <div className="mb-8">
          <button
            onClick={() => onNavigate(isPrivacy ? 'terms' : 'privacy')}
            className="text-[#22c55e] hover:underline text-xs font-mono cursor-pointer"
          >
            {isPrivacy ? 'Read the Terms of Service →' : 'Read the Privacy Policy →'}
          </button>
        </div>

        {isPrivacy ? <Privacy /> : <Terms />}
      </div>
    </div>
  );
}
