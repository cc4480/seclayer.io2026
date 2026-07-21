import { useState, useEffect } from 'react';

// Domain-ownership verification for the scan launcher. Active exploit probing
// (SQLi/XSS/SSRF/etc.) only runs once a domain is verified — via DNS/file proof
// or an explicit authorization attestation; unverified targets still get a full
// passive scan. Enforcement is server-side; this is the UX around it. Derives
// the "current domain" from the live scan-URL input.
export function useDomainVerification(scanUrl: string, userId: string) {
  const [domainVerifications, setDomainVerifications] = useState<any[]>([]);
  const [verifyInfo, setVerifyInfo] = useState<any | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState('');

  const fetchDomainVerifications = async () => {
    try {
      const res = await fetch('/api/domains');
      if (res.ok) {
        const data = await res.json();
        setDomainVerifications(data.domains || []);
      }
    } catch (err) {
      console.error('Error loading domain verifications:', err);
    }
  };

  useEffect(() => {
    fetchDomainVerifications();
  }, [userId]);

  const currentDomain = (() => {
    const trimmed = scanUrl.trim();
    if (!trimmed) return '';
    try {
      const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      return new URL(withScheme).hostname.toLowerCase();
    } catch {
      return '';
    }
  })();

  const currentDomainVerified = domainVerifications.some((d) => d.domain === currentDomain && d.verified);

  const handleStartVerification = async () => {
    if (!currentDomain) return;
    setIsVerifying(true);
    setVerifyError('');
    try {
      const res = await fetch('/api/domains/verify/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl.trim() })
      });
      const data = await res.json();
      if (res.ok) {
        setVerifyInfo(data);
        if (data.verified) fetchDomainVerifications();
      } else {
        setVerifyError(data.message || 'Could not start verification.');
      }
    } catch {
      setVerifyError('Could not start verification.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleCheckVerification = async () => {
    if (!currentDomain) return;
    setIsVerifying(true);
    setVerifyError('');
    try {
      const res = await fetch('/api/domains/verify/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl.trim() })
      });
      const data = await res.json();
      if (res.ok && data.verified) {
        setVerifyInfo(null);
        fetchDomainVerifications();
      } else {
        setVerifyError(data.message || 'Verification not detected yet.');
      }
    } catch {
      setVerifyError('Could not check verification.');
    } finally {
      setIsVerifying(false);
    }
  };

  // Attestation path: the user explicitly affirms authorization (recorded
  // server-side) instead of proving control via DNS/file. window.confirm forces
  // a deliberate acknowledgement before active probes are unlocked. Returns true
  // when the domain is (now) authorized for active testing.
  const attestCurrentDomain = async (): Promise<boolean> => {
    if (!currentDomain) return false;
    if (currentDomainVerified) return true;
    const ok = window.confirm(
      `Authorize ACTIVE security testing of ${currentDomain}?\n\n` +
      `I attest that I own, or am explicitly authorized by the owner to perform active ` +
      `security testing (including exploit probes such as SQLi / XSS / SSRF) against ${currentDomain}.\n\n` +
      `This acknowledgement is recorded. Only proceed if you have authorization — testing a ` +
      `domain you don't control may be illegal.`
    );
    if (!ok) return false;
    setIsVerifying(true);
    setVerifyError('');
    try {
      const res = await fetch('/api/domains/verify/acknowledge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl.trim(), acknowledged: true })
      });
      const data = await res.json();
      if (res.ok && data.verified) {
        setVerifyInfo(null);
        fetchDomainVerifications();
        return true;
      }
      setVerifyError(data.message || 'Could not record acknowledgement.');
      return false;
    } catch {
      setVerifyError('Could not record acknowledgement.');
      return false;
    } finally {
      setIsVerifying(false);
    }
  };
  const handleAcknowledgeVerification = () => { void attestCurrentDomain(); };

  return {
    verifyInfo, isVerifying, verifyError, setVerifyError,
    currentDomain, currentDomainVerified,
    handleStartVerification, handleCheckVerification, attestCurrentDomain, handleAcknowledgeVerification,
  };
}
