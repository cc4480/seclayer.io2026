import { useState, useEffect } from 'react';

// Domain-ownership verification for the scan launcher. Active exploit probing
// (SQLi/XSS/SSRF/etc.) only runs once a domain is verified via DNS TXT record
// or well-known file; unverified targets still get a full passive scan.
// Enforcement is server-side; this is the UX around it. Derives the "current
// domain" from the live scan-URL input.
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

  return {
    verifyInfo, isVerifying, verifyError, setVerifyError,
    currentDomain, currentDomainVerified,
    handleStartVerification, handleCheckVerification,
  };
}
