import { useState } from 'react';
import { Scan, Finding } from '../types.js';

// False-positive suppression for a scan's findings: the inline "mark as false
// positive" form state plus the save/remove handlers that talk to the
// suppression API. Extracted from ReportViewer so the component keeps only view
// concerns.
export function useSuppression(scan: Scan, onRefreshScans?: () => void) {
  const [suppressInputId, setSuppressInputId] = useState<string | null>(null);
  const [suppressReason, setSuppressReason] = useState('');
  const [isSuppressing, setIsSuppressing] = useState(false);
  const [suppressError, setSuppressError] = useState<string | null>(null);

  const handleSaveSuppression = async (finding: Finding) => {
    setIsSuppressing(true);
    setSuppressError(null);
    try {
      const res = await fetch(`/api/scans/${scan.id}/findings/${finding.id}/suppress`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: suppressReason.trim() || 'Verified acceptable risk / false positive audit confirmation.'
        })
      });
      if (res.ok) {
        setSuppressInputId(null);
        setSuppressReason('');
        if (onRefreshScans) onRefreshScans();
      } else {
        const data = await res.json();
        setSuppressError(data.error || 'Failed to apply suppression rule');
      }
    } catch (err: any) {
      setSuppressError(err.message || 'Network failure applying suppression');
    } finally {
      setIsSuppressing(false);
    }
  };

  const handleRemoveSuppressionDirectly = async (findingTitle: string) => {
    setIsSuppressing(true);
    try {
      const listRes = await fetch(`/api/suppressions`);
      if (!listRes.ok) throw new Error('Could not read exclusion lists');
      const listData = await listRes.json();
      const matchingRule = (listData.suppressions || []).find((s: any) =>
        s.findingTitle === findingTitle &&
        s.targetUrl.toLowerCase().replace(/https?:\/\//i, '').replace(/\/+$/, '') === scan.url.toLowerCase().replace(/https?:\/\//i, '').replace(/\/+$/, '')
      );

      if (!matchingRule) {
        throw new Error('Suppression rule on this target was not found in database.');
      }

      const delRes = await fetch(`/api/suppressions/${matchingRule.id}`, { method: 'DELETE' });
      if (delRes.ok) {
        if (onRefreshScans) onRefreshScans();
      } else {
        const delData = await delRes.json();
        throw new Error(delData.error || 'Failed to remove exclusion rule');
      }
    } catch (err: any) {
      alert(err.message || 'Failed to restore original findings status.');
    } finally {
      setIsSuppressing(false);
    }
  };

  return {
    suppressInputId, setSuppressInputId,
    suppressReason, setSuppressReason,
    isSuppressing, suppressError, setSuppressError,
    handleSaveSuppression, handleRemoveSuppressionDirectly,
  };
}
