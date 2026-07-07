import React, { useState } from 'react';
import { 
  Shield, ArrowLeft, Download, Share2, Clipboard, Globe, 
  Settings, Check, Eye, Code, Terminal, AlertTriangle, 
  ChevronDown, ChevronUp, Clock, FileText, CheckCircle2,
  Zap, Package, Grid, AlertCircle, Sparkles, Server, Copy
} from 'lucide-react';
import { Scan, Finding } from '../types.js';
// Single source of truth for every risk figure/label shown here — the same
// module the server scanner and read-model score from. No risk value or label
// in this component is computed locally; that independent labelling is what let
// the score, pillar counts and banner contradict each other.
import {
  deriveSecurityPosture, riskLabelForSeverity, highestSeverity,
  bannerForPosture, isConfirmed, type RiskLabel,
} from '../../server/scoring.js';
import { SEVERITY_TOKENS, tokenForRiskLabel } from '../lib/severity.js';
import ScoreGauge from '../components/ScoreGauge.js';
import SeverityBar from '../components/SeverityBar.js';
import BrowserFrame from '../components/BrowserFrame.js';
import { jsPDF } from "jspdf";
import autoTable from 'jspdf-autotable';

interface ReportViewerProps {
  scan: Scan;
  previousScan?: Scan;
  onBack: () => void;
  onRefreshScans?: () => void;
}

type SecCategory = 'SAST' | 'DAST' | 'IAST' | 'SCA' | 'EASM' | 'RED_TEAM' | 'API_SEC';

export default function ReportViewer({ scan, previousScan, onBack, onRefreshScans }: ReportViewerProps) {
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | SecCategory>('OVERVIEW');
  const [showRaw, setShowRaw] = useState(false);
  const [showReasoning, setShowReasoning] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  // Suppression and False Positives States
  const [suppressInputId, setSuppressInputId] = useState<string | null>(null);
  const [suppressReason, setSuppressReason] = useState('');
  const [isSuppressing, setIsSuppressing] = useState(false);
  const [suppressError, setSuppressError] = useState<string | null>(null);
  const [expandedApiRows, setExpandedApiRows] = useState<Record<string, boolean>>({});

  const findings = scan.findings || [];
  // Derive the whole posture (score, grade, severity, posture rating, counts)
  // once, from the same shared module the server uses, so every section below
  // renders from one object instead of recomputing risk independently.
  const posture = deriveSecurityPosture(findings);
  const banner = bannerForPosture(findings);

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
        if (onRefreshScans) {
          onRefreshScans();
        }
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

      const delRes = await fetch(`/api/suppressions/${matchingRule.id}`, {
        method: 'DELETE'
      });
      if (delRes.ok) {
        if (onRefreshScans) {
          onRefreshScans();
        }
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

  const handleShareClick = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const handleCopyCode = (findingId: string, fixText: string) => {
    navigator.clipboard.writeText(fixText);
    setCopiedCodeId(findingId);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  const handleDownloadPdf = () => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    
    // Brand header
    doc.setFillColor(9, 9, 11);
    doc.rect(0, 0, pageWidth, 40, 'F');
    
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.text("SECLAYER", 15, 20);
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text("Systematic Penetration Testing & AppSec Report", 15, 28);
    
    doc.setTextColor(161, 161, 170); // text-zinc-400
    doc.text(`Generated: ${new Date().toISOString().split('T')[0]}`, pageWidth - 15, 25, { align: 'right' });
    
    // Executive Summary Info Box
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("EXECUTIVE SUMMARY", 15, 55);
    
    doc.setFontSize(11);
    doc.setFont("helvetica", "normal");
    doc.text(`Target Assessed: ${scan.url}`, 15, 65);
    // Same shared posture as the on-screen report, so the PDF can never disagree
    // with the UI it was exported from.
    doc.text(`Security Posture Score: ${posture.score}/100 (Grade ${posture.grade})`, 15, 72);
    doc.text(`Risk Rating: ${posture.postureRating} (${posture.severity.toUpperCase()})`, 15, 79);
    doc.text(`Total Findings: ${posture.activeCount} (${posture.confirmedCount} confirmed, ${posture.needsVerificationCount} need verification)`, 15, 86);
    
    // AI Summary
    let currentY = 96;
    if (scan.aiSummary) {
      doc.setFont("helvetica", "bold");
      doc.text("Assessment Analysis", 15, currentY);
      doc.setFont("helvetica", "normal");
      currentY += 7;
      const splitAiText = doc.splitTextToSize(scan.aiSummary, pageWidth - 30);
      doc.text(splitAiText, 15, currentY);
      currentY += (splitAiText.length * 5) + 12;
    } else {
      currentY = 100;
    }

    // Detailed executive breakdown (adds a page break first if space is tight)
    if (scan.executiveBreakdown) {
      const eb = scan.executiveBreakdown;
      if (currentY > pageHeight - 60) { doc.addPage(); currentY = 20; }

      doc.setFontSize(13);
      doc.setFont("helvetica", "bold");
      doc.text("DETAILED BREAKDOWN", 15, currentY);
      currentY += 8;

      doc.setFontSize(10);
      doc.setFont("helvetica", "normal");
      const overviewLines = doc.splitTextToSize(eb.overview, pageWidth - 30);
      doc.text(overviewLines, 15, currentY);
      currentY += (overviewLines.length * 5) + 8;

      if (eb.riskAreas.length > 0) {
        if (currentY > pageHeight - 40) { doc.addPage(); currentY = 20; }
        doc.setFont("helvetica", "bold");
        doc.text("Key Risk Areas", 15, currentY);
        currentY += 6;
        doc.setFont("helvetica", "normal");
        for (const r of eb.riskAreas) {
          if (currentY > pageHeight - 20) { doc.addPage(); currentY = 20; }
          const lines = doc.splitTextToSize(`• ${r.area}: ${r.detail}`, pageWidth - 30);
          doc.text(lines, 15, currentY);
          currentY += (lines.length * 5) + 2;
        }
        currentY += 6;
      }

      if (currentY > pageHeight - 40) { doc.addPage(); currentY = 20; }
      doc.setFont("helvetica", "bold");
      doc.text("Business Impact", 15, currentY);
      currentY += 6;
      doc.setFont("helvetica", "normal");
      const impactLines = doc.splitTextToSize(eb.businessImpact, pageWidth - 30);
      doc.text(impactLines, 15, currentY);
      currentY += (impactLines.length * 5) + 8;

      if (eb.priorityActions.length > 0) {
        if (currentY > pageHeight - 40) { doc.addPage(); currentY = 20; }
        doc.setFont("helvetica", "bold");
        doc.text("Priority Actions", 15, currentY);
        currentY += 6;
        doc.setFont("helvetica", "normal");
        eb.priorityActions.forEach((action, idx) => {
          if (currentY > pageHeight - 20) { doc.addPage(); currentY = 20; }
          const lines = doc.splitTextToSize(`${idx + 1}. ${action}`, pageWidth - 30);
          doc.text(lines, 15, currentY);
          currentY += (lines.length * 5) + 2;
        });
        currentY += 10;
      }

      if (currentY > pageHeight - 60) { doc.addPage(); currentY = 20; }
    }

    // Findings Table
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("TECHNICAL FINDINGS & REMEDIATION", 15, currentY);
    
    const tableBody = findings.map((f, i) => [
      i + 1,
      f.title,
      f.severity.toUpperCase(),
      f.category,
      f.description,
      f.fix
    ]);
    
    autoTable(doc, {
      startY: currentY + 5,
      head: [['#', 'Vulnerability', 'Severity', 'Module', 'Description', 'Remediation']],
      body: tableBody,
      theme: 'grid',
      styles: { fontSize: 8, cellPadding: 3 },
      headStyles: { fillColor: [9, 9, 11], textColor: [255, 255, 255] },
      columnStyles: {
        0: { cellWidth: 10 },
        1: { cellWidth: 35 },
        2: { cellWidth: 20 },
        3: { cellWidth: 20 },
        4: { cellWidth: 55 },
        5: { cellWidth: 50 },
      },
      didParseCell: function(data) {
        if (data.section === 'body' && data.column.index === 2) {
          // just standard formatting here, custom styles can be complex in some autotable versions, so we use string values
        }
      }
    });
    
    // Page footer
    const pageCount = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(150, 150, 150);
        doc.text(`Page ${i} of ${pageCount} - Private & Confidential - Enterprise Security Audit Document`, pageWidth / 2, pageHeight - 10, { align: 'center' });
    }
    
    doc.save(`seclayer-appsec-audit-${scan.url.replace(/https?:\/\//i, '').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`);
  };

  // Colour keyed off SEVERITY (not ad-hoc score thresholds) so a colour can
  // never contradict the posture rating. Shared by the executive score card and
  // the pillar cards.
  const severityColorClass = (label: RiskLabel) => {
    if (label === 'CRITICAL' || label === 'HIGH RISK') return 'text-red-400 border-red-500/20 bg-red-500/5';
    if (label === 'MODERATE') return 'text-amber-400 border-amber-500/20 bg-amber-500/5';
    if (label === 'LOW RISK') return 'text-blue-400 border-blue-500/20 bg-blue-500/5';
    if (label === 'INFO') return 'text-zinc-300 border-zinc-500/20 bg-zinc-500/5';
    return 'text-[#22c55e] border-[#22c55e]/25 bg-[#22c55e]/5'; // SECURE
  };

  const getCategoryCount = (cat: SecCategory) => {
    return findings.filter(f => f.category === cat && !f.isFalsePositive).length;
  };

  // Per-pillar label, derived from the SAME shared severity model as everything
  // else — an info-only category reads "INFO", never "LOW RISK".
  const getCategorySeverity = (cat: SecCategory): RiskLabel => {
    const catFindings = findings.filter(f => f.category === cat);
    return riskLabelForSeverity(highestSeverity(catFindings));
  };

  const getCategoryColor = (cat: SecCategory) => severityColorClass(getCategorySeverity(cat));

  const categoryTabLabels = [
    { key: 'SAST' as const, label: 'SAST', icon: Code, term: 'Static Analysis' },
    { key: 'DAST' as const, label: 'DAST', icon: Globe, term: 'Dynamic Audit' },
    { key: 'IAST' as const, label: 'IAST', icon: Zap, term: 'Interactive Policies' },
    { key: 'SCA' as const, label: 'SCA', icon: Package, term: 'Composition Review' },
    { key: 'EASM' as const, label: 'EASM', icon: Grid, term: 'Attack Surface' },
    { key: 'API_SEC' as const, label: 'API SEC', icon: Server, term: 'API Security Testing' },
    { key: 'RED_TEAM' as const, label: 'RED TEAM', icon: Terminal, term: 'Red Team Active Probes' },
  ];

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-5xl mx-auto space-y-8 animate-fade-in">
        
        {/* Navigation Action Header */}
        <div className="flex items-center justify-between">
          <button
            onClick={onBack}
            className="flex items-center space-x-2 text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider transition-colors cursor-pointer"
            id="report-back-btn"
          >
            <ArrowLeft className="w-4 h-4 text-[#22c55e]" />
            <span>Audit Workspace</span>
          </button>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleShareClick}
              className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
              id="report-share-btn"
            >
              {copiedLink ? <Check className="w-3.5 h-3.5 text-[#22c55e]" /> : <Share2 className="w-3.5 h-3.5 text-[#52525b]" />}
              <span>{copiedLink ? 'Copied' : 'Share Link'}</span>
            </button>
            <button
              onClick={handleDownloadPdf}
              className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
              id="report-download-btn"
            >
              <Download className="w-3.5 h-3.5 text-[#52525b]" />
              <span>Export Audit Findings</span>
            </button>
          </div>
        </div>

        {/* Audit Meta Summary Card */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden shadow-2xl">
          <div className="bg-black/40 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-[#27272a]">
            <div>
              <div className="flex items-center space-x-2.5">
                <span className="font-mono text-xs text-[#52525b] select-none">[Target Host]</span>
                <strong className="font-mono text-sm text-white tracking-wide break-all select-all">{scan.url}</strong>
              </div>
              <p className="text-[#52525b] text-xs mt-2 font-mono flex items-center space-x-4">
                <span className="flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5 text-[#52525b]" />
                  <span>Assessed: {new Date(scan.createdAt).toLocaleDateString()}</span>
                </span>
                <span>•</span>
                <span>Job ID: {scan.id}</span>
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 shrink-0">
              {previousScan && (
                <div className="p-4 rounded border border-zinc-800 bg-black flex items-center space-x-5 h-full">
                  <div className="text-right">
                    <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Score Delta</span>
                    <span className={`text-xl font-mono font-black block mt-1 ${scan.score > previousScan.score ? 'text-green-500' : scan.score < previousScan.score ? 'text-red-500' : 'text-zinc-500'}`}>
                      {scan.score > previousScan.score ? '+' : ''}{scan.score - previousScan.score}
                    </span>
                  </div>
                  <div className="border-l border-zinc-800 pl-4 text-right">
                    <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Findings Delta</span>
                    <span className={`text-xl font-mono font-black block mt-1 ${findings.length < previousScan.findings!.length ? 'text-green-500' : findings.length > previousScan.findings!.length ? 'text-amber-500' : 'text-zinc-500'}`}>
                      {findings.length > previousScan.findings!.length ? '+' : ''}{findings.length - previousScan.findings!.length}
                    </span>
                  </div>
                </div>
              )}
              <div className="p-4 rounded-lg border border-[#27272a] bg-black/30 flex items-center gap-5 h-full shrink-0">
                <ScoreGauge score={posture.score} grade={posture.grade} size={124} />
                <div className="border-l border-[#27272a] pl-5 space-y-3">
                  <div>
                    <span className="text-[10px] font-mono text-[#71717a] uppercase block tracking-wider select-none">Posture Rating</span>
                    <span className={`text-sm font-bold uppercase tracking-wider block mt-1 ${tokenForRiskLabel(posture.postureRating).text}`}>{posture.postureRating}</span>
                  </div>
                  <div>
                    <span className="text-[10px] font-mono text-[#71717a] uppercase block tracking-wider select-none mb-1.5">Findings</span>
                    <SeverityBar counts={posture.findingsBySeverity} className="w-32" />
                    <span className="text-[10px] font-mono text-[#71717a] mt-1.5 block">
                      {posture.activeCount === 0 ? 'None found' : `${posture.confirmedCount} confirmed · ${posture.needsVerificationCount} to verify`}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Core AppSec Framework Segmented Matrix tabs */}
          <div className="flex overflow-x-auto border-b border-[#27272a] bg-black/20 select-none scrollbar-none">
            <button
              onClick={() => setActiveTab('OVERVIEW')}
              className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider font-semibold transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
                activeTab === 'OVERVIEW' 
                  ? 'border-[#22c55e] text-white bg-black/40' 
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              <Shield className="w-4 h-4 text-[#22c55e]" />
              <span>Executive Overview</span>
            </button>

            {categoryTabLabels.map(cat => {
              const count = getCategoryCount(cat.key);
              const label = getCategorySeverity(cat.key);
              // Colour the count by real severity, not merely "count > 0", so an
              // info-only pillar doesn't glow red like a critical one.
              const alertBadge = label === 'CRITICAL' || label === 'HIGH RISK'
                ? 'bg-red-500/10 text-red-400 border border-red-500/25'
                : label === 'MODERATE'
                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/25'
                : label === 'LOW RISK'
                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/25'
                : label === 'INFO'
                ? 'bg-zinc-500/10 text-zinc-300 border border-zinc-500/25'
                : 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25';
              return (
                <button
                  key={cat.key}
                  onClick={() => setActiveTab(cat.key)}
                  className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
                    activeTab === cat.key 
                      ? 'border-[#22c55e] text-white bg-black/40' 
                      : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
                  }`}
                >
                  <cat.icon className={`w-4 h-4 ${activeTab === cat.key ? 'text-[#22c55e]' : 'text-[#52525b]'}`} />
                  <span className="font-bold">{cat.label}</span>
                  <span className={`text-[10px] px-1.5 py-0.2 ml-1 rounded font-mono ${alertBadge}`}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="p-6">
            
            {/* OVERVIEW TAB RENDERER */}
            {activeTab === 'OVERVIEW' && (
              <div className="space-y-6 animate-fade-in">
                
                {/* Executive Assessment summary */}
                <div className="bg-black/40 p-5 rounded border border-[#27272a] relative">
                  <div className="absolute right-4 top-4 font-mono text-[9px] text-[#22c55e] uppercase border border-[#22c55e]/30 px-2 py-0.5 rounded flex items-center space-x-1 select-none">
                    <Sparkles className="w-3 h-3" />
                    <span>DeepSeek AI Analyst Verified</span>
                  </div>
                  <h3 className="text-xs font-bold font-mono text-white mb-2 uppercase tracking-wider flex items-center space-x-1.5">
                    <span>Executive Summary</span>
                  </h3>
                  <p className="text-zinc-200 text-[13px] font-sans leading-relaxed prose-invert">
                    {scan.aiSummary || 'Security pipeline completed. Report compiles diagnostics...'}
                  </p>

                  {scan.aiReasoning && (
                    <div className="mt-4 pt-3 border-t border-[#27272a]/60">
                      <button
                        onClick={() => setShowReasoning(!showReasoning)}
                        className="w-full flex items-center justify-between text-[#71717a] hover:text-white font-mono text-[10px] uppercase tracking-wider cursor-pointer"
                      >
                        <span className="flex items-center space-x-1.5">
                          <Sparkles className="w-3 h-3 text-purple-300" />
                          <span>How the AI assessed this (chain-of-thought)</span>
                        </span>
                        {showReasoning ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </button>
                      {showReasoning && (
                        <div className="mt-2.5 p-3 bg-black/60 border border-[#27272a] rounded max-h-72 overflow-y-auto scrollbar-thin animate-fade-in">
                          <code className="text-[10px] font-mono whitespace-pre-wrap leading-relaxed text-zinc-400">
                            {scan.aiReasoning}
                          </code>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Detailed executive breakdown — DeepSeek's deeper, structured
                    analysis, distinct from the headline summary above. */}
                {scan.executiveBreakdown && (
                  <div className="bg-black/40 p-5 rounded border border-[#27272a] space-y-5">
                    <h3 className="text-xs font-bold font-mono text-white uppercase tracking-wider flex items-center space-x-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-purple-300" />
                      <span>Detailed Executive Breakdown</span>
                    </h3>

                    <p className="text-zinc-200 text-[13px] font-sans leading-relaxed">
                      {scan.executiveBreakdown.overview}
                    </p>

                    {scan.executiveBreakdown.riskAreas.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="text-[10px] font-mono text-[#71717a] uppercase tracking-wider font-bold">Key Risk Areas</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          {scan.executiveBreakdown.riskAreas.map((r, idx) => (
                            <div key={idx} className="p-3.5 bg-black border border-[#27272a] rounded-lg">
                              <span className="text-[13px] font-sans font-semibold text-white block mb-1">{r.area}</span>
                              <span className="text-[12px] font-sans text-zinc-400 leading-relaxed">{r.detail}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="p-3.5 rounded-lg border border-amber-500/20 bg-amber-500/5">
                      <h4 className="text-[10px] font-mono text-amber-400 uppercase tracking-wider font-bold mb-1.5">Business Impact</h4>
                      <p className="text-[12px] font-sans text-amber-100/90 leading-relaxed">{scan.executiveBreakdown.businessImpact}</p>
                    </div>

                    {scan.executiveBreakdown.priorityActions.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="text-[10px] font-mono text-[#71717a] uppercase tracking-wider font-bold">Priority Actions (Ranked)</h4>
                        <ol className="space-y-2">
                          {scan.executiveBreakdown.priorityActions.map((action, idx) => (
                            <li key={idx} className="flex items-start space-x-2.5 text-[12px] font-sans text-zinc-200 leading-relaxed">
                              <span className="shrink-0 w-4 h-4 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] text-[9px] font-mono font-bold flex items-center justify-center mt-0.5">{idx + 1}</span>
                              <span>{action}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </div>
                )}

                {/* Grid layout of the security pillars */}
                <div className="space-y-3">
                  <h4 className="text-[10px] font-mono text-[#52525b] uppercase tracking-wider pl-1 font-bold">Dynamic Application Security & Pen-Testing Pillars</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                    {categoryTabLabels.map(cell => {
                      const count = getCategoryCount(cell.key);
                      const stateText = getCategorySeverity(cell.key);
                      const colorClass = getCategoryColor(cell.key);
                      // Per-severity counts for this pillar, feeding the mini bar.
                      const cellCounts = findings
                        .filter(f => f.category === cell.key && !f.isFalsePositive)
                        .reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {} as Record<string, number>);

                      return (
                        <div
                          key={cell.key}
                          onClick={() => setActiveTab(cell.key)}
                          className={`p-4 rounded-lg border transition-all cursor-pointer hover:border-[#3f3f46] hover:bg-black/40 ${colorClass}`}
                        >
                          <div className="flex justify-between items-start mb-2">
                            <cell.icon className="w-5 h-5 opacity-80" />
                            <span className="text-[10px] uppercase font-mono tracking-wider font-extrabold">{cell.label}</span>
                          </div>
                          <span className="text-[9px] font-mono text-zinc-500 block uppercase font-bold">{cell.term}</span>
                          <div className="mt-3 flex items-baseline justify-between">
                            <span className="text-[10px] font-mono font-semibold">{stateText}</span>
                            <span className="text-lg font-mono font-black">{count}</span>
                          </div>
                          <SeverityBar counts={cellCounts} className="mt-2.5" />
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Real diagnostic evidence behind the findings — resolved from
                    the actual scan, not placeholder values. */}
                {scan.evidence && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
                      <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Network & Attack Surface (EASM)</h5>
                      <div className="font-mono text-xs space-y-2 text-zinc-400">
                        <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
                          <span className="text-[#52525b] shrink-0">Resolved IP:</span>
                          <span className="text-zinc-300 text-right break-all">{scan.evidence.resolvedIp || 'not resolved'}</span>
                        </div>
                        <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
                          <span className="text-[#52525b] shrink-0">Nameserver:</span>
                          <span className="text-zinc-300 text-right break-all">{scan.evidence.nameserver || 'not disclosed'}</span>
                        </div>
                        <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
                          <span className="text-[#52525b] shrink-0">Protocol / Status:</span>
                          <span className="text-zinc-300 text-right">{scan.evidence.protocol} · HTTP {scan.evidence.responseStatus}</span>
                        </div>
                        <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
                          <span className="text-[#52525b] shrink-0">Server Header:</span>
                          <span className="text-zinc-300 text-right break-all">{scan.evidence.serverHeader || 'suppressed (good)'}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-[#52525b] shrink-0">Live Subdomains:</span>
                          <span className="text-right">
                            {scan.evidence.liveSubdomains.length > 0
                              ? <span className="text-amber-400 break-all">{scan.evidence.liveSubdomains.slice(0, 4).join(', ')}{scan.evidence.liveSubdomains.length > 4 ? ` +${scan.evidence.liveSubdomains.length - 4} more` : ''}</span>
                              : <span className="text-zinc-500">none of {scan.evidence.subdomainsChecked} checked</span>}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
                      <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Dynamic Coverage (DAST)</h5>
                      <div className="font-mono text-xs space-y-2 text-zinc-400">
                        <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
                          <span className="text-[#52525b] shrink-0">Sensitive Paths:</span>
                          <span className="text-right">
                            {(() => {
                              const exposed = scan.evidence!.probedPaths.filter(p => p.exposed);
                              return exposed.length > 0
                                ? <span className="text-red-400 break-all">{exposed.map(p => p.path).join(', ')} exposed</span>
                                : <span className="text-[#22c55e]">{scan.evidence!.probedPaths.length} probed, all locked down</span>;
                            })()}
                          </span>
                        </div>
                        <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
                          <span className="text-[#52525b] shrink-0">Crawl Coverage:</span>
                          <span className="text-zinc-300 text-right">
                            {scan.evidence.crawl
                              ? `${scan.evidence.crawl.pagesVisited} page(s), ${scan.evidence.crawl.endpointsDiscovered} endpoint(s)`
                              : 'root only'}
                          </span>
                        </div>
                        <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
                          <span className="text-[#52525b] shrink-0">Params Fuzzed:</span>
                          <span className="text-zinc-300 text-right">{scan.evidence.activeProbesRun ? (scan.evidence.crawl?.paramsTested ?? 0) : 'skipped (unverified)'}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-[#52525b] shrink-0">Detected Libraries:</span>
                          <span className="text-right break-all">
                            {scan.evidence.detectedLibraries.length > 0
                              ? scan.evidence.detectedLibraries.map((l, i) => (
                                  <span key={i} className={l.vulnerable ? 'text-red-400' : 'text-zinc-300'}>{l.name} {l.version}{i < scan.evidence!.detectedLibraries.length - 1 ? ', ' : ''}</span>
                                ))
                              : <span className="text-zinc-500">none flagged</span>}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Visual recon — a headless-browser screenshot of the target's
                    landing page, captured during the scan (opt-in feature). */}
                {scan.evidence?.screenshot && (
                  <div className="bg-[#0c0c0e] border border-[#27272a] rounded-lg p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold flex items-center space-x-1.5">
                        <Eye className="w-3.5 h-3.5 text-[#22c55e]" />
                        <span>Visual Recon — Target Landing Page</span>
                      </h5>
                      <span className="text-[9px] font-mono text-[#71717a]">
                        Captured {new Date(scan.evidence.screenshot.capturedAt).toLocaleString()} · {scan.evidence.screenshot.width}×{scan.evidence.screenshot.height}
                      </span>
                    </div>
                    <a href={scan.evidence.screenshot.dataUri} target="_blank" rel="noreferrer" className="block hover:opacity-95 transition-opacity">
                      <BrowserFrame url={scan.url}>
                        <img
                          src={scan.evidence.screenshot.dataUri}
                          alt={`Screenshot of ${scan.url}`}
                          className="w-full h-auto block"
                          loading="lazy"
                        />
                      </BrowserFrame>
                    </a>
                    <p className="text-[10px] font-sans text-[#71717a] leading-relaxed">
                      Rendered by a headless browser as an anonymous visitor would see it. Click to open full size.
                    </p>
                  </div>
                )}

                {/* Severity-proportionate summary banner. Language and colour are
                    DERIVED from the actual highest-severity finding (bannerForPosture)
                    — never a hard-coded "arbitrary code execution / fix immediately"
                    string, and no red alarm when the worst finding is only INFO/LOW. */}
                {banner && (
                  <div className={`rounded p-4 flex items-center space-x-3 border ${
                    banner.level === 'critical' ? 'bg-red-950/20 border-red-500/20' :
                    banner.level === 'warning' ? 'bg-amber-950/20 border-amber-500/20' :
                    'bg-[#0c0c0e] border-[#27272a]'
                  }`}>
                    {banner.level === 'critical'
                      ? <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
                      : banner.level === 'warning'
                      ? <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
                      : <AlertCircle className="w-5 h-5 text-[#52525b] shrink-0" />}
                    <div>
                      <p className={`text-xs font-mono font-bold uppercase tracking-wide ${
                        banner.level === 'notice' ? 'text-[#a1a1aa]' : 'text-white'
                      }`}>{banner.title}</p>
                      <p className={`text-[11px] font-mono mt-0.5 leading-relaxed ${
                        banner.level === 'critical' ? 'text-red-300/80' :
                        banner.level === 'warning' ? 'text-amber-200/80' :
                        'text-[#71717a]'
                      }`}>
                        {banner.message}
                      </p>
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* DYNAMIC PER MODULE FINDINGS RENDERER */}
            {activeTab !== 'OVERVIEW' && (
              <div className="space-y-6 animate-fade-in">
                
                {/* Module title cards */}
                <div className="flex items-center justify-between border-b border-[#27272a] pb-4">
                  <div>
                    <h4 className="text-white text-sm font-bold font-mono tracking-tight uppercase flex items-center space-x-2">
                      {React.createElement(categoryTabLabels.find(c => c.key === activeTab)?.icon || Shield, { className: 'w-5 h-5 text-[#22c55e]' })}
                      <span>{categoryTabLabels.find(c => c.key === activeTab)?.label} Module Findings</span>
                    </h4>
                    <span className="text-[10px] font-mono text-[#52525b] uppercase mt-1 block">
                      {categoryTabLabels.find(c => c.key === activeTab)?.term}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-400 block uppercase font-extrabold bg-[#18181b] border border-[#27272a] px-2.5 py-1">
                    Risk Assessment: {getCategorySeverity(activeTab)}
                  </span>
                </div>

                {/* Filtered list of findings */}
                {findings.filter(f => f.category === activeTab).length === 0 ? (
                  <div className="text-center py-16 bg-black/40 rounded border border-dashed border-[#27272a] flex flex-col items-center">
                    <CheckCircle2 className="w-10 h-10 text-[#22c55e] mb-3" />
                    <span className="text-xs text-white font-bold font-mono uppercase block">Zero Vulnerabilities Outstanding</span>
                    <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-md">
                      Your current configurations satisfy standard defensive criteria in {categoryTabLabels.find(c => c.key === activeTab)?.term}.
                    </p>
                    <div className="mt-5 grid grid-cols-2 gap-3 max-w-sm w-full font-mono text-[9px] text-[#52525b] text-left">
                      <div className="flex items-center space-x-1">
                        <Check className="w-3 h-3 text-[#22c55e]" />
                        <span>Hardening complete</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Check className="w-3 h-3 text-[#22c55e]" />
                        <span>Continuous evaluation active</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {(() => {
                      // Confirmed vs. Needs-Verification split (Bug 3): probe-
                      // confirmed findings first, then heuristic ones, then
                      // suppressed — each group introduced by a header so the
                      // confidence level is legible at a glance.
                      const moduleFindings = findings.filter(f => f.category === activeTab);
                      const groupOf = (f: Finding): 'confirmed' | 'needs' | 'suppressed' =>
                        f.isFalsePositive ? 'suppressed' : isConfirmed(f) ? 'confirmed' : 'needs';
                      const rank = { confirmed: 0, needs: 1, suppressed: 2 };
                      const ordered = [...moduleFindings].sort((a, b) => rank[groupOf(a)] - rank[groupOf(b)]);
                      let lastGroup = '';
                      return ordered.map(finding => {
                      const group = groupOf(finding);
                      const showGroupHeader = group !== lastGroup;
                      lastGroup = group;
                      // Severity chip styling from the shared token map (single
                      // source of truth for severity colour).
                      const severityColor = finding.isFalsePositive
                        ? 'bg-zinc-800 text-zinc-400 border border-zinc-700/60 font-medium'
                        : (SEVERITY_TOKENS[finding.severity]?.chip ?? 'bg-black text-[#52525b] border border-[#27272a]');

                      return (
                        <React.Fragment key={finding.id}>
                        {showGroupHeader && (
                          <div className="flex flex-wrap items-center gap-2 pt-3 first:pt-0">
                            {group === 'confirmed' ? (
                              <><CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e] shrink-0" /><span className="text-[10px] font-mono uppercase tracking-wider font-bold text-[#22c55e]">Confirmed</span></>
                            ) : group === 'needs' ? (
                              <><AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" /><span className="text-[10px] font-mono uppercase tracking-wider font-bold text-amber-400">Needs Verification</span></>
                            ) : (
                              <><Eye className="w-3.5 h-3.5 text-zinc-500 shrink-0" /><span className="text-[10px] font-mono uppercase tracking-wider font-bold text-zinc-500">Suppressed (False Positive)</span></>
                            )}
                            <span className="text-[9px] font-mono text-[#52525b]">
                              {group === 'confirmed'
                                ? 'Engine-verified — high confidence'
                                : group === 'needs'
                                ? 'Heuristic / pattern match — verify before acting'
                                : 'Excluded from the posture score'}
                            </span>
                          </div>
                        )}
                        <div
                          className={`border rounded p-5 transition-colors shadow ${
                            finding.isFalsePositive
                              ? 'bg-[#0f0f11]/60 border-zinc-800 border-dashed opacity-70 hover:border-zinc-750'
                              : 'bg-black border-[#27272a]/90 hover:border-[#3f3f46]'
                          }`}
                        >
                          
                          {/* Title element */}
                          <div className="flex flex-wrap items-start justify-between gap-2 mb-3">
                            <div className="flex items-center space-x-2.5">
                              <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${severityColor}`}>
                                {finding.isFalsePositive ? 'SUPPRESSED (FP)' : finding.severity}
                              </span>
                              {finding.confidence && (
                                <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded border bg-black ${
                                  finding.confidence === 'high' ? 'border-[#22c55e]/30 text-[#22c55e]' :
                                  finding.confidence === 'medium' ? 'border-amber-500/30 text-amber-500' :
                                  'border-zinc-500/30 text-zinc-500'
                                }`}>
                                  Conf: {finding.confidence}
                                </span>
                              )}
                              {finding.owasp && (
                                <span
                                  title={finding.owasp}
                                  className="text-[9px] font-mono uppercase px-2 py-0.5 rounded border border-purple-500/30 bg-black text-purple-300"
                                >
                                  {finding.owasp.split(' – ')[0]}
                                </span>
                              )}
                              <h5 className={`text-xs font-bold font-mono tracking-tight leading-snug ${finding.isFalsePositive ? 'text-zinc-500 line-through' : 'text-white'}`}>{finding.title}</h5>
                            </div>
                            <span className="text-[10px] text-[#52525b] font-mono tracking-wide">ID: {finding.id}</span>
                          </div>

                          {/* Detail summary */}
                          <div className="mb-4">
                            <p className={`text-[13px] font-sans leading-relaxed pl-1 ${finding.isFalsePositive ? 'text-zinc-500' : 'text-zinc-300'}`}>
                              {finding.description}
                            </p>
                            {finding.impact && !finding.isFalsePositive && (
                              <p className="text-[12px] font-sans leading-relaxed mt-2 pl-1 text-amber-300/90">
                                <strong className="text-amber-400 font-semibold">Impact:</strong> {finding.impact}
                              </p>
                            )}
                          </div>

                          {/* Detailed Remediation code fix payload block */}
                          <div className={`p-4 rounded border ${finding.isFalsePositive ? 'bg-zinc-950/40 border-zinc-850' : 'bg-[#0c0c0e] border-[#27272a]'}`}>
                            <div className="flex justify-between items-center mb-1.5">
                              <span className="text-[#52525b] font-mono text-[9px] uppercase tracking-wider">Automated Remediation Fix</span>
                              <button
                                onClick={() => handleCopyCode(finding.id, finding.fix)}
                                className="text-[10px] font-mono text-[#52525b] hover:text-[#22c55e] flex items-center space-x-1 transition-colors cursor-pointer"
                              >
                                {copiedCodeId === finding.id ? (
                                  <>
                                    <Check className="w-3 h-3 text-[#22c55e] shrink-0" />
                                    <span>Copied fix</span>
                                  </>
                                ) : (
                                  <>
                                    <Clipboard className="w-3 h-3 text-[#52525b] shrink-0" />
                                    <span>Copy directive</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <div className="overflow-x-auto max-h-48 scrollbar-thin">
                              <code className={`text-[11px] font-mono whitespace-pre leading-relaxed block py-1 ${finding.isFalsePositive ? 'text-zinc-600' : 'text-zinc-300'}`}>
                                {finding.fix}
                              </code>
                            </div>
                          </div>

                          {/* "Fix with AI" — a ready-to-paste prompt for the user's own coding agent */}
                          {finding.agentPrompt && !finding.isFalsePositive && (
                            <div className="mt-3 p-4 rounded border border-purple-500/20 bg-purple-500/5">
                              <div className="flex justify-between items-center mb-1.5">
                                <span className="text-purple-300/80 font-mono text-[9px] uppercase tracking-wider flex items-center space-x-1.5">
                                  <Sparkles className="w-3 h-3" />
                                  <span>Fix With AI — paste into Cursor / Claude Code / Windsurf</span>
                                </span>
                                <button
                                  onClick={() => handleCopyCode(`agent-${finding.id}`, finding.agentPrompt!)}
                                  className="text-[10px] font-mono text-[#52525b] hover:text-purple-300 flex items-center space-x-1 transition-colors cursor-pointer"
                                >
                                  {copiedCodeId === `agent-${finding.id}` ? (
                                    <>
                                      <Check className="w-3 h-3 text-purple-300 shrink-0" />
                                      <span>Copied prompt</span>
                                    </>
                                  ) : (
                                    <>
                                      <Clipboard className="w-3 h-3 text-[#52525b] shrink-0" />
                                      <span>Copy prompt</span>
                                    </>
                                  )}
                                </button>
                              </div>
                              <div className="overflow-x-auto max-h-48 scrollbar-thin">
                                <code className="text-[11px] font-mono whitespace-pre-wrap leading-relaxed block py-1 text-zinc-300">
                                  {finding.agentPrompt}
                                </code>
                              </div>
                            </div>
                          )}

                          {/* Raw Request / Response Collapsible Drawer for API_SEC / Payload details */}
                          {(finding.rawRequest || finding.rawResponse) && (
                            <div className="mt-3">
                              <button 
                                onClick={() => setExpandedApiRows(p => ({ ...p, [finding.id]: !p[finding.id] }))}
                                className="w-full flex items-center justify-between p-3 rounded bg-zinc-950/40 hover:bg-zinc-900 border border-zinc-800/80 transition-colors cursor-pointer group"
                              >
                                <span className="flex items-center space-x-2 text-[10px] font-mono text-zinc-400 group-hover:text-amber-400 transition-colors uppercase tracking-wider font-bold">
                                  <Terminal className="w-3.5 h-3.5 shrink-0" />
                                  <span>Raw HTTP Probes & Response Dump</span>
                                </span>
                                {expandedApiRows[finding.id] ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
                              </button>
                              
                              {expandedApiRows[finding.id] && (
                                <div className="mt-2 space-y-2 animate-fade-in">
                                  {finding.endpoint && (
                                    <div className="p-3 bg-black border border-zinc-800 rounded font-mono text-[10px] text-zinc-300 overflow-x-auto">
                                      <span className="text-zinc-500 select-none block mb-1">Target Endpoint:</span>
                                      {finding.endpoint}
                                    </div>
                                  )}
                                  
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    {finding.rawRequest && (
                                      <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                                        <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-amber-500/80 flex items-center justify-between">
                                          <span>Raw Request</span>
                                          <button onClick={() => handleCopyCode(`req-${finding.id}`, finding.rawRequest!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                                        </div>
                                        <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                                          <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawRequest}</code>
                                        </div>
                                      </div>
                                    )}
                                    {finding.rawResponse && (
                                      <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                                        <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-red-400/80 flex items-center justify-between">
                                          <span>Raw Response</span>
                                          <button onClick={() => handleCopyCode(`res-${finding.id}`, finding.rawResponse!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                                        </div>
                                        <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                                          <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawResponse}</code>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}

                          {/* False Positives Management UI Drawer Toggle */}
                          <div className="mt-4 border-t border-[#27272a]/30 pt-3 flex flex-col">
                            {suppressInputId === finding.id ? (
                              <div className="bg-[#121214] border border-[#27272a]/80 p-3.5 rounded space-y-3 animate-fade-in">
                                <label className="text-[10px] font-mono uppercase tracking-wider text-amber-500/90 font-bold block">
                                  Define Suppression Justification (Audit Trail)
                                </label>
                                <p className="text-[11px] text-[#52525b] font-mono">
                                  By declaring this finding a false positive or an excluded risk, its impact is subtracted from the final security score and rating, and the exemption will apply to future scans of this URL.
                                </p>
                                <input
                                  type="text"
                                  autoFocus
                                  placeholder="e.g. Host-level firewalls handle payload blocking / acceptable legacby boundary match."
                                  value={suppressReason}
                                  onChange={(e) => setSuppressReason(e.target.value)}
                                  className="w-full bg-black border border-[#27272a] rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#22c55e] placeholder-zinc-700"
                                />
                                {suppressError && (
                                  <p className="text-[10px] font-mono text-red-400">{suppressError}</p>
                                )}
                                <div className="flex justify-end space-x-2">
                                  <button
                                    onClick={() => { setSuppressInputId(null); setSuppressError(null); }}
                                    className="px-2.5 py-1.5 border border-[#27272a] text-[#a1a1aa] hover:text-white bg-zinc-900 hover:bg-zinc-800 text-[10px] font-mono uppercase rounded cursor-pointer transition-all"
                                  >
                                    Close
                                  </button>
                                  <button
                                    onClick={() => handleSaveSuppression(finding)}
                                    disabled={isSuppressing}
                                    className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/35 text-[10px] font-mono uppercase rounded font-bold cursor-pointer transition-all"
                                  >
                                    {isSuppressing ? 'Processing...' : 'Suppress Finding'}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <div className="flex justify-between items-center">
                                {finding.isFalsePositive ? (
                                  <div className="flex items-center justify-between w-full bg-zinc-900/40 border border-dashed border-zinc-800/80 px-3.5 py-2 rounded">
                                    <p className="text-[11px] font-mono text-zinc-500 flex items-center space-x-1.5">
                                      <AlertTriangle className="w-3.5 h-3.5 text-zinc-600 shrink-0" />
                                      <span><strong>Exempted Risk:</strong> {finding.suppressionReason || 'Declared acceptable false positive risk.'}</span>
                                    </p>
                                    <button
                                      disabled={isSuppressing}
                                      onClick={() => handleRemoveSuppressionDirectly(finding.title)}
                                      className="text-[10px] font-mono text-red-400 hover:text-red-300 underline cursor-pointer select-none transition-colors"
                                    >
                                      Remove Exemption
                                    </button>
                                  </div>
                                ) : (
                                  <>
                                    <span className="text-[10px] font-mono text-[#52525b]">Is this threat checked or invalid?</span>
                                    <button
                                      onClick={() => { setSuppressInputId(finding.id); setSuppressReason(''); setSuppressError(null); }}
                                      className="px-2.5 py-1 bg-zinc-900 border border-zinc-800/80 hover:border-amber-500/20 text-[#71717a] hover:text-amber-400 text-[10px] font-mono uppercase tracking-wider transition-all flex items-center space-x-1.5 cursor-pointer"
                                    >
                                      <AlertTriangle className="w-3.5 h-3.5" />
                                      <span>Mark False Positive</span>
                                    </button>
                                  </>
                                )}
                              </div>
                            )}
                          </div>

                        </div>
                        </React.Fragment>
                      );
                    });
                    })()}
                  </div>
                )}

              </div>
            )}

          </div>
        </div>

        {/* Raw Header Output Inspection drawer */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
          <button
            onClick={() => setShowRaw(!showRaw)}
            className="w-full flex items-center justify-between text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider cursor-pointer"
          >
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-[#22c55e]" />
              <span>Diagnostic Raw Headers & Outputs</span>
            </div>
            {showRaw ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showRaw && (
            <div className="mt-5 space-y-4 pt-4 border-t border-[#27272a] animate-fade-in">
              <p className="text-[#52525b] text-[11px] leading-relaxed font-mono">
                The exact evidence captured during this scan of {scan.url} — resolved network data, per-path probe results, and observed header state. Everything below is real output from this run.
              </p>

              {!scan.evidence ? (
                <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-500 border border-[#27272a]">
                  Raw diagnostic evidence was not captured for this scan (it predates evidence logging). Re-run the scan to populate it.
                </div>
              ) : (
                <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-400 space-y-2 border border-[#27272a] max-h-96 overflow-y-auto">
                  <span className="text-[#52525b] text-[9px] uppercase font-bold block mb-1">Captured scan trace</span>
                  <p className="text-zinc-200">GET / HTTP/1.1</p>
                  <p className="text-zinc-200">Host: {scan.url.replace(/https?:\/\//i, '').replace(/\/.*$/, '')}</p>
                  <p className="text-[#52525b]">User-Agent: Seclayer-Security-Scanner/2.0 (seclayer.io)</p>
                  <p className="text-zinc-300">→ HTTP {scan.evidence.responseStatus} over {scan.evidence.protocol}</p>

                  <p className="text-[#22c55e] font-bold mt-3">[EASM — DNS &amp; PERIMETER]</p>
                  <p className="text-zinc-400">Resolved IP: {scan.evidence.resolvedIp || '(not resolved)'}</p>
                  <p className="text-zinc-400">Authoritative nameserver: {scan.evidence.nameserver || '(not disclosed)'}</p>
                  <p className="text-zinc-400">Subdomains probed: {scan.evidence.subdomainsChecked} · live: {scan.evidence.liveSubdomains.length}</p>
                  {scan.evidence.liveSubdomains.slice(0, 8).map((d, i) => (
                    <p key={i} className="text-amber-400">  ↳ {d}</p>
                  ))}

                  <p className="text-[#22c55e] font-bold mt-3">[DAST — SENSITIVE PATH PROBES]</p>
                  {scan.evidence.probedPaths.map((p, i) => (
                    <p key={i} className="text-zinc-200">
                      Path: <span className={p.exposed ? 'text-red-400' : 'text-amber-400'}>{p.path}</span> — HTTP {p.status} <span className={p.exposed ? 'text-red-400' : 'text-[#22c55e]'}>({p.exposed ? 'EXPOSED' : 'locked down'})</span>
                    </p>
                  ))}

                  <p className="text-[#22c55e] font-bold mt-4">[HTTP RESPONSE]</p>
                  <p className="text-zinc-300">Server: {scan.evidence.serverHeader || '(suppressed)'}</p>
                  <p className="text-zinc-300">Scanned at: {new Date(scan.evidence.scannedAt).toUTCString()}</p>

                  <p className="text-[#22c55e] font-bold mt-4">[IAST — DEFENSIVE HEADERS]</p>
                  {['content-security-policy','strict-transport-security','x-frame-options','x-content-type-options','referrer-policy'].map((h) => {
                    const present = scan.evidence!.presentSecurityHeaders.includes(h);
                    return (
                      <p key={h} className="text-zinc-450">{h}: <span className={present ? 'text-[#22c55e]' : 'text-amber-400'}>{present ? 'PRESENT' : 'ABSENT'}</span></p>
                    );
                  })}

                  <p className="text-red-500 font-bold mt-4">[RED TEAM — ACTIVE EXPLOIT PROBES]</p>
                  {!scan.evidence.activeProbesRun ? (
                    <p className="text-zinc-400">Skipped — domain ownership not verified (passive recon only).</p>
                  ) : findings.filter(f => f.category === 'RED_TEAM' || f.category === 'API_SEC').length > 0 ? (
                    findings.filter(f => f.category === 'RED_TEAM' || f.category === 'API_SEC').map((f, i) => (
                      <p key={i} className="text-red-300">{`✗ ${f.title} — ${f.severity.toUpperCase()} confirmed`}</p>
                    ))
                  ) : (
                    <p className="text-[#22c55e]">Active probes ran — no exploitable injection/SSRF/API signatures confirmed.</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
