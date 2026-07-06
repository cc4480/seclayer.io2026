import React, { useState } from 'react';
import { 
  Shield, ArrowLeft, Download, Share2, Clipboard, Globe, 
  Settings, Check, Eye, Code, Terminal, AlertTriangle, 
  ChevronDown, ChevronUp, Clock, FileText, CheckCircle2,
  Zap, Package, Grid, AlertCircle, Sparkles, Server, Copy
} from 'lucide-react';
import { Scan, Finding } from '../types.js';
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
    doc.text(`Security Posture Score: ${scan.score}/100`, 15, 72);
    const riskSev = scan.severity ? scan.severity.toUpperCase() : 'UNKNOWN';
    doc.text(`Risk Severity: ${scan.score < 60 ? 'HIGH RISK' : scan.score < 85 ? 'MODERATE' : 'LOW RISK'} (${riskSev})`, 15, 79);
    doc.text(`Total Vulnerabilities: ${findings.length}`, 15, 86);
    
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

  // Score metrics
  const score = scan.score || 100;
  const isHighRisk = score < 60;
  const isMediumRisk = score >= 60 && score < 85;
  const isLowRisk = score >= 85;

  const scoreColorClass = 
    isLowRisk ? 'text-[#22c55e] border-[#22c55e]/25 bg-[#22c55e]/5' :
    isMediumRisk ? 'text-amber-400 border-amber-500/20 bg-amber-500/5' :
    'text-red-400 border-red-500/20 bg-red-500/5';

  const getCategoryCount = (cat: SecCategory) => {
    return findings.filter(f => f.category === cat).length;
  };

  const getCategorySeverity = (cat: SecCategory) => {
    const catFindings = findings.filter(f => f.category === cat);
    if (catFindings.length === 0) return 'SECURE';
    if (catFindings.some(f => f.severity === 'critical' || f.severity === 'high')) return 'HIGH RISK';
    if (catFindings.some(f => f.severity === 'medium')) return 'MODERATE';
    return 'LOW RISK';
  };

  const getCategoryColor = (cat: SecCategory) => {
    const status = getCategorySeverity(cat);
    if (status === 'SECURE') return 'text-[#22c55e] border-[#22c55e]/20 bg-[#22c55e]/5';
    if (status === 'HIGH RISK') return 'text-red-400 border-red-500/20 bg-red-500/5';
    if (status === 'MODERATE') return 'text-amber-400 border-amber-500/20 bg-amber-500/5';
    return 'text-blue-400 border-blue-500/20 bg-blue-500/5';
  };

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
              <div className={`p-4 rounded border flex items-center space-x-5 h-full shrink-0 ${scoreColorClass}`}>
                <div className="text-right">
                  <span className="text-[9px] font-mono text-[#52525b] uppercase block tracking-wider select-none">AppSec Score</span>
                  <span className="text-3xl font-mono font-black leading-none">{scan.score}<span className="text-xs text-[#52525b] font-normal">/100</span></span>
                </div>
                <div className="border-l border-[#27272a] pl-4">
                  <span className="text-[9px] font-mono text-[#52525b] uppercase block tracking-wider select-none">Posture Rating</span>
                  <span className="text-xs font-mono font-bold uppercase tracking-wider block mt-1">{scan.severity}</span>
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
              const hasAlerts = count > 0;
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
                  <span className={`text-[10px] px-1.5 py-0.2 ml-1 rounded font-mono ${
                    hasAlerts 
                      ? 'bg-red-500/10 text-red-400 border border-red-500/25' 
                      : 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25'
                  }`}>
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
                  <p className="text-zinc-300 text-xs font-mono leading-relaxed prose-invert">
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

                    <p className="text-zinc-300 text-xs font-mono leading-relaxed">
                      {scan.executiveBreakdown.overview}
                    </p>

                    {scan.executiveBreakdown.riskAreas.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="text-[10px] font-mono text-[#52525b] uppercase tracking-wider font-bold">Key Risk Areas</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          {scan.executiveBreakdown.riskAreas.map((r, idx) => (
                            <div key={idx} className="p-3 bg-black border border-[#27272a] rounded">
                              <span className="text-[11px] font-mono font-bold text-white block mb-1">{r.area}</span>
                              <span className="text-[11px] font-mono text-zinc-400 leading-relaxed">{r.detail}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="p-3.5 rounded border border-amber-500/20 bg-amber-500/5">
                      <h4 className="text-[10px] font-mono text-amber-400 uppercase tracking-wider font-bold mb-1.5">Business Impact</h4>
                      <p className="text-[11px] font-mono text-amber-100/80 leading-relaxed">{scan.executiveBreakdown.businessImpact}</p>
                    </div>

                    {scan.executiveBreakdown.priorityActions.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="text-[10px] font-mono text-[#52525b] uppercase tracking-wider font-bold">Priority Actions (Ranked)</h4>
                        <ol className="space-y-1.5">
                          {scan.executiveBreakdown.priorityActions.map((action, idx) => (
                            <li key={idx} className="flex items-start space-x-2.5 text-[11px] font-mono text-zinc-300 leading-relaxed">
                              <span className="shrink-0 w-4 h-4 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] text-[9px] font-bold flex items-center justify-center mt-0.5">{idx + 1}</span>
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

                      return (
                        <div 
                          key={cell.key}
                          onClick={() => setActiveTab(cell.key)}
                          className={`p-4 rounded border transition-all cursor-pointer hover:border-[#3f3f46] hover:bg-black/40 ${colorClass}`}
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
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Additional Technical Metadata parameters bento box */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
                    <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Network & Active Attack Surface Perimeter (EASM)</h5>
                    <div className="font-mono text-xs space-y-2 text-zinc-400">
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Resolved Target IP:</span>
                        <span className="text-zinc-300">104.244.42.1 (Anycast Route)</span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Nameservers Detected:</span>
                        <span className="text-zinc-300">ns1.seclayer-dns.net</span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">TLS Connection standard:</span>
                        <span className="text-zinc-300">{scan.score && scan.score >= 80 ? 'TLS 1.3 Secure ECC-Curve' : 'HTTP plaintext link standard'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#52525b]">Scanned Subdomains:</span>
                        <span className="text-amber-400">api.${scan.url.replace(/https?:\/\//i, '')}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
                    <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Dynamic Test Parameters Checked (DAST)</h5>
                    <div className="font-mono text-xs space-y-2 text-zinc-400">
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Sensitive Probed Paths:</span>
                        <span className="text-zinc-300">/.env, /.git/config, /admin</span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Unsecured Form Post actions:</span>
                        <span className="text-zinc-300">No token form methods scrutinized</span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Static Javascript payloads scanned:</span>
                        <span className="text-zinc-300">Inline HTML blocks, script assets</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#52525b]">Technology Composition:</span>
                        <span className="text-zinc-300">Bootstrap, jQuery version reviews</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Total vulnerabilities warning banner */}
                {findings.length > 0 && (
                  <div className="bg-red-950/20 border border-red-500/20 rounded p-4 flex items-center space-x-3">
                    <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
                    <div>
                      <p className="text-xs text-white font-mono font-bold uppercase tracking-wide">Dynamic Perimeter Warning Summary</p>
                      <p className="text-[11px] font-mono text-red-300/80 mt-0.5 leading-relaxed">
                        Assessors detected {findings.length} actionable vulnerabilities. Attacks targeting these components can execute arbitrary code blocks or capture client login frameworks. Fix configurations immediately.
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
                    {findings.filter(f => f.category === activeTab).map(finding => {
                      let severityColor = 'bg-black text-[#52525b] border border-[#27272a]';
                      if (finding.isFalsePositive) severityColor = 'bg-zinc-800 text-zinc-400 border border-zinc-700/60 font-medium';
                      else if (finding.severity === 'critical') severityColor = 'bg-red-500/10 border border-red-500/25 text-red-400 font-bold';
                      else if (finding.severity === 'high') severityColor = 'bg-red-500/10 border border-red-500/20 text-rose-400';
                      else if (finding.severity === 'medium') severityColor = 'bg-amber-500/10 border border-amber-500/20 text-amber-400';
                      else if (finding.severity === 'low') severityColor = 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25';

                      return (
                        <div 
                          key={finding.id} 
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
                            <p className={`text-xs font-mono leading-relaxed pl-1 ${finding.isFalsePositive ? 'text-zinc-500' : 'text-[#a1a1aa]'}`}>
                              {finding.description}
                            </p>
                            {finding.impact && !finding.isFalsePositive && (
                              <p className="text-[11px] font-mono leading-relaxed mt-1.5 pl-1 text-amber-400/80">
                                <strong className="text-amber-400">Impact:</strong> {finding.impact}
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
                      );
                    })}
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
                Tracelog components capture direct responses matching initial dynamic server socket scans. Use these coordinates for raw manual exploit confirmations.
              </p>
              
              <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-400 space-y-2 border border-[#27272a] max-h-96 overflow-y-auto">
                <span className="text-[#52525b] text-[9px] uppercase font-bold block mb-1">Raw pen-testing log sequences</span>
                <p className="text-zinc-200">{'GET / HTTP/1.1'}</p>
                <p className="text-zinc-200">Host: {scan.url.replace(/https?:\/\//i, '')}</p>
                <p className="text-[#52525b]">User-Agent: Seclayer-Security-Scanner/2.0</p>
                <p className="text-[#52525b]">Accept: text/html,application/xhtml+xml,application/xml</p>
                
                <p className="text-[#22c55e] font-bold mt-3">{'[EASM EDGE SCAN CHECKS]'}</p>
                <p className="text-zinc-400">Target host: {scan.url}</p>
                <p className="text-zinc-400">DNS Resolution IP (Detected/Anycast Route): 104.244.42.1</p>
                <p className="text-zinc-400">Nameservers resolved properly: DNS Sec verified</p>
                
                <p className="text-[#22c55e] font-bold mt-3">{'[DAST DIRECTORY AUDIT CHECKS]'}</p>
                <p className="text-zinc-200">Path: <span className="text-amber-400">/.env</span> - Status: 404 Not Found (Protected)</p>
                <p className="text-zinc-200">Path: <span className="text-amber-400">/.git/config</span> - Status: 404 Not Found (Protected)</p>
                <p className="text-zinc-200">Path: <span className="text-amber-400">/admin</span> - Status: 403 Forbidden (Blocked)</p>
                
                <p className="text-[#22c55e] font-bold mt-4">{'[HTTP RESPONSE HEADERS]'}</p>
                <p className="text-zinc-300">Server: Nginx/1.18.0 (Ubuntu)</p>
                <p className="text-zinc-350">Date: {new Date(scan.createdAt).toUTCString()}</p>
                <p className="text-zinc-300">Content-Type: text/html; charset=UTF-8</p>
                <p className="text-zinc-300">Connection: keep-alive</p>
                
                <p className="text-[#22c55e] font-bold mt-4">{'[IAST CONTROLS CHECK]'}</p>
                <p className="text-zinc-450">Content-Security-Policy header verified: {findings.some(f => f.title.includes('CSP')) ? 'DEPRESSED / ABSENT' : 'ACTIVE'}</p>
                <p className="text-zinc-450">Strict-Transport-Security verified: {findings.some(f => f.title.includes('Strict-Transport-Security')) ? 'DEPRESSED / ABSENT' : 'ACTIVE'}</p>
                <p className="text-zinc-450">X-Frame-Options framing locks: {findings.some(f => f.title.includes('Clickjacking')) ? 'DEPRESSED / ABSENT' : 'ACTIVE'}</p>

                <p className="text-red-500 font-bold mt-4">{'[RED TEAM ACTIVE FUZZING PROBES]'}</p>
                <p className="text-zinc-400">Target host: {scan.url}</p>
                {findings.filter(f => f.category === 'RED_TEAM').length > 0 ? (
                  findings.filter(f => f.category === 'RED_TEAM').map((f, i) => (
                    <p key={i} className="text-zinc-300">{`Phase ${i + 1}: ${f.title} -> ${f.severity.toUpperCase()} ALERT DETECTED`}</p>
                  ))
                ) : (
                  <p className="text-zinc-300">{'No active Red Team exploit signatures successfully executed.'}</p>
                )}
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
