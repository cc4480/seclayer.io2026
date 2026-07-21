// PDF export of a completed scan report. Kept out of ReportViewer so the
// (long, jsPDF-heavy) document layout lives on its own. Renders from the same
// shared `posture` the on-screen report uses, so the PDF can never disagree with
// the UI it was exported from.
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import { Scan, Finding } from "../types.js";
import { deriveSecurityPosture } from "../../server/scoring.js";

type Posture = ReturnType<typeof deriveSecurityPosture>;

export function downloadReportPdf(scan: Scan, posture: Posture, findings: Finding[]) {
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
    f.fix,
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
    didParseCell: function (data) {
      if (data.section === 'body' && data.column.index === 2) {
        // just standard formatting here, custom styles can be complex in some autotable versions, so we use string values
      }
    },
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
}
