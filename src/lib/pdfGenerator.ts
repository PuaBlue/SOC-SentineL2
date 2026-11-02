import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { SecurityFinding, DashboardStats, ReportConfig, Language } from '@/types';

interface ReportData {
  config: ReportConfig;
  findings: SecurityFinding[];
  stats: DashboardStats;
}

const labels: Record<Language, Record<string, string>> = {
  en: {
    report_title: 'Security Analysis Report',
    executive_title: 'Executive Summary Report',
    technical_title: 'Technical Analysis Report',
    confidential: 'CONFIDENTIAL',
    generated: 'Generated',
    author: 'Author',
    organization: 'Organization',
    executive_summary: 'Executive Summary',
    overview: 'Overview',
    total_events: 'Total Events Analyzed',
    findings_detected: 'Security Findings Detected',
    critical_findings: 'Critical Findings',
    high_findings: 'High Findings',
    medium_findings: 'Medium Findings',
    low_findings: 'Low Findings',
    unique_sources: 'Unique Source IPs',
    unique_users: 'Unique Users',
    analysis_period: 'Analysis Period',
    risk_summary: 'Risk Summary',
    risk_critical_desc: 'Critical-severity findings require immediate response and remediation.',
    risk_high_desc: 'High-severity findings should be addressed within 24 hours.',
    risk_medium_desc: 'Medium-severity findings should be investigated within 72 hours.',
    risk_low_desc: 'Low-severity findings should be reviewed during the next maintenance window.',
    findings_detail: 'Findings Detail',
    finding: 'Finding',
    severity: 'Severity',
    type: 'Type',
    description: 'Description',
    justification: 'Evidence & Justification',
    affected_assets: 'Affected Assets',
    indicators: 'Indicators of Compromise',
    recommendation: 'Recommendation',
    mitre_attack: 'MITRE ATT&CK',
    confidence: 'Confidence',
    related_logs: 'Related Log Entries',
    top_source_ips: 'Top Source IPs',
    top_users: 'Most Active Users',
    events_by_type: 'Events by Type',
    page: 'Page',
    of: 'of',
    no_findings: 'No security findings were detected in the analyzed logs.',
    disclaimer: 'DISCLAIMER: This report was generated through automated security log analysis. All findings are based strictly on evidence present in the provided log data. No findings have been fabricated or assumed beyond the available evidence. Manual verification of critical findings is recommended.',
    brute_force: 'Brute Force Attack',
    suspicious_login: 'Suspicious Login',
    privilege_escalation: 'Privilege Escalation',
    anomalous_command: 'Anomalous Command',
    lateral_movement: 'Lateral Movement',
  },
  es: {
    report_title: 'Reporte de Análisis de Seguridad',
    executive_title: 'Reporte de Resumen Ejecutivo',
    technical_title: 'Reporte de Análisis Técnico',
    confidential: 'CONFIDENCIAL',
    generated: 'Generado',
    author: 'Autor',
    organization: 'Organización',
    executive_summary: 'Resumen Ejecutivo',
    overview: 'Resumen General',
    total_events: 'Total de Eventos Analizados',
    findings_detected: 'Hallazgos de Seguridad Detectados',
    critical_findings: 'Hallazgos Críticos',
    high_findings: 'Hallazgos Altos',
    medium_findings: 'Hallazgos Medios',
    low_findings: 'Hallazgos Bajos',
    unique_sources: 'IPs Origen Únicas',
    unique_users: 'Usuarios Únicos',
    analysis_period: 'Período de Análisis',
    risk_summary: 'Resumen de Riesgos',
    risk_critical_desc: 'Los hallazgos de severidad crítica requieren respuesta y remediación inmediata.',
    risk_high_desc: 'Los hallazgos de severidad alta deben ser atendidos en las próximas 24 horas.',
    risk_medium_desc: 'Los hallazgos de severidad media deben ser investigados en las próximas 72 horas.',
    risk_low_desc: 'Los hallazgos de severidad baja deben ser revisados en la próxima ventana de mantenimiento.',
    findings_detail: 'Detalle de Hallazgos',
    finding: 'Hallazgo',
    severity: 'Severidad',
    type: 'Tipo',
    description: 'Descripción',
    justification: 'Evidencia y Justificación',
    affected_assets: 'Activos Afectados',
    indicators: 'Indicadores de Compromiso',
    recommendation: 'Recomendación',
    mitre_attack: 'MITRE ATT&CK',
    confidence: 'Confianza',
    related_logs: 'Registros Relacionados',
    top_source_ips: 'IPs Origen Principales',
    top_users: 'Usuarios más Activos',
    events_by_type: 'Eventos por Tipo',
    page: 'Página',
    of: 'de',
    no_findings: 'No se detectaron hallazgos de seguridad en los logs analizados.',
    disclaimer: 'AVISO: Este reporte fue generado mediante análisis automatizado de logs de seguridad. Todos los hallazgos se basan estrictamente en la evidencia presente en los datos de log proporcionados. Ningún hallazgo ha sido fabricado o asumido más allá de la evidencia disponible. Se recomienda la verificación manual de los hallazgos críticos.',
    brute_force: 'Ataque de Fuerza Bruta',
    suspicious_login: 'Inicio de Sesión Sospechoso',
    privilege_escalation: 'Escalamiento de Privilegios',
    anomalous_command: 'Comando Anómalo',
    lateral_movement: 'Movimiento Lateral',
  },
};

function getFindingTypeLabel(type: string, lang: Language): string {
  const key = type as keyof typeof labels.en;
  return labels[lang][key] || type;
}

function severityColorRGB(severity: string): [number, number, number] {
  switch (severity.toLowerCase()) {
    case 'critical': return [239, 68, 68];
    case 'high': return [249, 115, 22];
    case 'medium': return [234, 179, 8];
    case 'low': return [34, 197, 94];
    default: return [148, 163, 184];
  }
}

export function generatePDF(data: ReportData): jsPDF {
  const { config, findings, stats } = data;
  const lang = config.language;
  const t = labels[lang];
  const doc = new jsPDF('p', 'mm', 'a4');
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  const contentWidth = pageWidth - margin * 2;

  let yPos = 0;

  // ── Helper: check if we need a new page ──
  function checkPage(neededHeight: number = 30) {
    if (yPos + neededHeight > pageHeight - 30) {
      doc.addPage();
      yPos = margin;
      addHeader();
    }
  }

  // ── Header on each page ──
  function addHeader() {
    doc.setFillColor(30, 27, 75); // brand-950
    doc.rect(0, 0, pageWidth, 12, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text(t.confidential, pageWidth / 2, 8, { align: 'center' });
    doc.setTextColor(0, 0, 0);
  }

  // ── Footer on each page ──
  function addFooter() {
    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFillColor(30, 27, 75);
      doc.rect(0, pageHeight - 10, pageWidth, 10, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(7);
      doc.text(
        `${t.page} ${i} ${t.of} ${totalPages}`,
        pageWidth / 2,
        pageHeight - 4,
        { align: 'center' }
      );
      doc.text(
        `${t.generated}: ${new Date().toLocaleDateString(lang === 'es' ? 'es-ES' : 'en-US')}`,
        margin,
        pageHeight - 4
      );
      doc.text(
        config.organization || '',
        pageWidth - margin,
        pageHeight - 4,
        { align: 'right' }
      );
    }
  }

  // ── COVER PAGE ──
  addHeader();
  doc.setFillColor(30, 27, 75);
  doc.rect(0, 60, pageWidth, 80, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  const title = config.type === 'executive' ? t.executive_title : t.technical_title;
  doc.text(title, pageWidth / 2, 90, { align: 'center' });

  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.text(config.title || t.report_title, pageWidth / 2, 105, { align: 'center' });

  doc.setFontSize(10);
  doc.text(
    `${t.generated}: ${new Date().toLocaleDateString(lang === 'es' ? 'es-ES' : 'en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`,
    pageWidth / 2,
    125,
    { align: 'center' }
  );

  doc.setTextColor(0, 0, 0);
  doc.setFontSize(11);
  yPos = 160;
  if (config.author) {
    doc.text(`${t.author}: ${config.author}`, pageWidth / 2, yPos, { align: 'center' });
    yPos += 8;
  }
  if (config.organization) {
    doc.text(`${t.organization}: ${config.organization}`, pageWidth / 2, yPos, { align: 'center' });
    yPos += 8;
  }

  // Disclaimer at bottom of cover
  doc.setFontSize(7);
  doc.setTextColor(100, 100, 100);
  const disclaimerLines = doc.splitTextToSize(t.disclaimer, contentWidth);
  doc.text(disclaimerLines, margin, pageHeight - 35);

  // ── OVERVIEW PAGE ──
  doc.addPage();
  addHeader();
  yPos = 22;

  doc.setTextColor(30, 27, 75);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text(t.overview, margin, yPos);
  yPos += 12;

  // Stats table
  const overviewData = [
    [t.total_events, stats.totalLogs.toLocaleString()],
    [t.findings_detected, stats.totalFindings.toLocaleString()],
    [t.critical_findings, stats.criticalCount.toLocaleString()],
    [t.high_findings, stats.highCount.toLocaleString()],
    [t.medium_findings, stats.mediumCount.toLocaleString()],
    [t.low_findings, stats.lowCount.toLocaleString()],
    [t.unique_sources, stats.uniqueSourceIPs.toLocaleString()],
    [t.unique_users, stats.uniqueUsers.toLocaleString()],
  ];
  if (stats.timeRange.start && stats.timeRange.end) {
    overviewData.push([
      t.analysis_period,
      `${new Date(stats.timeRange.start).toLocaleDateString()} — ${new Date(stats.timeRange.end).toLocaleDateString()}`,
    ]);
  }

  autoTable(doc, {
    startY: yPos,
    head: [],
    body: overviewData,
    theme: 'grid',
    styles: { fontSize: 10, cellPadding: 4 },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 80 },
      1: { cellWidth: contentWidth - 80 },
    },
    margin: { left: margin, right: margin },
    didParseCell: (data) => {
      // Color severity counts
      if (data.column.index === 1 && data.row.index === 2)
        data.cell.styles.textColor = [239, 68, 68];
      if (data.column.index === 1 && data.row.index === 3)
        data.cell.styles.textColor = [249, 115, 22];
      if (data.column.index === 1 && data.row.index === 4)
        data.cell.styles.textColor = [234, 179, 8];
      if (data.column.index === 1 && data.row.index === 5)
        data.cell.styles.textColor = [34, 197, 94];
    },
  });

  yPos = (doc as any).lastAutoTable?.finalY + 15 || yPos + 60;

  // Risk Summary
  doc.setTextColor(30, 27, 75);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text(t.risk_summary, margin, yPos);
  yPos += 8;

  const riskItems = [
    { label: t.critical_findings, count: stats.criticalCount, color: severityColorRGB('critical'), desc: t.risk_critical_desc },
    { label: t.high_findings, count: stats.highCount, color: severityColorRGB('high'), desc: t.risk_high_desc },
    { label: t.medium_findings, count: stats.mediumCount, color: severityColorRGB('medium'), desc: t.risk_medium_desc },
    { label: t.low_findings, count: stats.lowCount, color: severityColorRGB('low'), desc: t.risk_low_desc },
  ];

  for (const item of riskItems) {
    checkPage(20);
    doc.setFillColor(...item.color);
    doc.roundedRect(margin, yPos - 3, 4, 4, 1, 1, 'F');
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(`${item.label}: ${item.count}`, margin + 8, yPos);
    yPos += 5;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(80, 80, 80);
    doc.text(item.desc, margin + 8, yPos);
    yPos += 10;
  }

  // ── FINDINGS DETAIL ──
  if (findings.length === 0) {
    doc.addPage();
    addHeader();
    yPos = 30;
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(12);
    doc.text(t.no_findings, margin, yPos);
  } else {
    doc.addPage();
    addHeader();
    yPos = 22;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text(t.findings_detail, margin, yPos);
    yPos += 10;

    // Findings summary table
    const findingSummaryRows = findings.map((f, i) => [
      `#${i + 1}`,
      f.severity,
      getFindingTypeLabel(f.type, lang),
      f.title.length > 60 ? f.title.substring(0, 57) + '...' : f.title,
      `${f.confidence}%`,
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [[`#`, t.severity, t.type, t.finding, t.confidence]],
      body: findingSummaryRows,
      theme: 'striped',
      styles: { fontSize: 8, cellPadding: 3 },
      headStyles: { fillColor: [30, 27, 75] },
      margin: { left: margin, right: margin },
      didParseCell: (data) => {
        if (data.column.index === 1 && data.section === 'body') {
          const val = String(data.cell.raw).toLowerCase();
          data.cell.styles.textColor = severityColorRGB(val);
          data.cell.styles.fontStyle = 'bold';
        }
      },
    });

    yPos = (doc as any).lastAutoTable?.finalY + 10 || yPos + 40;

    // Individual finding details
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      doc.addPage();
      addHeader();
      yPos = 22;

      // Finding header with severity badge
      const sevColor = severityColorRGB(f.severity);
      doc.setFillColor(...sevColor);
      doc.roundedRect(margin, yPos - 5, contentWidth, 18, 3, 3, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.text(`${t.finding} #${i + 1} — ${f.severity.toUpperCase()}`, margin + 5, yPos + 3);
      doc.setFontSize(8);
      doc.text(`${t.confidence}: ${f.confidence}%`, pageWidth - margin - 5, yPos + 3, { align: 'right' });
      yPos += 20;

      // Title
      doc.setTextColor(0, 0, 0);
      doc.setFontSize(13);
      doc.setFont('helvetica', 'bold');
      const titleLines = doc.splitTextToSize(f.title, contentWidth);
      doc.text(titleLines, margin, yPos);
      yPos += titleLines.length * 6 + 4;

      // Type and MITRE
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(80, 80, 80);
      doc.text(`${t.type}: ${getFindingTypeLabel(f.type, lang)}`, margin, yPos);
      if (f.mitreTactic && f.mitreId) {
        doc.text(`${t.mitre_attack}: ${f.mitreTactic} (${f.mitreId})`, margin + 80, yPos);
      }
      yPos += 8;

      // Description
      doc.setTextColor(0, 0, 0);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(t.description, margin, yPos);
      yPos += 5;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      const descLines = doc.splitTextToSize(f.description, contentWidth);
      doc.text(descLines, margin, yPos);
      yPos += descLines.length * 4.5 + 6;

      // Justification (evidence)
      checkPage(30);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(t.justification, margin, yPos);
      yPos += 5;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setFillColor(245, 245, 250);
      const justLines = doc.splitTextToSize(f.justification, contentWidth - 10);
      const justHeight = justLines.length * 4.5 + 6;
      doc.roundedRect(margin, yPos - 3, contentWidth, justHeight, 2, 2, 'F');
      doc.text(justLines, margin + 5, yPos + 1);
      yPos += justHeight + 6;

      // Affected Assets
      checkPage(20);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(t.affected_assets, margin, yPos);
      yPos += 5;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.text(f.affectedAssets.join(', '), margin, yPos);
      yPos += 8;

      // Indicators
      if (f.indicators.length > 0) {
        checkPage(20);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(t.indicators, margin, yPos);
        yPos += 5;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        for (const ind of f.indicators) {
          checkPage(6);
          doc.text(`• ${ind}`, margin + 3, yPos);
          yPos += 4.5;
        }
        yPos += 4;
      }

      // Recommendation
      checkPage(25);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(t.recommendation, margin, yPos);
      yPos += 5;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      const recLines = doc.splitTextToSize(f.recommendation, contentWidth);
      doc.text(recLines, margin, yPos);
      yPos += recLines.length * 4.5 + 6;

      // Related log count (technical report only)
      if (config.type === 'technical') {
        checkPage(10);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'italic');
        doc.setTextColor(100, 100, 100);
        doc.text(`${t.related_logs}: ${f.relatedLogIds.length} entries`, margin, yPos);
        yPos += 6;
      }
    }
  }

  // ── TOP TABLES (technical report only) ──
  if (config.type === 'technical') {
    // Top Source IPs
    if (stats.topSourceIPs.length > 0) {
      doc.addPage();
      addHeader();
      yPos = 22;
      doc.setTextColor(30, 27, 75);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text(t.top_source_ips, margin, yPos);
      yPos += 8;

      autoTable(doc, {
        startY: yPos,
        head: [['IP', 'Count']],
        body: stats.topSourceIPs.map((s) => [s.ip, s.count.toString()]),
        theme: 'striped',
        styles: { fontSize: 9 },
        headStyles: { fillColor: [30, 27, 75] },
        margin: { left: margin, right: margin },
      });
      yPos = (doc as any).lastAutoTable?.finalY + 15 || yPos + 40;

      // Top Users
      if (stats.topUsers.length > 0) {
        checkPage(40);
        doc.setTextColor(30, 27, 75);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text(t.top_users, margin, yPos);
        yPos += 8;

        autoTable(doc, {
          startY: yPos,
          head: [['User', 'Count']],
          body: stats.topUsers.map((u) => [u.user, u.count.toString()]),
          theme: 'striped',
          styles: { fontSize: 9 },
          headStyles: { fillColor: [30, 27, 75] },
          margin: { left: margin, right: margin },
        });
      }
    }
  }

  // ── Apply footers ──
  addFooter();

  return doc;
}
