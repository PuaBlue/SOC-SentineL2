import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { SecurityFinding, DashboardStats, ReportConfig, Language, SeverityLevel, IPReputation, LogEntry } from '@/types';
import { extractIP } from './threatIntel';
import {
  buildCorrelatedTimeline,
  extractForensiciOCs,
  extractL3TechnicalEvidence,
  getDfirActionPlan,
  getGeneralSecurityRecommendations,
  consolidateThreatFindings,
  ConsolidatedThreatFinding,
  localizeFinding,
} from './dfirForensicReport';

interface ReportData {
  config: ReportConfig;
  findings: SecurityFinding[];
  stats: DashboardStats;
  reputations?: Record<string, IPReputation>;
  logs?: LogEntry[];
}

const labels: Record<Language, Record<string, string>> = {
  en: {
    report_title: 'Security Analysis Report',
    executive_title: 'Executive Cybersecurity Threat Assessment & Incident Summary',
    technical_title: 'Technical Forensic Analysis & Incident Response Report (DFIR)',
    confidential: 'CONFIDENTIAL // TLP:AMBER',
    generated: 'Generated',
    author: 'Author',
    organization: 'Organization',
    executive_summary: 'Executive Summary',
    overview: 'Executive Overview',
    total_events: 'Total SIEM Events Analyzed',
    findings_detected: 'Selected Alerts',
    associated_events: 'Associated Threat Events',
    critical_findings: 'Critical Severity',
    high_findings: 'High Severity',
    medium_findings: 'Medium Severity',
    low_findings: 'Low Severity',
    unique_sources: 'Unique Source IPs',
    unique_users: 'Impacted Accounts',
    analysis_period: 'Observation Period',
    risk_summary: 'Threat Profile',
    status_critical: 'CRITICAL RISK — IMMEDIATE INTERVENTION REQUIRED',
    status_high: 'HIGH RISK — ACTION REQUIRED WITHIN 24 HOURS',
    status_medium: 'MODERATE RISK — ATTENTION REQUIRED WITHIN 72 HOURS',
    status_low: 'LOW RISK — SCHEDULED MAINTENANCE REVIEW',
    chart_events_by_severity: 'Associated Event Volume by Criticality Level',
    chart_events_by_type: 'Event Distribution by Threat Category',
    events_count: 'events',
    findings_count: 'alerts',
    table_num: '#',
    table_category: 'Attack Category',
    table_severity: 'Severity',
    table_events: 'Associated Events',
    table_targets: 'Key Assets Targeted',
    table_confidence: 'Confidence',
    impact_title: '1. Potential Business Impact Assessment',
    impact_confidentiality_title: 'Confidentiality & Data Theft Risk',
    impact_confidentiality_desc: 'Potential unauthorized extraction of proprietary databases, client records, trade secrets, and internal communications.',
    impact_continuity_title: 'Operational Continuity & Downtime',
    impact_continuity_desc: 'Threat of service degradation, ransomware deployment, or interruption of revenue-critical operations.',
    impact_regulatory_title: 'Regulatory & Compliance Liabilities',
    impact_regulatory_desc: 'Exposure under data privacy laws (e.g., GDPR, CCPA, local regulations) with risks of regulatory investigation, fines, and contractual penalties.',
    impact_reputation_title: 'Brand Reputation & Stakeholder Trust',
    impact_reputation_desc: 'Erosion of customer confidence, brand damage, and loss of competitive advantage should the incident escalate or become public.',
    actions_title: '2. Prioritized Immediate Action Plan',
    action_1_title: 'Immediate Credential Revocation & Reset',
    action_1_desc: 'Enforce immediate password reset and invalidate all active session tokens across cloud and on-premise directories for all impacted accounts.',
    action_2_title: 'Endpoint Network Isolation',
    action_2_desc: 'Quarantine flagged hosts and workstations from the internal network (LAN/Wi-Fi) to halt lateral movement while preserving evidence.',
    action_3_title: 'Perimeter IP & Domain Blocking',
    action_3_desc: 'Blacklist all verified malicious external source IP addresses on perimeter firewalls, proxies, and web application firewalls (WAF).',
    action_4_title: 'Activate Incident Response Team',
    action_4_desc: 'Convene the crisis management team to oversee containment and brief executive leadership on mitigation milestones.',
    action_5_title: 'Forensic Evidence Preservation',
    action_5_desc: 'Capture volatile RAM dumps and preserve immutable log trails prior to rebooting or re-imaging compromised systems.',
    findings_detail: 'Forensic Findings Detail',
    finding: 'Finding',
    severity: 'Severity',
    type: 'Type',
    description: 'Description',
    justification: 'Evidence & Technical Justification',
    affected_assets: 'Affected Assets',
    indicators: 'Indicators of Compromise (IoCs)',
    recommendation: 'Remediation Recommendation',
    mitre_attack: 'MITRE ATT&CK',
    confidence: 'Confidence',
    related_logs: 'Related SIEM Log Entries',
    top_source_ips: 'Top Source IPs & External Threat Intelligence',
    top_users: 'Most Active Users',
    events_by_type: 'Events by Type',
    page: 'Page',
    of: 'of',
    no_findings: 'No security findings were selected for this report.',
    disclaimer: 'DISCLAIMER: This report was generated through automated security log analysis. All findings are based strictly on evidence present in the provided log data and corroborated via VirusTotal & AbuseIPDB reputation feeds. No findings have been fabricated or assumed beyond the available evidence.',
    brute_force: 'Brute Force Attack',
    suspicious_login: 'Suspicious Login Pattern',
    privilege_escalation: 'Privilege Escalation',
    anomalous_command: 'Anomalous Command Execution',
    lateral_movement: 'Lateral Movement',
    threat_intel_title: 'External Threat Intelligence (VirusTotal & AbuseIPDB)',
  },
  es: {
    report_title: 'Reporte de Análisis de Seguridad',
    executive_title: 'Informe Ejecutivo de Evaluación de Amenazas e Incidentes de Seguridad',
    technical_title: 'Informe Técnico Forense y Respuesta a Incidentes (DFIR)',
    confidential: 'CONFIDENCIAL // TLP:AMBER',
    generated: 'Generado',
    author: 'Autor',
    organization: 'Organización',
    executive_summary: 'Resumen Ejecutivo',
    overview: 'Resumen General Ejecutivo',
    total_events: 'Total de Eventos SIEM Analizados',
    findings_detected: 'Alertas Seleccionadas',
    associated_events: 'Eventos Asociados a Amenazas',
    critical_findings: 'Severidad Crítica',
    high_findings: 'Severidad Alta',
    medium_findings: 'Severidad Media',
    low_findings: 'Severidad Baja',
    unique_sources: 'IPs Origen Únicas',
    unique_users: 'Cuentas Impactadas',
    analysis_period: 'Período de Observación',
    risk_summary: 'Perfil de Riesgo',
    status_critical: 'ESTADO: RIESGO CRÍTICO — INTERVENCIÓN INMEDIATA REQUERIDA',
    status_high: 'ESTADO: RIESGO ALTO — ACCIÓN REQUERIDA EN 24 HORAS',
    status_medium: 'ESTADO: RIESGO MODERADO — ATENCIÓN EN 72 HORAS',
    status_low: 'ESTADO: RIESGO BAJO — REVISIÓN EN VENTANA DE MANTENIMIENTO',
    chart_events_by_severity: 'Volumen de Eventos Asociados por Nivel de Criticidad',
    chart_events_by_type: 'Distribución de Eventos por Categoría de Amenaza',
    events_count: 'eventos',
    findings_count: 'alertas',
    table_num: '#',
    table_category: 'Categoría de Ataque',
    table_severity: 'Criticidad',
    table_events: 'Eventos Asociados',
    table_targets: 'Activos Clave Afectados',
    table_confidence: 'Confianza',
    impact_title: '1. Evaluación del Impacto Potencial en el Negocio',
    impact_confidentiality_title: 'Riesgo de Fuga y Robo de Información Confidencial',
    impact_confidentiality_desc: 'Extracción o acceso no autorizado a bases de datos de clientes, acuerdos comerciales, secretos de propiedad intelectual y registros internos.',
    impact_continuity_title: 'Interrupción Operativa y Continuidad de Negocio',
    impact_continuity_desc: 'Peligro de degradación de servicios esenciales, secuestro de información mediante ransomware o paradas forzadas en la operación productiva.',
    impact_regulatory_title: 'Responsabilidad Regulatoria y Consecuencias Legales',
    impact_regulatory_desc: 'Exposición a sanciones y multas económicas por incumplimiento de normativas de protección de datos (ej. RGPD, regulaciones locales) y reclamos contractuales.',
    impact_reputation_title: 'Daño Reputacional y Confianza Comercial',
    impact_reputation_desc: 'Erosión de la credibilidad frente a clientes, accionistas y socios de negocio en caso de que el incidente trascienda o escale.',
    actions_title: '2. Plan de Acciones Inmediatas Recomendadas',
    action_1_title: 'Revocación Inmediata de Credenciales',
    action_1_desc: 'Forzar el restablecimiento de contraseñas y cerrar de inmediato todas las sesiones activas en la nube y directorios locales para las cuentas afectadas.',
    action_2_title: 'Aislamiento de Equipos Comprometidos',
    action_2_desc: 'Desconectar de la red corporativa (LAN/Wi-Fi) los puestos de trabajo y servidores señalados para contener el avance del ataque sin alterar evidencias.',
    action_3_title: 'Bloqueo Perimetral de Direcciones IP Maliciosas',
    action_3_desc: 'Incorporar las direcciones IP externas identificadas a las listas de denegación en firewalls perimetrales, proxies y WAF.',
    action_4_title: 'Activación del Comité de Respuesta a Incidentes',
    action_4_desc: 'Convocar al equipo de gestión de crisis y ciberseguridad para coordinar acciones de contingencia y mantener informada a la dirección general.',
    action_5_title: 'Preservación de Evidencias Forenses',
    action_5_desc: 'Realizar volcados de memoria RAM y asegurar copias inmutables de los logs antes de reiniciar o reinstalar cualquier equipo afectado.',
    findings_detail: 'Detalle Forense de Hallazgos',
    finding: 'Hallazgo',
    severity: 'Severidad',
    type: 'Tipo',
    description: 'Descripción',
    justification: 'Evidencia y Justificación Técnica',
    affected_assets: 'Activos Afectados',
    indicators: 'Indicadores de Compromiso (IoCs)',
    recommendation: 'Recomendación Técnica',
    mitre_attack: 'MITRE ATT&CK',
    confidence: 'Confianza',
    related_logs: 'Registros SIEM Relacionados',
    top_source_ips: 'IPs Origen Principales e Inteligencia de Amenazas',
    top_users: 'Usuarios más Activos',
    events_by_type: 'Eventos por Tipo',
    page: 'Página',
    of: 'de',
    no_findings: 'No se seleccionaron alertas de seguridad para este reporte.',
    disclaimer: 'AVISO: Este reporte fue generado mediante análisis automatizado de logs de seguridad. Todos los hallazgos se basan estrictamente en la evidencia presente en los datos SIEM y se corroboran mediante fuentes de reputación de VirusTotal y AbuseIPDB. Ningún hallazgo ha sido fabricado o asumido más allá de la evidencia disponible.',
    brute_force: 'Ataque de Fuerza Bruta',
    suspicious_login: 'Patrón de Inicio de Sesión Sospechoso',
    privilege_escalation: 'Escalamiento de Privilegios',
    anomalous_command: 'Ejecución de Comandos Anómalos',
    lateral_movement: 'Movimiento Lateral',
    threat_intel_title: 'Inteligencia Externa de Amenazas (VirusTotal y AbuseIPDB)',
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
    default: return [100, 116, 139];
  }
}

// Draw a proportional horizontal vector bar chart directly onto PDF
function drawVectorBar(
  doc: jsPDF,
  startX: number,
  startY: number,
  totalWidth: number,
  height: number,
  segments: { count: number; color: [number, number, number]; label: string }[]
) {
  const total = segments.reduce((sum, s) => sum + s.count, 0);
  if (total <= 0) return startY + height + 10;

  let currentX = startX;
  doc.setLineWidth(0.2);
  doc.setDrawColor(255, 255, 255);

  segments.forEach((seg) => {
    if (seg.count <= 0) return;
    const segWidth = (seg.count / total) * totalWidth;
    doc.setFillColor(...seg.color);
    doc.rect(currentX, startY, segWidth, height, 'FD');
    currentX += segWidth;
  });

  const legendY = startY + height + 5;
  let legendX = startX;
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');

  segments.forEach((seg) => {
    if (seg.count <= 0) return;
    doc.setFillColor(...seg.color);
    doc.circle(legendX + 2, legendY - 1, 1.8, 'F');
    doc.setTextColor(51, 65, 85);
    const pct = Math.round((seg.count / total) * 100);
    const text = `${seg.label}: ${seg.count.toLocaleString()} (${pct}%)`;
    doc.text(text, legendX + 6, legendY);
    legendX += doc.getTextWidth(text) + 10;
  });

  return legendY + 10;
}

// Main Report Generator (Executive vs Technical)
export function generatePDF(data: ReportData): jsPDF {
  const { config, findings, stats, reputations, logs = [] } = data;
  const lang = config.language;
  const t = labels[lang];
  const doc = new jsPDF('p', 'mm', 'a4');
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;

  let yPos = 0;

  // Header
  function addHeader() {
    doc.setFillColor(30, 27, 75); // Brand Dark #1e1b4b
    doc.rect(0, 0, pageWidth, 12, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text(t.confidential, pageWidth / 2, 8, { align: 'center' });
    doc.setTextColor(0, 0, 0);
  }

  // Footer
  function addFooter() {
    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFillColor(30, 27, 75);
      doc.rect(0, pageHeight - 10, pageWidth, 10, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
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

  function checkPage(neededHeight: number = 30) {
    if (yPos + neededHeight > pageHeight - 25) {
      doc.addPage();
      yPos = margin;
      addHeader();
    }
  }

  // ═════════════════════════════════════════════════════════════
  // COVER PAGE (Both Executive and Technical)
  // ═════════════════════════════════════════════════════════════
  addHeader();

  // Primary Cover Banner
  doc.setFillColor(30, 27, 75);
  doc.rect(margin, 35, contentWidth, 80, 'F');

  // Decorative Accent bar
  doc.setFillColor(79, 70, 229); // Indigo 600
  doc.rect(margin, 35, 4, 80, 'F');

  // Badge: Report Type
  doc.setFillColor(49, 46, 129); // Indigo 900
  doc.roundedRect(margin + 12, 45, 85, 7, 1.5, 1.5, 'F');
  doc.setTextColor(199, 210, 254); // Indigo 200
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'bold');
  const typeBadgeText = config.type === 'executive'
    ? (lang === 'es' ? 'RESUMEN EJECUTIVO (NIVEL GERENCIAL)' : 'EXECUTIVE SUMMARY (LEADERSHIP BRIEF)')
    : (lang === 'es' ? 'INFORME TÉCNICO FORENSE (SOC NIVEL 2)' : 'TECHNICAL FORENSIC REPORT (SOC LEVEL 2)');
  doc.text(typeBadgeText, margin + 15, 49.5);

  // Main Report Title
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  let mainTitle = config.title;
  if (!mainTitle || (config.type === 'technical' && (mainTitle.includes('Ejecutivo') || mainTitle.includes('Executive')))) {
    mainTitle = config.type === 'executive' ? t.executive_title : t.technical_title;
  }
  const titleLines = doc.splitTextToSize(mainTitle, contentWidth - 25);
  doc.text(titleLines, margin + 12, 63);

  // Subtitle
  doc.setFontSize(9.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(203, 213, 225);
  const subtitle = config.type === 'executive'
    ? (lang === 'es'
        ? 'Evaluación estratégica de riesgos, impacto comercial y plan de acción priorizado'
        : 'Strategic risk evaluation, business impact assessment, and prioritized remediation actions')
    : (lang === 'es'
        ? 'Análisis forense DFIR, correlación cronológica de incidentes y telemetría técnica para escalamiento L3'
        : 'Deep DFIR investigation, incident correlation, raw telemetry, and IOC intelligence for Level 3 escalation');
  const subtitleLines = doc.splitTextToSize(subtitle, contentWidth - 25);
  doc.text(subtitleLines, margin + 12, 78);

  // Risk Classification Status Box on Cover
  let statusText = t.status_low;
  let statusBg: [number, number, number] = [34, 197, 94];
  if (findings.some((f) => f.severity === 'Critical')) {
    statusText = t.status_critical;
    statusBg = [220, 38, 38];
  } else if (findings.some((f) => f.severity === 'High')) {
    statusText = t.status_high;
    statusBg = [234, 88, 12];
  } else if (findings.some((f) => f.severity === 'Medium')) {
    statusText = t.status_medium;
    statusBg = [202, 138, 4];
  }

  doc.setFillColor(...statusBg);
  doc.roundedRect(margin, 122, contentWidth, 12, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(8.5);
  doc.setFont('helvetica', 'bold');
  doc.text(statusText, pageWidth / 2, 129.5, { align: 'center' });

  // Metadata Card
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, 140, contentWidth, 48, 3, 3, 'FD');

  const metaItems = [
    [t.organization, config.organization || 'Enterprise Cyber Defense Services'],
    [t.author, config.author || 'Lead SOC Analyst (L2)'],
    [t.generated, new Date().toLocaleString(lang === 'es' ? 'es-ES' : 'en-US')],
    [t.findings_detected, `${findings.length} ${t.findings_count}`],
  ];

  doc.setFontSize(9);
  metaItems.forEach((item, idx) => {
    const rowY = 150 + idx * 10;
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(71, 85, 105);
    const labelStr = item[0] + ':';
    doc.text(labelStr, margin + 8, rowY);

    const labelWidth = doc.getTextWidth(labelStr);
    const valX = Math.max(margin + 58, margin + 8 + labelWidth + 5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(15, 23, 42);
    doc.text(item[1], valX, rowY);
  });

  // ═════════════════════════════════════════════════════════════
  // BRANCH: EXECUTIVE BRIEFING REPORT
  // ═════════════════════════════════════════════════════════════
  if (config.type === 'executive') {
    doc.addPage();
    addHeader();
    yPos = 24;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(t.overview, margin, yPos);
    yPos += 8;

    const criticalCount = findings.filter((f) => f.severity === 'Critical').length;
    const highCount = findings.filter((f) => f.severity === 'High').length;
    const mediumCount = findings.filter((f) => f.severity === 'Medium').length;
    const lowCount = findings.filter((f) => f.severity === 'Low').length;

    // Vector proportional bar chart
    if (config.includeCharts && findings.length > 0) {
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 27, 75);
      doc.text(t.chart_events_by_severity, margin, yPos);
      yPos += 5;

      const segments = [
        { count: criticalCount, color: [239, 68, 68] as [number, number, number], label: t.critical_findings },
        { count: highCount, color: [249, 115, 22] as [number, number, number], label: t.high_findings },
        { count: mediumCount, color: [234, 179, 8] as [number, number, number], label: t.medium_findings },
        { count: lowCount, color: [34, 197, 94] as [number, number, number], label: t.low_findings },
      ];

      yPos = drawVectorBar(doc, margin, yPos, contentWidth, 8, segments);
      yPos += 4;
    }

    // High Level Findings Summary Table (Consolidated threat vectors)
    const consolidatedExec = consolidateThreatFindings(findings, logs, lang);
    const summaryRows = consolidatedExec.map((c, i) => [
      `#${i + 1}`,
      c.categoryLabel,
      c.severity,
      `${c.totalEvents} ${t.events_count}`,
      c.assets.slice(0, 3).join('\n') + (c.assets.length > 3 ? `\n(+${c.assets.length - 3} ${lang === 'es' ? 'más' : 'more'})` : ''),
      `${c.confidence}%`,
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [[t.table_num, t.table_category, t.table_severity, t.table_events, t.table_targets, t.table_confidence]],
      body: summaryRows,
      theme: 'striped',
      styles: { fontSize: 7.5, cellPadding: 2.2, overflow: 'linebreak', valign: 'middle' },
      headStyles: { fillColor: [30, 27, 75], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 7.5, valign: 'middle' },
      columnStyles: {
        0: { cellWidth: 8, halign: 'center' },
        1: { cellWidth: 42, halign: 'left' },
        2: { cellWidth: 20, halign: 'center' },
        3: { cellWidth: 24, halign: 'center' },
        4: { cellWidth: 62, halign: 'left' },
        5: { cellWidth: 24, halign: 'center' },
      },
      margin: { left: margin, right: margin },
      didParseCell: (cellData) => {
        if (cellData.column.index === 2 && cellData.section === 'body') {
          const val = String(cellData.cell.raw).toLowerCase();
          cellData.cell.styles.textColor = severityColorRGB(val);
          cellData.cell.styles.fontStyle = 'bold';
        }
      },
    });

    yPos = (doc as any).lastAutoTable?.finalY + 12 || yPos + 60;

    // Direct Executive Business Impact Assessment
    checkPage(45);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 27, 75);
    doc.text(t.impact_title, margin, yPos);
    yPos += 6;

    const impacts = [
      { title: t.impact_confidentiality_title, desc: t.impact_confidentiality_desc, color: [220, 38, 38] as [number, number, number] },
      { title: t.impact_continuity_title, desc: t.impact_continuity_desc, color: [234, 88, 12] as [number, number, number] },
      { title: t.impact_regulatory_title, desc: t.impact_regulatory_desc, color: [202, 138, 4] as [number, number, number] },
      { title: t.impact_reputation_title, desc: t.impact_reputation_desc, color: [79, 70, 229] as [number, number, number] },
    ];

    impacts.forEach((imp) => {
      checkPage(16);
      doc.setFillColor(...imp.color);
      doc.rect(margin, yPos - 1, 2.5, 9, 'F');
      doc.setTextColor(15, 23, 42);
      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'bold');
      doc.text(imp.title, margin + 6, yPos + 2.5);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      const descLines = doc.splitTextToSize(imp.desc, contentWidth - 10);
      doc.text(descLines, margin + 6, yPos + 7);
      yPos += descLines.length * 3.8 + 6;
    });

    // Immediate Action Plan
    checkPage(45);
    yPos += 4;
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 27, 75);
    doc.text(t.actions_title, margin, yPos);
    yPos += 6;

    const actionList = [
      { title: t.action_1_title, desc: t.action_1_desc },
      { title: t.action_2_title, desc: t.action_2_desc },
      { title: t.action_3_title, desc: t.action_3_desc },
      { title: t.action_4_title, desc: t.action_4_desc },
      { title: t.action_5_title, desc: t.action_5_desc },
    ];

    actionList.forEach((act, idx) => {
      checkPage(16);
      doc.setFillColor(30, 27, 75);
      doc.circle(margin + 2.5, yPos + 1.5, 2.5, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'bold');
      doc.text(String(idx + 1), margin + 2.5, yPos + 2.3, { align: 'center' });

      doc.setTextColor(15, 23, 42);
      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'bold');
      doc.text(act.title, margin + 8, yPos + 2);
      yPos += 5.5;

      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      const actDescLines = doc.splitTextToSize(act.desc, contentWidth - 8);
      doc.text(actDescLines, margin + 8, yPos);
      yPos += actDescLines.length * 3.8 + 4;
    });
  }

  // ═════════════════════════════════════════════════════════════
  // BRANCH: TECHNICAL FORENSIC REPORT (DFIR / SOC NIVEL 2 -> L3)
  // Strict compliance with the 8 syllabus sections:
  // 1. Resumen ejecutivo
  // 2. Hallazgos identificados
  // 3. Explicación técnica de cada hallazgo
  // 4. Evidencias encontradas en los logs
  // 5. Criticidad y justificación
  // 6. Posible impacto en la organización
  // 7. Plan de acción: investigar, contener y remediar
  // 8. Recomendaciones generales de seguridad
  // ═════════════════════════════════════════════════════════════
  if (config.type === 'technical') {
    const isEs = lang === 'es';
    const consolidatedThreats = consolidateThreatFindings(findings, logs, lang);
    const l3Telemetry = extractL3TechnicalEvidence(findings, logs, lang);
    const forensiciOCs = extractForensiciOCs(findings, reputations || {}, logs, lang);
    const dfirPlan = getDfirActionPlan(findings, lang);
    const generalRecs = getGeneralSecurityRecommendations(lang);

    const sectionPages: Record<string, number> = {
      resumenEjecutivo: 2,
      hallazgosIdentificados: 2,
      explicacionTecnica: 2,
      evidenciasLogs: 2,
      criticidadJustificacion: 2,
      impactoOrganizacion: 2,
      planAccion: 2,
      recomendacionesGenerales: 2,
    };

    // ── SECTION 1: RESUMEN EJECUTIVO & SCOPE DE TELEMETRÍA ──
    doc.addPage();
    addHeader();
    sectionPages.resumenEjecutivo = (doc as any).internal.getNumberOfPages();
    yPos = 24;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '1. RESUMEN EJECUTIVO FORENSE' : '1. EXECUTIVE FORENSIC SUMMARY',
      margin,
      yPos
    );
    yPos += 6;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    const execNarrative = isEs
      ? 'Durante la ventana de auditoría forense, el equipo SOC Nivel 2 identificó y correlacionó una secuencia de intrusión multifásica contra la infraestructura corporativa. El adversario inició con ataques automatizados de fuerza bruta hacia servicios de autenticación, logrando el compromiso de credenciales corporativas e inicios de sesión anómalos. Posteriormente, ejecutó intérpretes de comandos nativos (PowerShell) con argumentos codificados en Base64 para evadir mecanismos de detección perimetral, escaló privilegios y desplegó utilidades de movimiento lateral hacia servidores internos. La postura global del incidente se clasifica como CRÍTICA, requiriendo contención y erradicación inmediata.'
      : 'During the forensic audit window, the SOC Level 2 team identified and correlated a multi-phase intrusion sequence against corporate infrastructure. The adversary conducted brute force attacks against authentication endpoints, compromising corporate credentials and generating suspicious logins. Native command shells (PowerShell) were subsequently invoked using Base64 encoded arguments to evade perimeter detection, followed by privilege escalation and lateral propagation toward internal servers. The global incident posture is classified as CRITICAL, requiring immediate containment and eradication.';
    const execNarrativeLines = doc.splitTextToSize(execNarrative, contentWidth);
    doc.text(execNarrativeLines, margin, yPos);
    yPos += execNarrativeLines.length * 3.8 + 6;

    // Scope Table
    const overviewData = [
      [t.total_events, stats.totalLogs.toLocaleString()],
      [isEs ? 'Alertas Consolidadas' : 'Consolidated Threat Vectors', `${findings.length} ${t.findings_count} (${consolidatedThreats.length} ${isEs ? 'vectores consolidados' : 'threat vectors'})`],
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
      styles: { fontSize: 8, cellPadding: 2.8 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 70 },
        1: { cellWidth: contentWidth - 70 },
      },
      margin: { left: margin, right: margin },
      didParseCell: (cellData) => {
        if (cellData.column.index === 1 && cellData.row.index === 2)
          cellData.cell.styles.textColor = [239, 68, 68];
        if (cellData.column.index === 1 && cellData.row.index === 3)
          cellData.cell.styles.textColor = [249, 115, 22];
        if (cellData.column.index === 1 && cellData.row.index === 4)
          cellData.cell.styles.textColor = [234, 179, 8];
        if (cellData.column.index === 1 && cellData.row.index === 5)
          cellData.cell.styles.textColor = [34, 197, 94];
      },
    });
    yPos = (doc as any).lastAutoTable?.finalY + 10 || yPos + 45;

    // ── SECTION 2: HALLAZGOS IDENTIFICADOS ──
    checkPage(40);
    sectionPages.hallazgosIdentificados = (doc as any).internal.getNumberOfPages();
    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '2. HALLAZGOS IDENTIFICADOS' : '2. IDENTIFIED SECURITY FINDINGS',
      margin,
      yPos
    );
    yPos += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(
      isEs
        ? 'Matriz sintética y consolidada de vectores de ataque detectados en la auditoría SIEM:'
        : 'Synthetic, consolidated matrix of attack vectors detected across the SIEM audit window:',
      margin,
      yPos
    );
    yPos += 6;

    const findingsTableHeaders = isEs
      ? ['#', 'Vector de Amenaza / Categoría', 'Severidad', 'Eventos', 'Activos Clave Afectados', 'Confianza']
      : ['#', 'Threat Vector / Category', 'Severity', 'Events', 'Targeted Key Assets', 'Confidence'];

    const findingsTableBody = consolidatedThreats.map((threat, idx) => [
      String(idx + 1),
      threat.categoryLabel,
      threat.severity.toUpperCase(),
      threat.totalEvents.toLocaleString(),
      threat.assets.join(', '),
      `${threat.confidence}%`,
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [findingsTableHeaders],
      body: findingsTableBody,
      theme: 'grid',
      styles: { fontSize: 7.5, cellPadding: 2.8, overflow: 'linebreak' },
      headStyles: { fillColor: [30, 27, 75], textColor: [255, 255, 255], fontStyle: 'bold' },
      columnStyles: {
        0: { cellWidth: 8, halign: 'center' },
        1: { cellWidth: 44, fontStyle: 'bold' },
        2: { cellWidth: 20, halign: 'center', fontStyle: 'bold' },
        3: { cellWidth: 18, halign: 'center' },
        4: { cellWidth: 66 },
        5: { cellWidth: 24, halign: 'center' },
      },
      margin: { left: margin, right: margin },
      didParseCell: (cellData) => {
        if (cellData.section === 'body' && cellData.column.index === 2) {
          const sev = String(cellData.cell.raw).toLowerCase();
          if (sev === 'critical') cellData.cell.styles.textColor = [220, 38, 38];
          else if (sev === 'high') cellData.cell.styles.textColor = [234, 88, 12];
          else if (sev === 'medium') cellData.cell.styles.textColor = [202, 138, 4];
          else cellData.cell.styles.textColor = [22, 163, 74];
        }
      },
    });
    yPos = (doc as any).lastAutoTable?.finalY + 12 || yPos + 40;

    // ── SECTION 3: EXPLICACIÓN TÉCNICA DE CADA HALLAZGO ──
    doc.addPage();
    addHeader();
    sectionPages.explicacionTecnica = (doc as any).internal.getNumberOfPages();
    yPos = 24;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '3. EXPLICACIÓN TÉCNICA DE CADA HALLAZGO' : '3. TECHNICAL EXPLANATION OF EACH FINDING',
      margin,
      yPos
    );
    yPos += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(
      isEs
        ? 'Desglose analítico de los vectores identificados, tácticas MITRE ATT&CK y mecánica operativa observada:'
        : 'Detailed forensic breakdown of identified vectors, MITRE ATT&CK mappings, and adversary mechanics:',
      margin,
      yPos
    );
    yPos += 7;

    for (let idx = 0; idx < consolidatedThreats.length; idx++) {
      const threat = consolidatedThreats[idx];
      const sevColor = severityColorRGB(threat.severity);

      const headerTitle = `#${idx + 1} — ${threat.categoryLabel}`;
      const mitreBadge = `MITRE: ${threat.mitreTactic} (${threat.mitreId}) | ${threat.severity.toUpperCase()}`;
      
      // Strict inner width: margin + 6 on left, 10mm margin on right (ends at 185mm inside 195mm box)
      const maxCardTextWidth = contentWidth - 16;

      // Set font and size BEFORE calling splitTextToSize so measurements are 100% exact
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.8);
      const explLines = doc.splitTextToSize(threat.technicalExplanation, maxCardTextWidth);

      const assetLine = `${isEs ? 'Activos impactados' : 'Impacted assets'}: ${threat.assets.join(', ')}`;
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(7);
      const assetLines = doc.splitTextToSize(assetLine, maxCardTextWidth);

      const cardHeight = explLines.length * 3.8 + assetLines.length * 3.4 + 16;
      checkPage(cardHeight + 4);

      // Outer container
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, yPos - 2, contentWidth, cardHeight, 2, 2, 'FD');

      // Left color accent bar
      doc.setFillColor(...sevColor);
      doc.rect(margin, yPos - 2, 3.5, cardHeight, 'F');

      let innerY = yPos + 3;

      // Title & MITRE badge
      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(headerTitle, margin + 6, innerY);

      doc.setFontSize(7.2);
      doc.setTextColor(...sevColor);
      doc.text(mitreBadge, pageWidth - margin - 6, innerY, { align: 'right' });
      innerY += 6;

      // Technical Explanation Body
      doc.setFontSize(7.8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.text(explLines, margin + 6, innerY);
      innerY += explLines.length * 3.8 + 2;

      // Assets footer in card
      doc.setFontSize(7);
      doc.setFont('helvetica', 'italic');
      doc.setTextColor(100, 116, 139);
      doc.text(assetLines, margin + 6, innerY);

      yPos += cardHeight + 4;
    }
    yPos += 4;

    // ── SECTION 4: EVIDENCIAS ENCONTRADAS EN LOS LOGS ──
    doc.addPage();
    addHeader();
    sectionPages.evidenciasLogs = (doc as any).internal.getNumberOfPages();
    yPos = 24;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '4. EVIDENCIAS ENCONTRADAS EN LOS LOGS' : '4. LOG EVIDENCE & FORENSIC TELEMETRY',
      margin,
      yPos
    );
    yPos += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(
      isEs
        ? 'Telemetría forense representativa: Event IDs de Windows, comandos de terminal ejecutados y contexto CTI:'
        : 'Representative forensic telemetry: Windows Event IDs, executed CLI commands, and threat intelligence context:',
      margin,
      yPos
    );
    yPos += 7;

    // 4.1 Event IDs Table
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 27, 75);
    doc.text(
      isEs ? '4.1. Event IDs Clave Auditados en los Registros del Sistema' : '4.1. Key Audited System Event IDs',
      margin,
      yPos
    );
    yPos += 4;

    const eventIdRows = [
      ['Event ID 4625', isEs ? 'Intento fallido de inicio de sesión (Logon Failure)' : 'Logon Failure', isEs ? 'Ráfagas automatizadas de fuerza bruta RDP/SMB' : 'Automated brute force bursts over RDP/SMB'],
      ['Event ID 4624', isEs ? 'Inicio de sesión exitoso (Logon Type 10 / Remote Interactive)' : 'Successful Logon (Type 10)', isEs ? 'Compromiso y uso de credenciales corporativas' : 'Corporate credential compromise & usage'],
      ['Event ID 4672', isEs ? 'Asignación de privilegios especiales a nueva sesión' : 'Special Privileges Assigned', isEs ? 'Uso indebido de privilegios administrativos' : 'Administrative privilege misuse'],
      ['Event ID 4688', isEs ? 'Creación de nuevo proceso con línea de comandos' : 'New Process Created with Command Line', isEs ? 'Invocación de powershell.exe y cmd.exe con parámetros' : 'powershell.exe / cmd.exe CLI execution'],
      ['Event ID 7045 / 7036', isEs ? 'Servicio nuevo instalado / Operación de servicio' : 'New Service Installed / Service Operation', isEs ? 'Ejecución remota vía servicio PSEXESVC / movimiento lateral' : 'Remote execution via PSEXESVC / lateral movement'],
    ];

    autoTable(doc, {
      startY: yPos,
      head: [isEs ? ['Evento', 'Definición Forense', 'Relevancia en el Incidente'] : ['Event', 'Forensic Definition', 'Incident Relevance']],
      body: eventIdRows,
      theme: 'striped',
      styles: { fontSize: 7.5, cellPadding: 2.2 },
      headStyles: { fillColor: [30, 27, 75], fontStyle: 'bold' },
      columnStyles: {
        0: { cellWidth: 32, fontStyle: 'bold' },
        1: { cellWidth: 68 },
        2: { cellWidth: 80 },
      },
      margin: { left: margin, right: margin },
    });
    yPos = (doc as any).lastAutoTable?.finalY + 8 || yPos + 35;

    // 4.2 Raw Command Telemetry (Terminal Cards - Top 2 representative items)
    if (l3Telemetry.length > 0) {
      checkPage(45);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 27, 75);
      doc.text(
        isEs ? '4.2. Telemetría Cruda de Comandos CLI (Escalamiento Nivel 3)' : '4.2. Raw CLI Terminal Telemetry (Level 3 Escalation)',
        margin,
        yPos
      );
      yPos += 5;

      const sampleTelemetry = l3Telemetry.slice(0, 2);
      for (const te of sampleTelemetry) {
        const maxTextWidth = contentWidth - 8;
        const headerStr = `[${te.timestamp}] HOST: ${te.host} | USER: ${te.user} | MITRE: ${te.mitreId}`;
        const cmdStr = `CLI> ${te.rawCommand || te.evidenceText}`;
        const cmdLines = doc.splitTextToSize(cmdStr, maxTextWidth).slice(0, 2);
        const decodedLines = te.decodedCommand
          ? doc.splitTextToSize(`DECODED> ${te.decodedCommand}`, maxTextWidth).slice(0, 2)
          : [];
        const pLines = te.processTree.slice(0, 2).map((p) => `  ${p}`);

        let cardHeight = 14 + cmdLines.length * 3.2 + (decodedLines.length > 0 ? decodedLines.length * 3.2 + 2 : 0) + pLines.length * 3.2;
        checkPage(cardHeight + 4);

        doc.setFillColor(15, 23, 42); // Terminal Slate 900
        doc.roundedRect(margin, yPos - 2, contentWidth, cardHeight, 1.5, 1.5, 'F');

        let innerY = yPos + 2;
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(56, 189, 248); // Cyan
        doc.text(headerStr, margin + 4, innerY);
        innerY += 4.5;

        doc.setFont('courier', 'bold');
        doc.setFontSize(6.8);
        doc.setTextColor(248, 113, 113); // Red
        doc.text(cmdLines, margin + 4, innerY);
        innerY += cmdLines.length * 3.2 + 1.5;

        if (decodedLines.length > 0) {
          doc.setTextColor(74, 222, 128); // Green
          doc.text(decodedLines, margin + 4, innerY);
          innerY += decodedLines.length * 3.2 + 1.5;
        }

        doc.setFont('courier', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(165, 180, 252);
        for (const p of pLines) {
          doc.text(p, margin + 4, innerY);
          innerY += 3.2;
        }

        yPos += cardHeight + 4;
      }
      yPos += 2;
    }

    // 4.3 Structured IoCs Table
    if (forensiciOCs.length > 0) {
      checkPage(35);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 27, 75);
      doc.text(
        isEs ? '4.3. Matriz de Indicadores de Compromiso (IoCs) e Inteligencia CTI' : '4.3. Indicators of Compromise (IoCs) & CTI Context',
        margin,
        yPos
      );
      yPos += 4;

      const iocRows = forensiciOCs.slice(0, 6).map((ioc) => [
        ioc.type,
        ioc.value,
        ioc.ctiContext,
        ioc.role,
      ]);

      autoTable(doc, {
        startY: yPos,
        head: [isEs ? ['Tipo IoC', 'Valor', 'Inteligencia de Amenazas (CTI)', 'Rol en el Ataque'] : ['IoC Type', 'Value', 'CTI Context', 'Attack Role']],
        body: iocRows,
        theme: 'grid',
        styles: { fontSize: 7, cellPadding: 2.2, overflow: 'linebreak' },
        headStyles: { fillColor: [30, 27, 75], fontStyle: 'bold' },
        columnStyles: {
          0: { cellWidth: 26, fontStyle: 'bold' },
          1: { cellWidth: 42, fontStyle: 'bold', textColor: [220, 38, 38] },
          2: { cellWidth: 74 },
          3: { cellWidth: 38 },
        },
        margin: { left: margin, right: margin },
      });
      yPos = (doc as any).lastAutoTable?.finalY + 10 || yPos + 35;
    }

    // ── SECTION 5: CRITICIDAD Y JUSTIFICACIÓN ──
    doc.addPage();
    addHeader();
    sectionPages.criticidadJustificacion = (doc as any).internal.getNumberOfPages();
    yPos = 24;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '5. CRITICIDAD Y JUSTIFICACIÓN' : '5. CRITICALITY & TECHNICAL JUSTIFICATION',
      margin,
      yPos
    );
    yPos += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(
      isEs
        ? 'Ponderación analítica del nivel de riesgo atribuido a cada vector de amenaza detectado:'
        : 'Analytical risk evaluation and justification for each detected attack vector:',
      margin,
      yPos
    );
    yPos += 6;

    for (const threat of consolidatedThreats) {
      const sevColor = severityColorRGB(threat.severity);
      const maxTextWidth = contentWidth - 16;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      const justLines = doc.splitTextToSize(threat.criticalityJustification, maxTextWidth);
      const boxHeight = justLines.length * 3.8 + 12;

      checkPage(boxHeight + 4);

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, yPos - 2, contentWidth, boxHeight, 1.5, 1.5, 'FD');

      doc.setFillColor(...sevColor);
      doc.rect(margin, yPos - 2, 3.5, boxHeight, 'F');

      let innerY = yPos + 3;
      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...sevColor);
      doc.text(`[${threat.severity.toUpperCase()}] ${threat.categoryLabel}`, margin + 6, innerY);
      innerY += 5;

      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.text(justLines, margin + 6, innerY);

      yPos += boxHeight + 4;
    }
    yPos += 4;

    // ── SECTION 6: POSIBLE IMPACTO EN LA ORGANIZACIÓN ──
    checkPage(50);
    sectionPages.impactoOrganizacion = (doc as any).internal.getNumberOfPages();
    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '6. POSIBLE IMPACTO EN LA ORGANIZACIÓN' : '6. POTENTIAL ORGANIZATIONAL IMPACT',
      margin,
      yPos
    );
    yPos += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(
      isEs
        ? 'Evaluación forense del impacto potencial sobre los activos, procesos y reputación institucional:'
        : 'Forensic evaluation of potential consequences across organizational assets, processes, and reputation:',
      margin,
      yPos
    );
    yPos += 6;

    const impactCards = [
      {
        title: isEs ? 'A. Confidencialidad y Fuga de Información Crítica' : 'A. Confidentiality & Critical Data Theft',
        desc: isEs
          ? 'El compromiso de credenciales corporativas y cuentas administrativas expone bases de datos operativas, secretos comerciales y propiedad intelectual a accesos no autorizados y potencial exfiltración.'
          : 'Compromised corporate and administrative credentials expose proprietary databases, trade secrets, and intellectual property to unauthorized access and exfiltration.',
      },
      {
        title: isEs ? 'B. Continuidad Operativa y Riesgo de Ransomware' : 'B. Operational Continuity & Ransomware Threat',
        desc: isEs
          ? 'La ejecución de comandos ofuscados de PowerShell y el movimiento lateral hacia servidores de archivos (FS-SRV01) son indicativos directos de etapas previas a un despliegue de ransomware destructivo, arriesgando la parálisis total de operaciones.'
          : 'Obfuscated PowerShell executions and lateral movement toward file servers (FS-SRV01) constitute direct precursors to ransomware deployment, risking complete operational paralysis.',
      },
      {
        title: isEs ? 'C. Responsabilidad Regulatoria y Consecuencias Legales' : 'C. Regulatory Liabilities & Legal Exposure',
        desc: isEs
          ? 'La intrusión no contenida compromete registros de empleados y clientes, activando mandatos de notificación de brechas de seguridad conforme a normativas de protección de datos (RGPD / leyes nacionales) bajo riesgo de penalizaciones económicas severas.'
          : 'Uncontained intrusion compromising customer or employee data activates mandatory breach notification requirements under data protection regulations (GDPR/local laws), with severe financial penalties.',
      },
      {
        title: isEs ? 'D. Daño Reputacional y Confianza Comercial' : 'D. Brand Reputation & Stakeholder Trust',
        desc: isEs
          ? 'La divulgación pública de un incidente de intrusión y exfiltración socava la credibilidad de la organización frente a clientes estratégicos, socios comerciales y entidades auditoras.'
          : 'Public disclosure of an uncontained network compromise erodes stakeholder confidence, partner trust, and market reputation.',
      },
    ];

    for (const card of impactCards) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      const cardLines = doc.splitTextToSize(card.desc, contentWidth - 16);
      const cardHeight = cardLines.length * 3.6 + 10;
      checkPage(cardHeight + 3);

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, yPos - 2, contentWidth, cardHeight, 1.5, 1.5, 'FD');

      doc.setFillColor(79, 70, 229); // Indigo
      doc.rect(margin, yPos - 2, 3, cardHeight, 'F');

      let innerY = yPos + 3;
      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 27, 75);
      doc.text(card.title, margin + 6, innerY);
      innerY += 4.5;

      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text(cardLines, margin + 6, innerY);

      yPos += cardHeight + 3;
    }
    yPos += 4;

    // ── SECTION 7: PLAN DE ACCIÓN: INVESTIGAR, CONTENER Y REMEDIAR ──
    doc.addPage();
    addHeader();
    sectionPages.planAccion = (doc as any).internal.getNumberOfPages();
    yPos = 24;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '7. PLAN DE ACCIÓN: INVESTIGAR, CONTENER Y REMEDIAR' : '7. ACTION PLAN: INVESTIGATE, CONTAIN & REMEDIATE',
      margin,
      yPos
    );
    yPos += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(
      isEs
        ? 'Protocolo operativo forense DFIR estructurado en 3 fases de respuesta a incidentes:'
        : 'Operational DFIR incident response protocol structured into 3 technical phases:',
      margin,
      yPos
    );
    yPos += 7;

    const actionPhases = [
      {
        badge: isEs ? 'FASE 1: INVESTIGAR (TRIAGE FORENSE Y TRAZABILIDAD)' : 'PHASE 1: INVESTIGATE (FORENSIC TRIAGE & TRACEABILITY)',
        color: [79, 70, 229] as [number, number, number],
        steps: dfirPlan.phase2, // Forensic analysis and investigation
      },
      {
        badge: isEs ? 'FASE 2: CONTENER (AISLAMIENTO Y BLOQUEO PERIMETRAL)' : 'PHASE 2: CONTAIN (ISOLATION & PERIMETER BLOCKING)',
        color: [220, 38, 38] as [number, number, number],
        steps: dfirPlan.phase1, // Immediate containment
      },
      {
        badge: isEs ? 'FASE 3: REMEDIAR (ERRADICACIÓN Y RECUPERACIÓN)' : 'PHASE 3: REMEDIATE (ERADICATION & RECOVERY)',
        color: [22, 163, 74] as [number, number, number],
        steps: dfirPlan.phase3, // Remediation & hardening
      },
    ];

    for (const ph of actionPhases) {
      checkPage(25);
      doc.setFillColor(...ph.color);
      doc.roundedRect(margin, yPos - 2, contentWidth, 6, 1.5, 1.5, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.text(ph.badge, margin + 4, yPos + 2.2);
      yPos += 8;

      for (const st of ph.steps) {
        checkPage(14);
        doc.setTextColor(15, 23, 42);
        doc.setFontSize(7.8);
        doc.setFont('helvetica', 'bold');
        doc.text(`• ${st.title}`, margin + 3, yPos);
        yPos += 3.8;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.2);
        doc.setTextColor(71, 85, 105);
        const stLines = doc.splitTextToSize(st.desc, contentWidth - 6);
        doc.text(stLines, margin + 6, yPos);
        yPos += stLines.length * 3.4 + 2.5;
      }
      yPos += 2;
    }
    yPos += 4;

    // ── SECTION 8: RECOMENDACIONES GENERALES DE SEGURIDAD ──
    checkPage(45);
    sectionPages.recomendacionesGenerales = (doc as any).internal.getNumberOfPages();
    doc.setTextColor(30, 27, 75);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? '8. RECOMENDACIONES GENERALES DE SEGURIDAD' : '8. GENERAL SECURITY RECOMMENDATIONS',
      margin,
      yPos
    );
    yPos += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(
      isEs
        ? 'Directrices estratégicas de endurecimiento (Hardening) arquitectónico post-incidente:'
        : 'Strategic architectural hardening and preventative security recommendations:',
      margin,
      yPos
    );
    yPos += 7;

    generalRecs.forEach((rec, idx) => {
      checkPage(15);
      doc.setFillColor(30, 27, 75);
      doc.circle(margin + 2.5, yPos + 1.5, 2.5, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'bold');
      doc.text(String(idx + 1), margin + 2.5, yPos + 2.3, { align: 'center' });

      doc.setTextColor(15, 23, 42);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text(rec.title, margin + 8, yPos + 2);
      yPos += 5;

      doc.setFontSize(7.2);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      const recDescLines = doc.splitTextToSize(rec.desc, contentWidth - 8);
      doc.text(recDescLines, margin + 8, yPos);
      yPos += recDescLines.length * 3.4 + 3.5;
    });

    // ── INSERT TABLE OF CONTENTS (PAGE 2) WITH INTERACTIVE PDF LINKS ──
    doc.insertPage(2);
    doc.setPage(2);
    addHeader();
    let tocY = 24;

    doc.setTextColor(30, 27, 75);
    doc.setFontSize(15);
    doc.setFont('helvetica', 'bold');
    doc.text(
      isEs ? 'ÍNDICE GENERAL Y NAVEGACIÓN FORENSE' : 'FORENSIC TABLE OF CONTENTS & NAVIGATION',
      margin,
      tocY
    );
    tocY += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(
      isEs
        ? 'Haga clic en cualquiera de las 8 secciones para saltar directamente a ella en el visor PDF:'
        : 'Click on any of the 8 sections to navigate directly to it within the PDF document viewer:',
      margin,
      tocY
    );
    tocY += 8;

    const tocEntries = [
      {
        num: '01',
        title: isEs ? '1. Resumen ejecutivo' : '1. Executive summary',
        desc: isEs ? 'Síntesis forense, ventana de auditoría y alcance global de telemetría SIEM.' : 'Forensic synthesis, audit window, and global SIEM telemetry scope.',
        targetPage: sectionPages.resumenEjecutivo + 1,
        color: [79, 70, 229] as [number, number, number],
      },
      {
        num: '02',
        title: isEs ? '2. Hallazgos identificados' : '2. Identified findings',
        desc: isEs ? 'Matriz sintética y consolidada de vectores de ataque detectados.' : 'Synthetic, consolidated matrix of detected attack vectors.',
        targetPage: sectionPages.hallazgosIdentificados + 1,
        color: [220, 38, 38] as [number, number, number],
      },
      {
        num: '03',
        title: isEs ? '3. Explicación técnica de cada hallazgo' : '3. Technical explanation of each finding',
        desc: isEs ? 'Mecánica de intrusión, tácticas MITRE ATT&CK y comportamiento adverso.' : 'Intrusion mechanics, MITRE ATT&CK mappings, and adversary techniques.',
        targetPage: sectionPages.explicacionTecnica + 1,
        color: [217, 119, 6] as [number, number, number],
      },
      {
        num: '04',
        title: isEs ? '4. Evidencias encontradas en los logs' : '4. Log evidence & forensic telemetry',
        desc: isEs ? 'Event IDs de Windows, comandos CLI de terminal, scripts Base64 e IoCs.' : 'Windows Event IDs, terminal CLI commands, Base64 scripts, and IoCs.',
        targetPage: sectionPages.evidenciasLogs + 1,
        color: [15, 23, 42] as [number, number, number],
      },
      {
        num: '05',
        title: isEs ? '5. Criticidad y justificación' : '5. Criticality & technical justification',
        desc: isEs ? 'Ponderación y justificación analítica del nivel de riesgo atribuido.' : 'Analytical justification and severity weighting for each threat vector.',
        targetPage: sectionPages.criticidadJustificacion + 1,
        color: [225, 29, 72] as [number, number, number],
      },
      {
        num: '06',
        title: isEs ? '6. Posible impacto en la organización' : '6. Potential organizational impact',
        desc: isEs ? 'Confidencialidad, continuidad operativa (ransomware), regulación y reputación.' : 'Confidentiality, operational continuity (ransomware), regulatory, and reputation.',
        targetPage: sectionPages.impactoOrganizacion + 1,
        color: [14, 165, 233] as [number, number, number],
      },
      {
        num: '07',
        title: isEs ? '7. Plan de acción: investigar, contener y remediar' : '7. Action plan: investigate, contain & remediate',
        desc: isEs ? 'Protocolo operativo forense DFIR estructurado en 3 fases de respuesta.' : 'Operational DFIR incident response protocol structured across 3 phases.',
        targetPage: sectionPages.planAccion + 1,
        color: [22, 163, 74] as [number, number, number],
        highlight: true,
      },
      {
        num: '08',
        title: isEs ? '8. Recomendaciones generales de seguridad' : '8. General security recommendations',
        desc: isEs ? 'Directrices estratégicas de endurecimiento (Hardening) arquitectónico post-incidente.' : 'Strategic architectural hardening and preventative security recommendations.',
        targetPage: sectionPages.recomendacionesGenerales + 1,
        color: [99, 102, 241] as [number, number, number],
      },
    ];

    const rowHeight = 15;
    for (const item of tocEntries) {
      doc.setFillColor(item.highlight ? 254 : 248, item.highlight ? 242 : 250, item.highlight ? 242 : 252);
      doc.setDrawColor(item.highlight ? 254 : 226, item.highlight ? 205 : 232, item.highlight ? 211 : 240);
      doc.roundedRect(margin, tocY - 2, contentWidth, rowHeight, 1.5, 1.5, 'FD');

      doc.setFillColor(...item.color);
      doc.rect(margin, tocY - 2, 3.5, rowHeight, 'F');

      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...item.color);
      doc.text(item.num, margin + 7, tocY + 3.5);

      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(item.title, margin + 16, tocY + 3.5);

      doc.setFontSize(6.8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.text(item.desc, margin + 16, tocY + 8.5);

      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(item.highlight ? 225 : 79, item.highlight ? 29 : 70, item.highlight ? 72 : 229);
      doc.text(`${isEs ? 'Pág.' : 'Page'} ${item.targetPage} ->`, pageWidth - margin - 5, tocY + 6, { align: 'right' });

      doc.link(margin, tocY - 2, contentWidth, rowHeight, { pageNumber: item.targetPage });

      tocY += rowHeight + 2.5;
    }
  }

  // Final footer apply
  addFooter();

  return doc;
}
