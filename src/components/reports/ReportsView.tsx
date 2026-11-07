'use client';

import { useState, useMemo, useEffect } from 'react';
import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { ReportConfig, SecurityFinding, SeverityLevel, Language } from '@/types';
import { generatePDF } from '@/lib/pdfGenerator';
import { cn, severityColor, severityDotColor } from '@/lib/utils';
import {
  buildCorrelatedTimeline,
  extractForensiciOCs,
  extractL3TechnicalEvidence,
  getDfirActionPlan,
  localizeFinding,
  consolidateThreatFindings,
  getGeneralSecurityRecommendations,
} from '@/lib/dfirForensicReport';
import {
  FileText,
  Download,
  Eye,
  Settings2,
  Shield,
  Building,
  User,
  CheckCircle2,
  FileCheck,
  Globe,
  Sliders,
  AlertTriangle,
  Briefcase,
  Terminal,
  Crosshair,
  Filter,
  CheckSquare,
  Square,
  Activity,
  Flame,
  BarChart3,
  CheckCircle,
  ShieldAlert,
  Clock,
  Cpu,
  ListOrdered,
  Bookmark,
  ChevronRight,
} from 'lucide-react';

export function ReportsView() {
  const { state, language: appLanguage, setLanguage } = useApp();
  const t = translations[appLanguage];

  // Report configuration state
  const [reportType, setReportType] = useState<'executive' | 'technical'>('executive');
  const [reportLang, setReportLang] = useState<Language>(appLanguage);
  
  // Default titles by language
  const defaultTitleEn = 'Executive Cybersecurity Threat Assessment & Incident Summary';
  const defaultTitleEs = 'Informe Ejecutivo de Evaluación de Amenazas e Incidentes de Seguridad';

  const [reportTitle, setReportTitle] = useState(
    appLanguage === 'es' ? defaultTitleEs : defaultTitleEn
  );
  const [author, setAuthor] = useState('Lead SOC Analyst (L2)');
  const [organization, setOrganization] = useState('Enterprise Cyber Defense Services');
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeRawLogs, setIncludeRawLogs] = useState(true);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>(
    state.findings.map((f) => f.id)
  );
  const [isExporting, setIsExporting] = useState(false);

  // Findings list filter inside report config
  const [findingsFilterSeverity, setFindingsFilterSeverity] = useState<string>('all');

  // Synchronize report language when application language changes
  useEffect(() => {
    setReportLang(appLanguage);
    setReportTitle((prev) => {
      if (prev === defaultTitleEn || prev === defaultTitleEs) {
        return appLanguage === 'es' ? defaultTitleEs : defaultTitleEn;
      }
      return prev;
    });
  }, [appLanguage]);

  const handleLanguageChange = (newLang: Language) => {
    setReportLang(newLang);
    setLanguage(newLang); // Keeps entire application and report strictly in sync!
  };

  // Handle report type change
  const handleTypeChange = (type: 'executive' | 'technical') => {
    setReportType(type);
    const execTitle = reportLang === 'es'
      ? 'Informe Ejecutivo de Evaluación de Amenazas e Incidentes de Seguridad'
      : 'Executive Cybersecurity Threat Assessment & Incident Summary';
    const techTitle = reportLang === 'es'
      ? 'Informe Técnico Forense y Respuesta a Incidentes (DFIR)'
      : 'Technical Forensic Analysis & Incident Response Report (DFIR)';

    setReportTitle((prev) => {
      if (type === 'technical' && (prev === execTitle || prev.includes('Ejecutivo') || prev.includes('Executive'))) {
        return techTitle;
      }
      if (type === 'executive' && (prev === techTitle || prev.includes('Técnico') || prev.includes('Technical'))) {
        return execTitle;
      }
      return prev;
    });
  };

  // Scroll to section helper for interactive index navigation
  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  // Group findings by severity
  const findingsBySeverity = useMemo(() => {
    const map: Record<SeverityLevel, SecurityFinding[]> = {
      Critical: [],
      High: [],
      Medium: [],
      Low: [],
    };
    for (const f of state.findings) {
      if (map[f.severity]) {
        map[f.severity].push(f);
      }
    }
    return map;
  }, [state.findings]);

  // Count selected findings per severity
  const selectedCounts = useMemo(() => {
    const counts: Record<SeverityLevel, { alerts: number; events: number }> = {
      Critical: { alerts: 0, events: 0 },
      High: { alerts: 0, events: 0 },
      Medium: { alerts: 0, events: 0 },
      Low: { alerts: 0, events: 0 },
    };
    for (const f of state.findings) {
      if (selectedFindingIds.includes(f.id)) {
        counts[f.severity].alerts += 1;
        counts[f.severity].events += (f.relatedLogIds?.length || 1);
      }
    }
    return counts;
  }, [state.findings, selectedFindingIds]);

  // Total associated events for selected alerts
  const totalSelectedEvents = useMemo(() => {
    return Object.values(selectedCounts).reduce((sum, item) => sum + item.events, 0);
  }, [selectedCounts]);

  // Filtered findings selected for the report
  const reportFindings = useMemo(() => {
    return state.findings.filter((f) => selectedFindingIds.includes(f.id));
  }, [state.findings, selectedFindingIds]);

  // Memoized DFIR Forensics Data for Technical Report & Preview
  const timelineEvents = useMemo(() => {
    return buildCorrelatedTimeline(reportFindings, state.logs, reportLang);
  }, [reportFindings, state.logs, reportLang]);

  const forensiciOCs = useMemo(() => {
    return extractForensiciOCs(reportFindings, state.threatIntel.reputations, state.logs, reportLang);
  }, [reportFindings, state.threatIntel.reputations, state.logs, reportLang]);

  const l3Evidence = useMemo(() => {
    return extractL3TechnicalEvidence(reportFindings, state.logs, reportLang);
  }, [reportFindings, state.logs, reportLang]);

  const dfirActionPlan = useMemo(() => {
    return getDfirActionPlan(reportFindings, reportLang);
  }, [reportFindings, reportLang]);

  const consolidatedThreats = useMemo(() => {
    return consolidateThreatFindings(reportFindings, state.logs, reportLang);
  }, [reportFindings, state.logs, reportLang]);

  const generalRecs = useMemo(() => {
    return getGeneralSecurityRecommendations(reportLang);
  }, [reportLang]);

  const toggleFindingSelection = (id: string) => {
    if (selectedFindingIds.includes(id)) {
      setSelectedFindingIds(selectedFindingIds.filter((item) => item !== id));
    } else {
      setSelectedFindingIds([...selectedFindingIds, id]);
    }
  };

  const selectAllFindings = () => {
    setSelectedFindingIds(state.findings.map((f) => f.id));
  };

  const deselectAllFindings = () => {
    setSelectedFindingIds([]);
  };

  // Toggle all findings of a specific severity
  const toggleSeveritySelection = (sev: SeverityLevel) => {
    const targetFindings = findingsBySeverity[sev];
    const targetIds = targetFindings.map((f) => f.id);
    const allSelected = targetIds.length > 0 && targetIds.every((id) => selectedFindingIds.includes(id));

    if (allSelected) {
      setSelectedFindingIds(selectedFindingIds.filter((id) => !targetIds.includes(id)));
    } else {
      const newSelection = Array.from(new Set([...selectedFindingIds, ...targetIds]));
      setSelectedFindingIds(newSelection);
    }
  };

  const selectCriticalAndHigh = () => {
    const critAndHighIds = [
      ...findingsBySeverity.Critical.map((f) => f.id),
      ...findingsBySeverity.High.map((f) => f.id),
    ];
    setSelectedFindingIds(critAndHighIds);
  };

  const selectOnlyCritical = () => {
    const critIds = findingsBySeverity.Critical.map((f) => f.id);
    setSelectedFindingIds(critIds);
  };

  const visibleFindingsInSelector = useMemo(() => {
    if (findingsFilterSeverity === 'all') return state.findings;
    return state.findings.filter((f) => f.severity.toLowerCase() === findingsFilterSeverity.toLowerCase());
  }, [state.findings, findingsFilterSeverity]);

  // PDF Export execution
  const handleExportPDF = async () => {
    if (!state.stats) return;
    setIsExporting(true);

    try {
      const config: ReportConfig = {
        type: reportType,
        language: reportLang,
        title: reportTitle,
        author,
        organization,
        includeCharts,
        includeRawLogs,
        selectedFindings: selectedFindingIds,
      };

      await new Promise((r) => setTimeout(r, 100));

      const doc = generatePDF({
        config,
        findings: reportFindings,
        stats: state.stats,
        reputations: state.threatIntel.reputations,
        logs: state.logs,
      });

      const sanitizedTitle = (reportTitle || 'SOC_Report').replace(/\s+/g, '_');
      const filename = `${sanitizedTitle}_${reportType}_${reportLang.toUpperCase()}.pdf`;
      doc.save(filename);
    } catch (err) {
      console.error('PDF Generation failed:', err);
      alert('Error generating PDF report. Please check the logs.');
    } finally {
      setIsExporting(false);
    }
  };

  const severities: SeverityLevel[] = ['Critical', 'High', 'Medium', 'Low'];

  // Status computation
  const hasCritical = reportFindings.some((f) => f.severity === 'Critical');
  const hasHigh = reportFindings.some((f) => f.severity === 'High');

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200/60 dark:border-indigo-800 px-2.5 py-0.5 rounded-full">
            {reportLang === 'en' ? 'Automated Deliverable Generation' : 'Generación Automatizada de Entregables'}
          </span>
          <span className="text-xs text-slate-400 dark:text-slate-500 font-mono">
            LANG: <strong className="text-indigo-600 dark:text-indigo-400">{reportLang.toUpperCase()}</strong>
          </span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          {t.report_title}
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-2xl leading-relaxed">
          {reportLang === 'en'
            ? 'Produce executive briefings in non-technical business language or comprehensive technical forensic documentation for incident response teams.'
            : 'Produzca resúmenes ejecutivos en lenguaje de negocio claro para la dirección o documentación técnica forense completa para equipos de respuesta a incidentes.'}
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Configuration Form (5 cols) */}
        <div className="lg:col-span-5 space-y-5">
          <div className="glass-card p-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
              <Settings2 className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                {reportLang === 'en' ? 'Report Parameters' : 'Parámetros del Reporte'}
              </h3>
            </div>

            {/* Report Type Selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block">
                {t.report_type}
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => handleTypeChange('executive')}
                  className={cn(
                    'p-3 rounded-xl border text-left transition-all',
                    reportType === 'executive'
                      ? 'border-indigo-600 bg-indigo-50/70 dark:bg-indigo-950/40 text-indigo-900 dark:text-indigo-200 font-bold shadow-sm'
                      : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-600 dark:text-slate-400 font-medium'
                  )}
                >
                  <Briefcase className="w-4 h-4 mb-1 text-indigo-600 dark:text-indigo-400" />
                  <div className="text-xs">{t.report_executive}</div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 font-normal">
                    {reportLang === 'en' ? 'Business summary & impact' : 'Resumen no técnico e impacto'}
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => handleTypeChange('technical')}
                  className={cn(
                    'p-3 rounded-xl border text-left transition-all',
                    reportType === 'technical'
                      ? 'border-indigo-600 bg-indigo-50/70 dark:bg-indigo-950/40 text-indigo-900 dark:text-indigo-200 font-bold shadow-sm'
                      : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-600 dark:text-slate-400 font-medium'
                  )}
                >
                  <Terminal className="w-4 h-4 mb-1 text-indigo-600 dark:text-indigo-400" />
                  <div className="text-xs">{t.report_technical}</div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 font-normal">
                    {reportLang === 'en' ? 'Full forensic log analysis' : 'Análisis forense detallado'}
                  </div>
                </button>
              </div>
            </div>

            {/* Language Selector (Synchronized with App) */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300 flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                  <span>{t.report_language}</span>
                </span>
                <span className="text-[10px] text-indigo-600 dark:text-indigo-400 font-normal">
                  {reportLang === 'en' ? 'Syncs with application' : 'Sincronizado con la app'}
                </span>
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => handleLanguageChange('en')}
                  className={cn(
                    'py-2 px-3 rounded-lg border text-xs font-semibold transition',
                    reportLang === 'en'
                      ? 'border-indigo-600 bg-indigo-600 text-white shadow-sm'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  )}
                >
                  🇬🇧 English
                </button>
                <button
                  type="button"
                  onClick={() => handleLanguageChange('es')}
                  className={cn(
                    'py-2 px-3 rounded-lg border text-xs font-semibold transition',
                    reportLang === 'es'
                      ? 'border-indigo-600 bg-indigo-600 text-white shadow-sm'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  )}
                >
                  🇪🇸 Español
                </button>
              </div>
            </div>

            {/* Report Metadata Inputs */}
            <div className="space-y-3 pt-2">
              <div>
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">
                  {t.report_doc_title}
                </label>
                <input
                  type="text"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  className="w-full text-xs px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">
                  {t.report_author}
                </label>
                <input
                  type="text"
                  value={author}
                  onChange={(e) => setAuthor(e.target.value)}
                  className="w-full text-xs px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-700 dark:text-slate-300 block mb-1">
                  {t.report_organization}
                </label>
                <input
                  type="text"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                  className="w-full text-xs px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 text-slate-900 dark:text-slate-100"
                />
              </div>
            </div>

            {/* Options Checkboxes */}
            <div className="pt-2 border-t border-slate-100 dark:border-slate-800 space-y-2 text-xs">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeCharts}
                  onChange={(e) => setIncludeCharts(e.target.checked)}
                  className="rounded text-indigo-600 focus:ring-indigo-500 dark:bg-slate-900 dark:border-slate-700"
                />
                <span className="text-slate-700 dark:text-slate-300">{t.report_include_charts}</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeRawLogs}
                  onChange={(e) => setIncludeRawLogs(e.target.checked)}
                  className="rounded text-indigo-600 focus:ring-indigo-500 dark:bg-slate-900 dark:border-slate-700"
                />
                <span className="text-slate-700 dark:text-slate-300">{t.report_include_raw}</span>
              </label>
            </div>

            {/* ── SELECT FINDINGS BY CRITICALITY SECTION ── */}
            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-3">
              <div className="flex items-center justify-between text-xs font-bold text-slate-900 dark:text-white">
                <span className="flex items-center gap-1.5">
                  <Filter className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                  <span>{t.report_select_findings}</span>
                </span>
                <span className="text-[11px] font-mono font-normal text-slate-500 dark:text-slate-400">
                  {selectedFindingIds.length} / {state.findings.length} {reportLang === 'en' ? 'alerts' : 'alertas'} ({totalSelectedEvents} {reportLang === 'en' ? 'events' : 'eventos'})
                </span>
              </div>

              {/* Quick Preset Buttons */}
              <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                <button
                  type="button"
                  onClick={selectAllFindings}
                  className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 font-medium transition"
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={selectOnlyCritical}
                  className="px-2 py-1 rounded bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 hover:bg-rose-100 dark:hover:bg-rose-900/50 font-medium transition border border-rose-200/60 dark:border-rose-900/50"
                >
                  Critical Only
                </button>
                <button
                  type="button"
                  onClick={selectCriticalAndHigh}
                  className="px-2 py-1 rounded bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 hover:bg-orange-100 dark:hover:bg-orange-900/50 font-medium transition border border-orange-200/60 dark:border-orange-900/50"
                >
                  Critical + High
                </button>
                <button
                  type="button"
                  onClick={deselectAllFindings}
                  className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700 font-medium transition ml-auto"
                >
                  None
                </button>
              </div>

              {/* Severity Category Quick-Select Pills */}
              <div className="space-y-1">
                <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 dark:text-slate-500 block">
                  {reportLang === 'en' ? 'Toggle by Criticality' : 'Alternar por Criticidad'}:
                </span>
                <div className="grid grid-cols-2 gap-1.5">
                  {severities.map((sev) => {
                    const totalInSev = findingsBySeverity[sev].length;
                    const selectedData = selectedCounts[sev];
                    const isFullySelected = totalInSev > 0 && selectedData.alerts === totalInSev;

                    return (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => toggleSeveritySelection(sev)}
                        disabled={totalInSev === 0}
                        className={cn(
                          'px-2.5 py-1.5 rounded-lg border text-xs flex items-center justify-between transition-all font-medium disabled:opacity-40 disabled:cursor-not-allowed',
                          sev === 'Critical'
                            ? isFullySelected
                              ? 'bg-rose-600 text-white border-rose-600 shadow-sm'
                              : 'bg-rose-50/70 dark:bg-rose-950/30 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-900/50 hover:bg-rose-100 dark:hover:bg-rose-900/40'
                            : sev === 'High'
                              ? isFullySelected
                                ? 'bg-orange-600 text-white border-orange-600 shadow-sm'
                                : 'bg-orange-50/70 dark:bg-orange-950/30 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-900/50 hover:bg-orange-100 dark:hover:bg-orange-900/40'
                              : sev === 'Medium'
                                ? isFullySelected
                                  ? 'bg-amber-600 text-white border-amber-600 shadow-sm'
                                  : 'bg-amber-50/70 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-900/50 hover:bg-amber-100 dark:hover:bg-amber-900/40'
                                : isFullySelected
                                  ? 'bg-emerald-600 text-white border-emerald-600 shadow-sm'
                                  : 'bg-emerald-50/70 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-900/50 hover:bg-emerald-100 dark:hover:bg-emerald-900/40'
                        )}
                      >
                        <span className="flex items-center gap-1.5">
                          <span
                            className={cn(
                              'w-2 h-2 rounded-full shrink-0',
                              isFullySelected ? 'bg-white' : severityDotColor(sev)
                            )}
                          />
                          <span>{sev}</span>
                        </span>
                        <span
                          className={cn(
                            'text-[10px] font-mono px-1.5 py-0.2 rounded font-bold',
                            isFullySelected
                              ? 'bg-white/20 text-white'
                              : 'bg-black/5 dark:bg-white/10'
                          )}
                        >
                          {selectedData.alerts}/{totalInSev} ({selectedData.events} ev)
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Filter view tabs for list */}
              <div className="flex items-center gap-1 pt-1 border-t border-slate-100 dark:border-slate-800 text-[11px]">
                <span className="text-slate-400 dark:text-slate-500 mr-1 text-[10px] uppercase font-bold">
                  View:
                </span>
                {['all', 'Critical', 'High', 'Medium', 'Low'].map((filterSev) => (
                  <button
                    key={filterSev}
                    type="button"
                    onClick={() => setFindingsFilterSeverity(filterSev)}
                    className={cn(
                      'px-1.5 py-0.5 rounded text-[10px] font-medium transition',
                      findingsFilterSeverity === filterSev
                        ? 'bg-indigo-600 text-white font-bold'
                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                    )}
                  >
                    {filterSev === 'all' ? 'All' : filterSev}
                  </button>
                ))}
              </div>

              {/* Individual Finding Checkbox List */}
              <div className="max-h-48 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900/80 rounded-xl border border-slate-200 dark:border-slate-800 text-xs">
                {visibleFindingsInSelector.length === 0 ? (
                  <p className="text-slate-400 dark:text-slate-500 text-center py-3 text-[11px]">
                    No findings in this category
                  </p>
                ) : (
                  visibleFindingsInSelector.map((f) => {
                    const checked = selectedFindingIds.includes(f.id);
                    return (
                      <label
                        key={f.id}
                        className={cn(
                          'flex items-center gap-2 p-1.5 rounded-lg cursor-pointer transition',
                          checked
                            ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 shadow-2xs'
                            : 'hover:bg-white/50 dark:hover:bg-slate-800/50 text-slate-500 dark:text-slate-400'
                        )}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleFindingSelection(f.id)}
                          className="rounded text-indigo-600 dark:bg-slate-900 dark:border-slate-700 focus:ring-indigo-500"
                        />
                        <span
                          className={cn(
                            'text-[9px] font-bold uppercase px-1.5 py-0.5 rounded shrink-0',
                            severityColor(f.severity)
                          )}
                        >
                          {f.severity}
                        </span>
                        <span className="truncate font-medium text-[11px] flex-1">
                          {localizeFinding(f, reportLang).title}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
                          {f.relatedLogIds?.length || 1} ev
                        </span>
                      </label>
                    );
                  })
                )}
              </div>
            </div>

            {/* Export PDF Button */}
            <button
              onClick={handleExportPDF}
              disabled={isExporting || reportFindings.length === 0}
              className="w-full flex items-center justify-center gap-2 py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-bold text-xs transition shadow-lg shadow-indigo-600/25 disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              <span>
                {isExporting
                  ? (reportLang === 'en' ? 'Generating PDF...' : 'Generando PDF...')
                  : `${reportLang === 'en' ? 'Download PDF Report' : 'Descargar Reporte PDF'} (${reportFindings.length} alerts • ${reportLang.toUpperCase()})`}
              </span>
            </button>
          </div>
        </div>

        {/* Right Column: Live In-Browser Preview (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Preview Navigation Tabs */}
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">{t.report_preview}</h3>
              <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200/60 dark:border-indigo-800">
                {reportLang.toUpperCase()}
              </span>
              <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 ml-2">
                {reportFindings.length} alerts • {totalSelectedEvents} events
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold px-2.5 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200/60 dark:border-indigo-800 flex items-center gap-1.5">
                {reportType === 'executive' ? (
                  <Briefcase className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                ) : (
                  <Terminal className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                )}
                <span>{reportType === 'executive' ? t.report_executive : t.report_technical}</span>
              </span>
            </div>
          </div>

          {/* Interactive Document Navigation Index / Quick Jump Bar */}
          <div className="bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 shadow-xs">
            <div className="flex items-center justify-between mb-2 px-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                <ListOrdered className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                {reportLang === 'en' ? 'Document Section Index (Quick Jump)' : 'Índice de Secciones (Navegación Rápida)'}
              </span>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                {reportLang === 'en' ? 'Click to jump' : 'Clic para ir directo'}
              </span>
            </div>

            {reportType === 'technical' ? (
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-index')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  {reportLang === 'en' ? 'Index' : 'Índice'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-1')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  1. {reportLang === 'en' ? 'Summary' : 'Resumen'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-2')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  2. {reportLang === 'en' ? 'Findings' : 'Hallazgos'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-3')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  3. {reportLang === 'en' ? 'Tech Explanation' : 'Explicación Técnica'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-4')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  4. {reportLang === 'en' ? 'Log Evidence' : 'Evidencias en Logs'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-5')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  5. {reportLang === 'en' ? 'Criticality' : 'Criticidad'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-6')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  6. {reportLang === 'en' ? 'Impact' : 'Impacto'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-7')}
                  className="px-2.5 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-600 hover:text-white text-[11px] font-bold transition flex items-center gap-1.5"
                >
                  <ShieldAlert className="w-3 h-3 text-rose-500" />
                  7. {reportLang === 'en' ? 'DFIR Plan' : 'Plan DFIR'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-tech-8')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  8. {reportLang === 'en' ? 'Recommendations' : 'Recomendaciones'}
                </button>
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-exec-status')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  1. {reportLang === 'en' ? 'Status' : 'Estado'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-exec-chart')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  2. {reportLang === 'en' ? 'Attack Volume' : 'Volumen de Amenazas'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-exec-impact')}
                  className="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-500 hover:text-indigo-600 dark:hover:text-indigo-400 text-[11px] font-medium transition"
                >
                  3. {reportLang === 'en' ? 'Business Impact' : 'Impacto en Negocio'}
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection('sec-exec-actions')}
                  className="px-2.5 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-600 hover:text-white text-[11px] font-bold transition"
                >
                  4. {reportLang === 'en' ? 'Immediate Actions' : 'Acciones Inmediatas'}
                </button>
              </div>
            )}
          </div>

          {/* Render Document Mockup */}
          <div className="glass-card p-8 bg-white dark:bg-slate-900/90 border border-slate-300 dark:border-slate-800 shadow-md rounded-2xl min-h-[600px] text-slate-900 dark:text-slate-100 space-y-6">
            {/* Header Document Banner */}
            <div className="border-b border-slate-800 dark:border-slate-700 pb-4">
              <div className="flex items-center justify-between text-[10px] font-mono tracking-widest text-slate-400 dark:text-slate-500 uppercase">
                <span>SOC L2 {reportType === 'executive' ? 'EXECUTIVE' : 'TECHNICAL'} REPORT</span>
                <span className="text-rose-600 dark:text-rose-400 font-bold">CONFIDENTIAL // TLP:AMBER</span>
              </div>
              <h2 className="text-2xl font-black text-slate-900 dark:text-white mt-2 tracking-tight">
                {reportTitle}
              </h2>
              <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 dark:text-slate-400 mt-2 font-mono">
                <span>ORG: <strong className="text-slate-800 dark:text-slate-200">{organization}</strong></span>
                <span>•</span>
                <span>ANALYST: <strong className="text-slate-800 dark:text-slate-200">{author}</strong></span>
                <span>•</span>
                <span>DATE: <strong className="text-slate-800 dark:text-slate-200">{new Date().toLocaleDateString(reportLang === 'es' ? 'es-ES' : 'en-US')}</strong></span>
              </div>
            </div>

            {/* Mode 1: Executive Summary Preview (Consolidated non-technical view) */}
            {reportType === 'executive' ? (
              <div className="space-y-6">
                {/* 1. Incident Status Banner */}
                <div
                  id="sec-exec-status"
                  className={cn(
                    'p-3.5 rounded-xl text-center text-xs font-bold text-white shadow-sm',
                    hasCritical
                      ? 'bg-rose-600'
                      : hasHigh
                        ? 'bg-orange-600'
                        : 'bg-amber-600'
                  )}
                >
                  {hasCritical
                    ? (reportLang === 'en' ? 'CRITICAL RISK — IMMEDIATE INTERVENTION REQUIRED' : 'ESTADO: RIESGO CRÍTICO — INTERVENCIÓN INMEDIATA REQUERIDA')
                    : hasHigh
                      ? (reportLang === 'en' ? 'HIGH RISK — ACTION REQUIRED WITHIN 24 HOURS' : 'ESTADO: RIESGO ALTO — ACCIÓN REQUERIDA EN 24 HORAS')
                      : (reportLang === 'en' ? 'MODERATE RISK — ATTENTION REQUIRED WITHIN 72 HOURS' : 'ESTADO: RIESGO MODERADO — ATENCIÓN EN 72 HORAS')}
                </div>

                {/* 2. Executive Key Metrics Grid */}
                <div id="sec-exec-metrics" className="grid grid-cols-4 gap-2 text-center">
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded-xl">
                    <p className="text-lg font-black text-slate-900 dark:text-white">
                      {state.stats?.totalLogs.toLocaleString()}
                    </p>
                    <p className="text-[10px] uppercase font-bold text-slate-500">
                      {reportLang === 'en' ? 'Total Events' : 'Eventos Totales'}
                    </p>
                  </div>
                  <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/60 rounded-xl">
                    <p className="text-lg font-black text-rose-600 dark:text-rose-400">
                      {reportFindings.length}
                    </p>
                    <p className="text-[10px] uppercase font-bold text-rose-700 dark:text-rose-300">
                      {reportLang === 'en' ? 'Selected Alerts' : 'Alertas Seleccionadas'}
                    </p>
                  </div>
                  <div className="p-3 bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-900/60 rounded-xl">
                    <p className="text-lg font-black text-indigo-600 dark:text-indigo-400">
                      {totalSelectedEvents}
                    </p>
                    <p className="text-[10px] uppercase font-bold text-indigo-700 dark:text-indigo-300">
                      {reportLang === 'en' ? 'Attack Events' : 'Eventos de Ataque'}
                    </p>
                  </div>
                  <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900/60 rounded-xl">
                    <p className="text-lg font-black text-emerald-600 dark:text-emerald-400">
                      {state.stats?.uniqueUsers}
                    </p>
                    <p className="text-[10px] uppercase font-bold text-emerald-700 dark:text-emerald-300">
                      {reportLang === 'en' ? 'Target Accounts' : 'Cuentas Afectadas'}
                    </p>
                  </div>
                </div>

                {/* 3. Visual Charts Representation in Preview */}
                <div id="sec-exec-chart" className="space-y-3 p-4 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200 dark:border-slate-800">
                  <div className="flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                      {reportLang === 'en' ? 'Associated Event Volume by Severity (Attack Gravity)' : 'Volumen de Eventos Asociados por Severidad (Gravedad del Ataque)'}
                    </h4>
                  </div>
                  <div className="space-y-2 pt-1">
                    {severities.map((sev) => {
                      const data = selectedCounts[sev];
                      if (data.alerts === 0) return null;
                      const maxEvents = Math.max(1, totalSelectedEvents);
                      const pct = Math.round((data.events / maxEvents) * 100);

                      return (
                        <div key={sev} className="space-y-1">
                          <div className="flex justify-between text-xs font-semibold">
                            <span className="flex items-center gap-1.5">
                              <span className={cn('w-2 h-2 rounded-full', severityDotColor(sev))} />
                              <span className="dark:text-slate-200">{sev} ({data.alerts} {reportLang === 'en' ? 'alerts' : 'alertas'})</span>
                            </span>
                            <span className="font-mono text-slate-500 dark:text-slate-400">
                              {data.events} {reportLang === 'en' ? 'events' : 'eventos'} ({pct}%)
                            </span>
                          </div>
                          <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2 overflow-hidden">
                            <div
                              className={cn(
                                'h-2 rounded-full transition-all',
                                sev === 'Critical'
                                  ? 'bg-rose-500'
                                  : sev === 'High'
                                    ? 'bg-orange-500'
                                    : sev === 'Medium'
                                      ? 'bg-amber-500'
                                      : 'bg-emerald-500'
                              )}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* 4. Potential Business Impact Assessment */}
                <div id="sec-exec-impact" className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                    {reportLang === 'en'
                      ? '1. Potential Business Impact Assessment'
                      : '1. Evaluación del Impacto Potencial en el Negocio'}
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/80 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                        {reportLang === 'en' ? 'Confidentiality & Data Theft' : 'Fuga de Información Confidencial'}
                      </span>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">
                        {reportLang === 'en'
                          ? 'Potential unauthorized extraction of client records, trade secrets, and databases.'
                          : 'Extracción o acceso no autorizado a bases de datos de clientes, acuerdos comerciales y secretos industriales.'}
                      </p>
                    </div>

                    <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/80 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                        {reportLang === 'en' ? 'Operational Continuity' : 'Continuidad Operativa'}
                      </span>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">
                        {reportLang === 'en'
                          ? 'Threat of system disruption, ransomware deployment, or interruption of revenue operations.'
                          : 'Peligro de degradación de servicios, despliegue de ransomware o paradas en la operación productiva.'}
                      </p>
                    </div>

                    <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/80 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                        {reportLang === 'en' ? 'Regulatory Compliance' : 'Responsabilidad Regulatoria'}
                      </span>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">
                        {reportLang === 'en'
                          ? 'Exposure under data privacy laws (GDPR/privacy acts) with risk of fines and audits.'
                          : 'Exposición a sanciones y multas económicas por incumplimiento de normativas de protección de datos.'}
                      </p>
                    </div>

                    <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/80 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
                        {reportLang === 'en' ? 'Brand & Stakeholder Trust' : 'Daño Reputacional'}
                      </span>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">
                        {reportLang === 'en'
                          ? 'Erosion of client trust and market valuation should the incident become public.'
                          : 'Pérdida de credibilidad frente a clientes y accionistas si el incidente se agrava públicamente.'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* 5. Prioritized Immediate Action Plan */}
                <div id="sec-exec-actions" className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                    {reportLang === 'en'
                      ? '2. Prioritized Immediate Action Plan'
                      : '2. Plan de Acciones Inmediatas Recomendadas'}
                  </h4>
                  <div className="space-y-1.5 text-xs">
                    {[
                      {
                        title: reportLang === 'en' ? '1. Immediate Credential Reset' : '1. Revocación Inmediata de Credenciales',
                        desc: reportLang === 'en' ? 'Force password changes and terminate all active sessions for targeted accounts.' : 'Forzar cambio de contraseñas y cerrar sesiones activas para las cuentas comprometidas.',
                      },
                      {
                        title: reportLang === 'en' ? '2. Endpoint Isolation' : '2. Aislamiento de Equipos Comprometidos',
                        desc: reportLang === 'en' ? 'Quarantine affected servers and workstations from the internal LAN to halt lateral movement.' : 'Desconectar de la red corporativa los puestos de trabajo señalados para contener la intrusión.',
                      },
                      {
                        title: reportLang === 'en' ? '3. Perimeter IP Blocking' : '3. Bloqueo Perimetral de Direcciones IP',
                        desc: reportLang === 'en' ? 'Blacklist identified malicious external source IP addresses on perimeter firewalls.' : 'Añadir las IPs externas detectadas a las listas de denegación en firewalls perimetrales.',
                      },
                    ].map((act, i) => (
                      <div key={i} className="p-2.5 rounded-lg bg-indigo-50/50 dark:bg-indigo-950/30 border border-indigo-100 dark:border-indigo-900/50">
                        <span className="font-bold text-slate-900 dark:text-white">{act.title}: </span>
                        <span className="text-slate-600 dark:text-slate-300 text-[11px]">{act.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              /* Mode 2: Technical Forensic Report Preview (DFIR SOC Level 2 -> Level 3 Escalation) */
              <div className="space-y-6">
                {/* Document Table of Contents / Forensic Section Index */}
                <div id="sec-tech-index" className="p-4 rounded-xl border border-indigo-100 dark:border-indigo-900/60 bg-indigo-50/40 dark:bg-indigo-950/20 space-y-3">
                  <div className="flex items-center justify-between border-b border-indigo-200/60 dark:border-indigo-900/40 pb-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-indigo-700 dark:text-indigo-400 flex items-center gap-1.5">
                      <ListOrdered className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                      {reportLang === 'en' ? 'Forensic Table of Contents (8 Syllabus Sections)' : 'Índice General y Navegación Forense (8 Secciones)'}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                      TLP:AMBER • L2 Escalation
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    {[
                      { id: 'sec-tech-1', num: '01', title: reportLang === 'en' ? '1. Executive Summary' : '1. Resumen Ejecutivo', desc: reportLang === 'en' ? 'Incident narrative, audit period, and global SIEM scope' : 'Síntesis forense, ventana de auditoría y alcance global SIEM' },
                      { id: 'sec-tech-2', num: '02', title: reportLang === 'en' ? '2. Identified Findings' : '2. Hallazgos Identificados', desc: reportLang === 'en' ? 'Consolidated threat vectors and targeted asset matrix' : 'Matriz consolidada de vectores de ataque y activos comprometidos' },
                      { id: 'sec-tech-3', num: '03', title: reportLang === 'en' ? '3. Technical Explanation' : '3. Explicación Técnica de Hallazgos', desc: reportLang === 'en' ? 'MITRE ATT&CK techniques, intrusion mechanics, and behavior' : 'Mecánica de intrusión, tácticas MITRE ATT&CK y comportamiento' },
                      { id: 'sec-tech-4', num: '04', title: reportLang === 'en' ? '4. Log Evidence & Telemetry' : '4. Evidencias en Logs y Telemetría', desc: reportLang === 'en' ? 'Windows Event IDs, raw CLI commands, and IoCs with CTI' : 'Event IDs clave, comandos CLI de terminal e IoCs con CTI' },
                      { id: 'sec-tech-5', num: '05', title: reportLang === 'en' ? '5. Criticality & Justification' : '5. Criticidad y Justificación', desc: reportLang === 'en' ? 'Analytical severity weighting and threat risk evaluation' : 'Ponderación y justificación analítica del nivel de riesgo' },
                      { id: 'sec-tech-6', num: '06', title: reportLang === 'en' ? '6. Organizational Impact' : '6. Posible Impacto en la Organización', desc: reportLang === 'en' ? 'Data confidentiality, ransomware, legal compliance, trust' : 'Confidencialidad, continuidad (ransomware), regulación y reputación' },
                      { id: 'sec-tech-7', num: '07', title: reportLang === 'en' ? '7. Phased Action Plan (DFIR)' : '7. Plan de Acción (DFIR)', desc: reportLang === 'en' ? 'Investigate, contain, and remediate (3 operational phases)' : 'Investigar, contener y remediar en 3 fases operativas', highlight: true },
                      { id: 'sec-tech-8', num: '08', title: reportLang === 'en' ? '8. General Security Recommendations' : '8. Recomendaciones Generales', desc: reportLang === 'en' ? 'Strategic architectural post-incident hardening guidelines' : 'Directrices estratégicas de endurecimiento (Hardening) post-incidente' },
                    ].map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => scrollToSection(item.id)}
                        className={cn(
                          'p-2.5 rounded-lg border text-left transition flex items-start gap-2.5 group cursor-pointer',
                          item.highlight
                            ? 'bg-rose-50/60 dark:bg-rose-950/30 border-rose-200 dark:border-rose-900/50 hover:border-rose-500'
                            : 'bg-white dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 hover:border-indigo-500'
                        )}
                      >
                        <span className={cn('text-[10px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0', item.highlight ? 'bg-rose-100 dark:bg-rose-900/60 text-rose-700 dark:text-rose-300' : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300')}>
                          {item.num}
                        </span>
                        <div className="flex-1 min-w-0">
                          <span className={cn('font-bold block text-[11px] group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition truncate', item.highlight ? 'text-rose-700 dark:text-rose-300' : 'text-slate-800 dark:text-slate-200')}>
                            {item.title}
                          </span>
                          <span className="text-[10px] text-slate-500 dark:text-slate-400 truncate block">
                            {item.desc}
                          </span>
                        </div>
                        <ChevronRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-indigo-600 group-hover:translate-x-0.5 transition shrink-0 mt-0.5" />
                      </button>
                    ))}
                  </div>
                </div>

                {/* 1. Resumen Ejecutivo Forense */}
                <div id="sec-tech-1" className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5" />
                    {reportLang === 'en' ? '1. Executive Forensic Summary' : '1. Resumen Ejecutivo Forense'}
                  </h4>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-800/40 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800">
                    {reportLang === 'en'
                      ? 'During the forensic audit window, the SOC Level 2 team identified and correlated a multi-phase intrusion sequence against corporate infrastructure. The adversary conducted brute force attacks against authentication endpoints, compromising corporate credentials and generating suspicious logins. Native command shells (PowerShell) were subsequently invoked using Base64 encoded arguments to evade perimeter detection, followed by privilege escalation and lateral propagation toward internal servers. The global incident posture is classified as CRITICAL, requiring immediate containment and eradication.'
                      : 'Durante la ventana de auditoría forense, el equipo SOC Nivel 2 identificó y correlacionó una secuencia de intrusión multifásica contra la infraestructura corporativa. El adversario inició con ataques automatizados de fuerza bruta hacia servicios de autenticación, logrando el compromiso de credenciales corporativas e inicios de sesión anómalos. Posteriormente, ejecutó intérpretes de comandos nativos (PowerShell) con argumentos codificados en Base64 para evadir mecanismos de detección perimetral, escaló privilegios y desplegó utilidades de movimiento lateral hacia servidores internos. La postura global del incidente se clasifica como CRÍTICA, requiriendo contención y erradicación inmediata.'}
                  </p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 text-xs font-mono bg-slate-900 text-slate-200 p-3.5 rounded-xl border border-slate-800">
                    <div>
                      <span className="text-[10px] text-slate-400 block uppercase">{reportLang === 'en' ? 'Total SIEM Events' : 'Total Eventos SIEM'}</span>
                      <span className="text-base font-bold text-emerald-400">{state.stats?.totalLogs.toLocaleString()}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 block uppercase">{reportLang === 'en' ? 'Threat Vectors' : 'Vectores Consolidados'}</span>
                      <span className="text-base font-bold text-rose-400">{consolidatedThreats.length} ({reportFindings.length} alertas)</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 block uppercase">{reportLang === 'en' ? 'Unique Source IPs' : 'IPs Origen Distintas'}</span>
                      <span className="text-base font-bold text-cyan-400">{state.stats?.uniqueSourceIPs}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 block uppercase">{reportLang === 'en' ? 'Impacted Accounts' : 'Cuentas Impactadas'}</span>
                      <span className="text-base font-bold text-amber-300">{state.stats?.uniqueUsers}</span>
                    </div>
                  </div>
                </div>

                {/* 2. Hallazgos Identificados (Matriz Consolidada) */}
                <div id="sec-tech-2" className="space-y-2.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <FileCheck className="w-3.5 h-3.5" />
                    {reportLang === 'en' ? '2. Identified Security Findings (Consolidated Matrix)' : '2. Hallazgos Identificados (Matriz Consolidada de Amenazas)'}
                  </h4>
                  <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead className="bg-slate-100 dark:bg-slate-900/90 text-slate-700 dark:text-slate-300 font-bold border-b border-slate-200 dark:border-slate-800">
                        <tr>
                          <th className="p-2.5 w-10 text-center">#</th>
                          <th className="p-2.5">{reportLang === 'en' ? 'Attack Category / Threat Vector' : 'Categoría de Ataque / Vector'}</th>
                          <th className="p-2.5 text-center">{reportLang === 'en' ? 'Severity' : 'Criticidad'}</th>
                          <th className="p-2.5 text-center">{reportLang === 'en' ? 'Events' : 'Eventos'}</th>
                          <th className="p-2.5">{reportLang === 'en' ? 'Targeted Key Assets' : 'Activos Clave Afectados'}</th>
                          <th className="p-2.5 text-center">{reportLang === 'en' ? 'Confidence' : 'Confianza'}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-[11px]">
                        {consolidatedThreats.map((threat, idx) => (
                          <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                            <td className="p-2.5 text-center font-bold text-slate-500">{idx + 1}</td>
                            <td className="p-2.5 font-bold text-slate-900 dark:text-white">{threat.categoryLabel}</td>
                            <td className="p-2.5 text-center">
                              <span className={cn('text-[9px] font-bold uppercase px-2 py-0.5 rounded', severityColor(threat.severity))}>
                                {threat.severity}
                              </span>
                            </td>
                            <td className="p-2.5 text-center font-mono font-bold text-indigo-600 dark:text-indigo-400">
                              {threat.totalEvents.toLocaleString()}
                            </td>
                            <td className="p-2.5 font-mono text-slate-600 dark:text-slate-300">
                              {threat.assets.join(', ')}
                            </td>
                            <td className="p-2.5 text-center font-mono font-semibold text-slate-600 dark:text-slate-400">
                              {threat.confidence}%
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* 3. Explicación Técnica de Cada Hallazgo */}
                <div id="sec-tech-3" className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5" />
                    {reportLang === 'en' ? '3. Technical Explanation of Each Finding' : '3. Explicación Técnica de Cada Hallazgo'}
                  </h4>
                  <div className="space-y-3">
                    {consolidatedThreats.map((threat, idx) => (
                      <div
                        key={idx}
                        className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 space-y-2.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
                          <span className="font-bold text-xs text-slate-900 dark:text-white flex items-center gap-2">
                            <span className={cn('w-2 h-2 rounded-full', severityDotColor(threat.severity))} />
                            #{idx + 1} — {threat.categoryLabel}
                          </span>
                          <div className="flex items-center gap-2">
                            <span className={cn('text-[9px] font-bold uppercase px-2 py-0.5 rounded', severityColor(threat.severity))}>
                              {threat.severity}
                            </span>
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded font-semibold text-slate-700 dark:text-slate-300">
                              MITRE: {threat.mitreTactic} ({threat.mitreId})
                            </span>
                          </div>
                        </div>
                        <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                          {threat.technicalExplanation}
                        </p>
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                          <strong>{reportLang === 'en' ? 'Impacted Assets:' : 'Activos Involucrados:'}</strong> {threat.assets.join(', ')}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 4. Evidencias Encontradas en los Logs */}
                <div id="sec-tech-4" className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    {reportLang === 'en' ? '4. Log Evidence & Forensic Telemetry' : '4. Evidencias Encontradas en los Logs'}
                  </h4>

                  {/* 4.1 Windows Event IDs */}
                  <div className="space-y-1.5">
                    <span className="text-[11px] font-bold text-slate-800 dark:text-slate-200 block">
                      {reportLang === 'en' ? '4.1 Key Audited Windows Event IDs' : '4.1 Event IDs Clave Auditados en los Registros del Sistema'}
                    </span>
                    <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead className="bg-slate-100 dark:bg-slate-900/90 text-slate-700 dark:text-slate-300 font-bold border-b border-slate-200 dark:border-slate-800">
                          <tr>
                            <th className="p-2.5 w-32">{reportLang === 'en' ? 'Event ID' : 'Evento'}</th>
                            <th className="p-2.5">{reportLang === 'en' ? 'Forensic Definition' : 'Definición Forense'}</th>
                            <th className="p-2.5">{reportLang === 'en' ? 'Incident Relevance' : 'Relevancia en el Incidente'}</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-[11px]">
                          <tr>
                            <td className="p-2.5 font-mono font-bold text-indigo-600 dark:text-indigo-400">Event ID 4625</td>
                            <td className="p-2.5 font-medium text-slate-800 dark:text-slate-200">Intento fallido de inicio de sesión (Logon Failure)</td>
                            <td className="p-2.5 text-slate-600 dark:text-slate-300">Ráfagas automatizadas de fuerza bruta contra RDP y SMB</td>
                          </tr>
                          <tr>
                            <td className="p-2.5 font-mono font-bold text-indigo-600 dark:text-indigo-400">Event ID 4624</td>
                            <td className="p-2.5 font-medium text-slate-800 dark:text-slate-200">Inicio de sesión exitoso (Logon Type 10 / Remote Interactive)</td>
                            <td className="p-2.5 text-slate-600 dark:text-slate-300">Compromiso efectivo y uso de credenciales corporativas</td>
                          </tr>
                          <tr>
                            <td className="p-2.5 font-mono font-bold text-indigo-600 dark:text-indigo-400">Event ID 4672</td>
                            <td className="p-2.5 font-medium text-slate-800 dark:text-slate-200">Asignación de privilegios especiales a nueva sesión</td>
                            <td className="p-2.5 text-slate-600 dark:text-slate-300">Uso indebido de privilegios administrativos / cuenta CORP\admin</td>
                          </tr>
                          <tr>
                            <td className="p-2.5 font-mono font-bold text-indigo-600 dark:text-indigo-400">Event ID 4688</td>
                            <td className="p-2.5 font-medium text-slate-800 dark:text-slate-200">Creación de nuevo proceso con línea de comandos</td>
                            <td className="p-2.5 text-slate-600 dark:text-slate-300">Invocación de powershell.exe y cmd.exe con parámetros ofuscados</td>
                          </tr>
                          <tr>
                            <td className="p-2.5 font-mono font-bold text-indigo-600 dark:text-indigo-400">Event ID 7045 / 7036</td>
                            <td className="p-2.5 font-medium text-slate-800 dark:text-slate-200">Servicio nuevo instalado / Operación de servicio</td>
                            <td className="p-2.5 text-slate-600 dark:text-slate-300">Ejecución remota vía servicio PSEXESVC y propagación lateral</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* 4.2 Raw Command Telemetry */}
                  {l3Evidence.length > 0 && (
                    <div className="space-y-1.5 pt-2">
                      <span className="text-[11px] font-bold text-slate-800 dark:text-slate-200 block">
                        {reportLang === 'en' ? '4.2 Raw CLI Terminal Telemetry (Level 3 Escalation)' : '4.2 Telemetría Cruda de Comandos CLI (Escalamiento Nivel 3)'}
                      </span>
                      <div className="space-y-2">
                        {l3Evidence.slice(0, 2).map((ev, idx) => (
                          <div
                            key={idx}
                            className="rounded-xl border border-slate-800 bg-slate-950 p-3.5 font-mono text-xs space-y-2 text-slate-200 shadow-inner"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-1.5 text-[11px]">
                              <span className="text-emerald-400 font-bold">[{ev.timestamp}]</span>
                              <span className="text-slate-400">HOST: <strong className="text-cyan-400">{ev.host}</strong></span>
                              <span className="text-slate-400">USER: <strong className="text-amber-300">{ev.user}</strong></span>
                              <span className="text-slate-400">TACTIC: <strong className="text-rose-400">{ev.mitreTactic} ({ev.mitreId})</strong></span>
                            </div>
                            {ev.rawCommand && (
                              <div className="bg-slate-900 p-2 rounded border border-slate-800 text-rose-300 break-all select-all text-[11px]">
                                {ev.rawCommand}
                              </div>
                            )}
                            {ev.decodedCommand && (
                              <div className="bg-emerald-950/40 p-2 rounded border border-emerald-800/60 text-emerald-300 break-all select-all text-[11px]">
                                <strong>DECODED: </strong>{ev.decodedCommand}
                              </div>
                            )}
                            <div className="text-[10px] text-slate-400 space-y-0.5">
                              {ev.processTree.slice(0, 2).map((p, pIdx) => (
                                <div key={pIdx}>{p}</div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* 4.3 Structured IoCs Table */}
                  {forensiciOCs.length > 0 && (
                    <div className="space-y-1.5 pt-2">
                      <span className="text-[11px] font-bold text-slate-800 dark:text-slate-200 block">
                        {reportLang === 'en' ? '4.3 Structured Indicators of Compromise (IoCs) & CTI Context' : '4.3 Matriz de Indicadores de Compromiso (IoCs) e Inteligencia CTI'}
                      </span>
                      <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead className="bg-slate-100 dark:bg-slate-900/90 text-slate-700 dark:text-slate-300 font-bold border-b border-slate-200 dark:border-slate-800">
                            <tr>
                              <th className="p-2.5">{reportLang === 'en' ? 'IoC Type' : 'Tipo IoC'}</th>
                              <th className="p-2.5">{reportLang === 'en' ? 'Value' : 'Valor'}</th>
                              <th className="p-2.5">{reportLang === 'en' ? 'CTI Context' : 'Inteligencia de Amenazas (CTI)'}</th>
                              <th className="p-2.5">{reportLang === 'en' ? 'Role' : 'Rol en el Ataque'}</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono text-[11px]">
                            {forensiciOCs.slice(0, 6).map((ioc, idx) => (
                              <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                                <td className="p-2.5 font-bold text-slate-800 dark:text-slate-200">{ioc.type}</td>
                                <td className="p-2.5 font-bold text-rose-600 dark:text-rose-400 break-all">{ioc.value}</td>
                                <td className="p-2.5 text-slate-600 dark:text-slate-300 font-sans">{ioc.ctiContext}</td>
                                <td className="p-2.5 text-slate-500 dark:text-slate-400 font-sans">{ioc.role}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>

                {/* 5. Criticidad y Justificación */}
                <div id="sec-tech-5" className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <Flame className="w-3.5 h-3.5" />
                    {reportLang === 'en' ? '5. Criticality & Analytical Justification' : '5. Criticidad y Justificación Analítica'}
                  </h4>
                  <div className="space-y-2.5">
                    {consolidatedThreats.map((threat, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-900 dark:text-white">
                            [{threat.severity.toUpperCase()}] {threat.categoryLabel}
                          </span>
                          <span className={cn('text-[9px] font-bold uppercase px-2 py-0.5 rounded', severityColor(threat.severity))}>
                            {threat.severity}
                          </span>
                        </div>
                        <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                          {threat.criticalityJustification}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 6. Posible Impacto en la Organización */}
                <div id="sec-tech-6" className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    {reportLang === 'en' ? '6. Potential Organizational Impact' : '6. Posible Impacto en la Organización'}
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/60 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white block">A. Confidencialidad y Fuga de Información Crítica</span>
                      <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">
                        El compromiso de credenciales corporativas y cuentas administrativas expone bases de datos operativas, secretos comerciales y propiedad intelectual a accesos no autorizados y potencial exfiltración.
                      </p>
                    </div>
                    <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/60 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white block">B. Continuidad Operativa y Riesgo de Ransomware</span>
                      <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">
                        La ejecución de comandos ofuscados de PowerShell y el movimiento lateral hacia servidores de archivos (FS-SRV01) constituyen etapas previas a un despliegue de ransomware destructivo, arriesgando la parálisis operativa.
                      </p>
                    </div>
                    <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/60 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white block">C. Responsabilidad Regulatoria y Consecuencias Legales</span>
                      <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">
                        La intrusión no contenida compromete registros de empleados y clientes, activando mandatos de notificación de brechas de seguridad conforme a normativas de protección de datos (RGPD / legislación nacional).
                      </p>
                    </div>
                    <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/60 space-y-1">
                      <span className="font-bold text-slate-900 dark:text-white block">D. Daño Reputacional y Confianza Comercial</span>
                      <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">
                        La divulgación pública de un incidente de intrusión y exfiltración socava la credibilidad de la organización frente a clientes estratégicos, socios comerciales y entidades auditoras.
                      </p>
                    </div>
                  </div>
                </div>

                {/* 7. Plan de Acción: Investigar, Contener y Remediar (DFIR) */}
                <div id="sec-tech-7" className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
                    {reportLang === 'en' ? '7. Phased Action Plan: Investigate, Contain & Remediate' : '7. Plan de Acción: Investigar, Contener y Remediar (DFIR)'}
                  </h4>

                  <div className="space-y-3 text-xs">
                    {/* Fase 1: Investigar */}
                    <div className="p-3.5 rounded-xl border border-indigo-200 dark:border-indigo-900/50 bg-indigo-50/50 dark:bg-indigo-950/20 space-y-2">
                      <span className="font-bold text-indigo-700 dark:text-indigo-400 text-xs uppercase tracking-wider block">
                        {reportLang === 'en' ? 'Phase 1: Investigate (Forensic Triage & Scope Analysis)' : 'Fase 1: Investigar (Triage Forense y Análisis de Alcance)'}
                      </span>
                      <div className="space-y-1.5">
                        {dfirActionPlan.phase2.map((act, idx) => (
                          <div key={idx} className="p-2 rounded bg-white dark:bg-slate-900 border border-indigo-100 dark:border-indigo-900/30">
                            <span className="font-bold text-slate-900 dark:text-white block text-[11px]">{act.title}</span>
                            <span className="text-slate-600 dark:text-slate-300 text-[11px]">{act.desc}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Fase 2: Contener */}
                    <div className="p-3.5 rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/50 dark:bg-rose-950/20 space-y-2">
                      <span className="font-bold text-rose-700 dark:text-rose-400 text-xs uppercase tracking-wider block">
                        {reportLang === 'en' ? 'Phase 2: Contain (Isolation & Perimeter Blocking)' : 'Fase 2: Contener (Aislamiento y Mitigación Inmediata)'}
                      </span>
                      <div className="space-y-1.5">
                        {dfirActionPlan.phase1.map((act, idx) => (
                          <div key={idx} className="p-2 rounded bg-white dark:bg-slate-900 border border-rose-100 dark:border-rose-900/30">
                            <span className="font-bold text-slate-900 dark:text-white block text-[11px]">{act.title}</span>
                            <span className="text-slate-600 dark:text-slate-300 text-[11px]">{act.desc}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Fase 3: Remediar */}
                    <div className="p-3.5 rounded-xl border border-emerald-200 dark:border-emerald-900/50 bg-emerald-50/50 dark:bg-emerald-950/20 space-y-2">
                      <span className="font-bold text-emerald-700 dark:text-emerald-400 text-xs uppercase tracking-wider block">
                        {reportLang === 'en' ? 'Phase 3: Remediate (Eradication & Hardening)' : 'Fase 3: Remediar (Erradicación y Recuperación Segura)'}
                      </span>
                      <div className="space-y-1.5">
                        {dfirActionPlan.phase3.map((act, idx) => (
                          <div key={idx} className="p-2 rounded bg-white dark:bg-slate-900 border border-emerald-100 dark:border-emerald-900/30">
                            <span className="font-bold text-slate-900 dark:text-white block text-[11px]">{act.title}</span>
                            <span className="text-slate-600 dark:text-slate-300 text-[11px]">{act.desc}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* 8. Recomendaciones Generales de Seguridad */}
                <div id="sec-tech-8" className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5" />
                    {reportLang === 'en' ? '8. General Security Hardening Recommendations' : '8. Recomendaciones Generales de Seguridad'}
                  </h4>
                  <div className="space-y-2">
                    {generalRecs.map((rec, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 space-y-1"
                      >
                        <span className="font-bold text-slate-900 dark:text-white text-xs block">{rec.title}</span>
                        <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">{rec.desc}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
