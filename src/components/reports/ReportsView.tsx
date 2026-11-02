'use client';

import { useState, useMemo } from 'react';
import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { ReportConfig, SecurityFinding, SeverityLevel, Language } from '@/types';
import { generatePDF } from '@/lib/pdfGenerator';
import { cn, severityColor, severityDotColor } from '@/lib/utils';
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
} from 'lucide-react';

export function ReportsView() {
  const { state, language: appLanguage } = useApp();
  const t = translations[appLanguage];

  // Report configuration state
  const [reportType, setReportType] = useState<'executive' | 'technical'>('executive');
  const [reportLang, setReportLang] = useState<Language>(appLanguage);
  const [reportTitle, setReportTitle] = useState('Cybersecurity Incident Assessment & Log Forensics');
  const [author, setAuthor] = useState('Lead SOC Analyst (L2)');
  const [organization, setOrganization] = useState('Enterprise Cyber Defense Services');
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeRawLogs, setIncludeRawLogs] = useState(true);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>(
    state.findings.map((f) => f.id)
  );
  const [isExporting, setIsExporting] = useState(false);
  const [activePreviewTab, setActivePreviewTab] = useState<'executive' | 'technical'>('executive');

  // Findings list filter inside report config
  const [findingsFilterSeverity, setFindingsFilterSeverity] = useState<string>('all');

  // Sync active preview tab with report type selector
  const handleTypeChange = (type: 'executive' | 'technical') => {
    setReportType(type);
    setActivePreviewTab(type);
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
    const counts: Record<SeverityLevel, number> = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
    };
    for (const f of state.findings) {
      if (selectedFindingIds.includes(f.id)) {
        counts[f.severity] = (counts[f.severity] || 0) + 1;
      }
    }
    return counts;
  }, [state.findings, selectedFindingIds]);

  // Filtered findings selected for the report
  const reportFindings = useMemo(() => {
    return state.findings.filter((f) => selectedFindingIds.includes(f.id));
  }, [state.findings, selectedFindingIds]);

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
      // Deselect all in this severity
      setSelectedFindingIds(selectedFindingIds.filter((id) => !targetIds.includes(id)));
    } else {
      // Select all in this severity
      const newSelection = Array.from(new Set([...selectedFindingIds, ...targetIds]));
      setSelectedFindingIds(newSelection);
    }
  };

  // Select only Critical and High findings
  const selectCriticalAndHigh = () => {
    const critAndHighIds = [
      ...findingsBySeverity.Critical.map((f) => f.id),
      ...findingsBySeverity.High.map((f) => f.id),
    ];
    setSelectedFindingIds(critAndHighIds);
  };

  // Select only Critical findings
  const selectOnlyCritical = () => {
    const critIds = findingsBySeverity.Critical.map((f) => f.id);
    setSelectedFindingIds(critIds);
  };

  // Visible findings in the selector based on the tab/filter
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

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200/60 dark:border-indigo-800 px-2.5 py-0.5 rounded-full">
            {appLanguage === 'en' ? 'Automated Deliverable Generation' : 'Generación Automatizada de Entregables'}
          </span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          {t.report_title}
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-2xl leading-relaxed">
          {t.report_subtitle}.{' '}
          {appLanguage === 'en'
            ? 'Produce executive briefings for C-level leadership or in-depth technical documentation for engineering and compliance teams.'
            : 'Produzca informes ejecutivos para liderazgo C-level o documentación técnica profunda para equipos de ingeniería y cumplimiento.'}
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Configuration Form (5 cols) */}
        <div className="lg:col-span-5 space-y-5">
          <div className="glass-card p-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
              <Settings2 className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                {appLanguage === 'en' ? 'Report Parameters' : 'Parámetros del Reporte'}
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
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 font-normal">C-Level & Management</div>
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
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 font-normal">SOC, Forensic, IR</div>
                </button>
              </div>
            </div>

            {/* Language Selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                <span>{t.report_language}</span>
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setReportLang('en')}
                  className={cn(
                    'py-2 px-3 rounded-lg border text-xs font-semibold transition',
                    reportLang === 'en'
                      ? 'border-indigo-600 bg-indigo-600 text-white shadow-sm'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  )}
                >
                  🇬🇧 {t.report_lang_en}
                </button>
                <button
                  type="button"
                  onClick={() => setReportLang('es')}
                  className={cn(
                    'py-2 px-3 rounded-lg border text-xs font-semibold transition',
                    reportLang === 'es'
                      ? 'border-indigo-600 bg-indigo-600 text-white shadow-sm'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  )}
                >
                  🇪🇸 {t.report_lang_es}
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
                  {selectedFindingIds.length} / {state.findings.length} selected
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
                  {appLanguage === 'en' ? 'Toggle by Criticality' : 'Alternar por Criticidad'}:
                </span>
                <div className="grid grid-cols-2 gap-1.5">
                  {severities.map((sev) => {
                    const totalInSev = findingsBySeverity[sev].length;
                    const selectedInSev = selectedCounts[sev];
                    const isFullySelected = totalInSev > 0 && selectedInSev === totalInSev;
                    const isPartiallySelected = selectedInSev > 0 && selectedInSev < totalInSev;

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
                          {selectedInSev}/{totalInSev}
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
                        <span className="truncate font-medium text-[11px]">
                          {f.title}
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
              <span>{isExporting ? t.report_generating : `${t.report_download} (${reportFindings.length} alerts)`}</span>
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
              <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                {reportLang.toUpperCase()}
              </span>
              <span className="text-[10px] font-mono text-indigo-600 dark:text-indigo-400 font-semibold ml-2">
                {reportFindings.length} findings included
              </span>
            </div>

            <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 p-1 rounded-lg">
              <button
                type="button"
                onClick={() => setActivePreviewTab('executive')}
                className={cn(
                  'px-3 py-1 rounded-md text-xs font-semibold transition',
                  activePreviewTab === 'executive'
                    ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                )}
              >
                {t.report_executive}
              </button>
              <button
                type="button"
                onClick={() => setActivePreviewTab('technical')}
                className={cn(
                  'px-3 py-1 rounded-md text-xs font-semibold transition',
                  activePreviewTab === 'technical'
                    ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                )}
              >
                {t.report_technical}
              </button>
            </div>
          </div>

          {/* Render Document Mockup */}
          <div className="glass-card p-8 bg-white dark:bg-slate-900/90 border border-slate-300 dark:border-slate-800 shadow-md rounded-2xl min-h-[600px] text-slate-900 dark:text-slate-100 space-y-6">
            {/* Header Document Banner */}
            <div className="border-b border-slate-800 dark:border-slate-700 pb-4">
              <div className="flex items-center justify-between text-[10px] font-mono tracking-widest text-slate-400 dark:text-slate-500 uppercase">
                <span>SOC L2 FORENSICS REPORT</span>
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
                <span>DATE: <strong className="text-slate-800 dark:text-slate-200">{new Date().toLocaleDateString()}</strong></span>
              </div>
            </div>

            {/* Mode 1: Executive Summary Preview */}
            {activePreviewTab === 'executive' ? (
              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 mb-2">
                    {reportLang === 'en' ? '1. Management Briefing' : '1. Resumen para la Dirección'}
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    {reportLang === 'en'
                      ? `During the analyzed inspection window, our SOC Level 2 automated detection engine processed ${state.stats?.totalLogs.toLocaleString()} SIEM telemetry logs. A total of ${reportFindings.length} verified security threats were selected for this executive report.`
                      : `Durante la ventana de inspección analizada, nuestro motor automatizado SOC Nivel 2 procesó ${state.stats?.totalLogs.toLocaleString()} registros de telemetría SIEM. Se seleccionaron ${reportFindings.length} amenazas de seguridad verificadas para este informe ejecutivo.`}
                  </p>
                </div>

                {/* Executive Risk Matrix of Selected Findings */}
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/60 rounded-xl">
                    <p className="text-xl font-black text-rose-600 dark:text-rose-400">{selectedCounts.Critical}</p>
                    <p className="text-[10px] font-bold uppercase text-rose-700 dark:text-rose-300">Critical</p>
                  </div>
                  <div className="p-3 bg-orange-50 dark:bg-orange-950/40 border border-orange-200 dark:border-orange-900/60 rounded-xl">
                    <p className="text-xl font-black text-orange-600 dark:text-orange-400">{selectedCounts.High}</p>
                    <p className="text-[10px] font-bold uppercase text-orange-700 dark:text-orange-300">High</p>
                  </div>
                  <div className="p-3 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900/60 rounded-xl">
                    <p className="text-xl font-black text-amber-600 dark:text-amber-400">{selectedCounts.Medium}</p>
                    <p className="text-[10px] font-bold uppercase text-amber-700 dark:text-amber-300">Medium</p>
                  </div>
                  <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900/60 rounded-xl">
                    <p className="text-xl font-black text-emerald-600 dark:text-emerald-400">{selectedCounts.Low}</p>
                    <p className="text-[10px] font-bold uppercase text-emerald-700 dark:text-emerald-300">Low</p>
                  </div>
                </div>

                {/* Key Executive Findings */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                    {reportLang === 'en' ? '2. Selected Priority Alerts' : '2. Alertas Prioritarias Seleccionadas'}
                  </h4>
                  {reportFindings.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-400 border border-dashed border-slate-300 dark:border-slate-800 rounded-xl">
                      No findings currently selected. Use the left panel to select findings by criticality.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {reportFindings.slice(0, 4).map((f, i) => (
                        <div key={f.id} className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200 dark:border-slate-800 space-y-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-bold text-slate-900 dark:text-white">
                              #{i + 1} {f.title}
                            </span>
                            <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase', severityColor(f.severity))}>
                              {f.severity}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">
                            {f.description}
                          </p>
                          <p className="text-[11px] text-indigo-900 dark:text-indigo-300 font-semibold pt-1">
                            Strategic Action: {f.recommendation}
                          </p>
                        </div>
                      ))}
                      {reportFindings.length > 4 && (
                        <p className="text-[11px] text-slate-400 dark:text-slate-500 text-center pt-1 font-mono">
                          + {reportFindings.length - 4} more findings will be included in the PDF export
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              /* Mode 2: Technical Forensic Report Preview */
              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 mb-2">
                    {reportLang === 'en' ? '1. Forensic Telemetry Scope' : '1. Alcance de Telemetría Forense'}
                  </h4>
                  <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-slate-900 dark:bg-slate-950 text-slate-200 p-3.5 rounded-xl border border-slate-800">
                    <div>TOTAL EVENTS: <span className="text-emerald-400">{state.stats?.totalLogs}</span></div>
                    <div>SELECTED FINDINGS: <span className="text-rose-400">{reportFindings.length}</span></div>
                    <div>DISTINCT SRC IPs: <span className="text-cyan-400">{state.stats?.uniqueSourceIPs}</span></div>
                    <div>USER ACCOUNTS: <span className="text-amber-300">{state.stats?.uniqueUsers}</span></div>
                  </div>
                </div>

                {/* Detailed Findings Table */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                    {reportLang === 'en' ? '2. Threat Correlation Deep Dive' : '2. Análisis Forense Detallado'}
                  </h4>
                  {reportFindings.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-400 border border-dashed border-slate-300 dark:border-slate-800 rounded-xl">
                      No findings selected. Use the left panel to select findings by criticality.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {reportFindings.slice(0, 3).map((f, i) => (
                        <div key={f.id} className="p-3.5 border border-slate-200 dark:border-slate-800 rounded-xl bg-slate-50/70 dark:bg-slate-800/50 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-slate-900 dark:text-white">
                              #{i + 1} {f.title}
                            </span>
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded font-semibold text-slate-700 dark:text-slate-300">
                              MITRE: {f.mitreId}
                            </span>
                          </div>
                          <div className="text-[11px] font-mono bg-white dark:bg-slate-900 p-2.5 rounded border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300">
                            <strong>EVIDENCE:</strong> {f.justification}
                          </div>
                          <div className="text-[11px] text-slate-600 dark:text-slate-400">
                            <strong>Assets:</strong> {f.affectedAssets.join(', ')}
                          </div>
                          <div className="text-[11px] text-slate-600 dark:text-slate-400">
                            <strong>IoCs:</strong> {f.indicators.join(' | ')}
                          </div>
                        </div>
                      ))}
                      {reportFindings.length > 3 && (
                        <p className="text-[11px] text-slate-400 dark:text-slate-500 text-center pt-1 font-mono">
                          + {reportFindings.length - 3} more technical finding sections included in PDF export
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Document Footer Disclaimer */}
            <div className="pt-6 border-t border-slate-200 dark:border-slate-800 text-[10px] text-slate-400 dark:text-slate-500 leading-relaxed font-sans">
              {reportLang === 'en'
                ? 'NOTICE: Generated via SOC Level 2 automated audit rules. All findings are derived strictly from immutable records present in the SIEM export file.'
                : 'AVISO: Generado mediante reglas automatizadas SOC Nivel 2. Todos los hallazgos se derivan estrictamente de los registros inmutables presentes en el archivo SIEM.'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
