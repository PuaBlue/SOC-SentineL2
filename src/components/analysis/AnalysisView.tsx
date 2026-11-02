'use client';

import { useState, useMemo } from 'react';
import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { SecurityFinding, SeverityLevel, FindingType, LogEntry } from '@/types';
import { cn, severityColor, severityDotColor } from '@/lib/utils';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  Terminal,
  Crosshair,
  Server,
  User,
  Clock,
  Layers,
  ArrowUpDown,
  BookOpen,
  Eye,
  X,
  FileText,
} from 'lucide-react';

export function AnalysisView() {
  const { state, language } = useApp();
  const t = translations[language];

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'severity' | 'confidence' | 'time'>('severity');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [inspectingLogsFinding, setInspectingLogsFinding] = useState<SecurityFinding | null>(null);

  // Map log IDs for fast lookup
  const logMap = useMemo(() => {
    const map = new Map<string, LogEntry>();
    for (const log of state.logs) {
      map.set(log.id, log);
    }
    return map;
  }, [state.logs]);

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    return state.findings
      .filter((finding) => {
        // Severity filter
        if (selectedSeverity !== 'all' && finding.severity.toLowerCase() !== selectedSeverity.toLowerCase()) {
          return false;
        }
        // Type filter
        if (selectedType !== 'all' && finding.type !== selectedType) {
          return false;
        }
        // Search query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchTitle = finding.title.toLowerCase().includes(q);
          const matchDesc = finding.description.toLowerCase().includes(q);
          const matchJust = finding.justification.toLowerCase().includes(q);
          const matchAssets = finding.affectedAssets.some((a) => a.toLowerCase().includes(q));
          const matchMitre = finding.mitreId?.toLowerCase().includes(q) || finding.mitreTactic?.toLowerCase().includes(q);
          return matchTitle || matchDesc || matchJust || matchAssets || matchMitre;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'severity') {
          const rank: Record<SeverityLevel, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
          return (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4);
        }
        if (sortBy === 'confidence') {
          return b.confidence - a.confidence;
        }
        // by time
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      });
  }, [state.findings, selectedSeverity, selectedType, searchQuery, sortBy]);

  const typeLabelMap: Record<FindingType, string> = {
    brute_force: t.finding_brute_force,
    suspicious_login: t.finding_suspicious_login,
    privilege_escalation: t.finding_privilege_escalation,
    anomalous_command: t.finding_anomalous_command,
    lateral_movement: t.finding_lateral_movement,
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200/60 dark:border-indigo-800 px-2.5 py-0.5 rounded-full">
            {language === 'en' ? 'Evidence-Based Threat Correlation' : 'Correlación de Amenazas Basada en Evidencia'}
          </span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          {t.analysis_title}
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-3xl leading-relaxed">
          {t.analysis_subtitle}.{' '}
          {language === 'en'
            ? 'Strict analytical rigor is enforced: every detection is directly supported by immutable SIEM log records.'
            : 'Se aplica un rigor analítico estricto: cada detección se sustenta directamente en registros de logs SIEM inmutables.'}
        </p>
      </div>

      {/* Control Bar: Filters, Search, and Sorters */}
      <div className="glass-card p-4 space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder={language === 'en' ? 'Search findings, assets, IPs, MITRE IDs...' : 'Buscar hallazgos, activos, IPs, MITRE...'}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-8 py-2 text-xs bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 text-slate-800 dark:text-slate-100"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Severity filter buttons */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
            {['all', 'Critical', 'High', 'Medium', 'Low'].map((sev) => {
              const isSelected = selectedSeverity === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all',
                    isSelected
                      ? sev === 'Critical'
                        ? 'bg-rose-600 text-white shadow-sm'
                        : sev === 'High'
                          ? 'bg-orange-600 text-white shadow-sm'
                          : sev === 'Medium'
                            ? 'bg-amber-600 text-white shadow-sm'
                            : sev === 'Low'
                              ? 'bg-emerald-600 text-white shadow-sm'
                              : 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
                  )}
                >
                  {sev === 'all'
                    ? t.analysis_filter_all
                    : sev === 'Critical'
                      ? t.dash_critical
                      : sev === 'High'
                        ? t.dash_high
                        : sev === 'Medium'
                          ? t.dash_medium
                          : t.dash_low}
                </button>
              );
            })}
          </div>
        </div>

        {/* Secondary filters: Type and Sort */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-100 dark:border-slate-800 text-xs">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
            <span className="font-semibold text-slate-600 dark:text-slate-400">{t.analysis_filter_type}:</span>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1 text-slate-700 dark:text-slate-300 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="all">{t.analysis_filter_all}</option>
              <option value="brute_force">{t.finding_brute_force}</option>
              <option value="suspicious_login">{t.finding_suspicious_login}</option>
              <option value="privilege_escalation">{t.finding_privilege_escalation}</option>
              <option value="anomalous_command">{t.finding_anomalous_command}</option>
              <option value="lateral_movement">{t.finding_lateral_movement}</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <ArrowUpDown className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
            <span className="font-semibold text-slate-600 dark:text-slate-400">Sort:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'severity' | 'confidence' | 'time')}
              className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1 text-slate-700 dark:text-slate-300 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="severity">Criticality</option>
              <option value="confidence">Confidence Score</option>
              <option value="time">Timestamp</option>
            </select>
            <span className="text-slate-400 dark:text-slate-500 font-mono text-[11px] ml-1">
              ({filteredFindings.length} {language === 'en' ? 'findings' : 'hallazgos'})
            </span>
          </div>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <CheckCircle2 className="w-12 h-12 mx-auto text-emerald-500 mb-3" />
          <h3 className="text-base font-bold text-slate-800 dark:text-slate-200">{t.analysis_no_findings}</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-sm mx-auto">
            {language === 'en'
              ? 'Try adjusting your filters or search keywords to view other correlated items.'
              : 'Intente ajustar sus filtros o términos de búsqueda para ver otros elementos correlacionados.'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredFindings.map((finding) => {
            const isExpanded = expandedFindingId === finding.id;
            return (
              <div
                key={finding.id}
                className={cn(
                  'glass-card border transition-all duration-200 overflow-hidden',
                  isExpanded ? 'shadow-md border-indigo-200 dark:border-indigo-800 ring-1 ring-indigo-500/10' : 'hover:border-slate-300 dark:hover:border-slate-700'
                )}
              >
                {/* Header row */}
                <div
                  onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                  className="p-5 cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="flex items-start gap-3.5">
                    <div
                      className={cn(
                        'w-9 h-9 rounded-xl flex items-center justify-center shrink-0 font-black text-xs',
                        finding.severity === 'Critical'
                          ? 'bg-rose-100 dark:bg-rose-950/70 text-rose-700 dark:text-rose-400'
                          : finding.severity === 'High'
                            ? 'bg-orange-100 dark:bg-orange-950/70 text-orange-700 dark:text-orange-400'
                            : finding.severity === 'Medium'
                              ? 'bg-amber-100 dark:bg-amber-950/70 text-amber-700 dark:text-amber-400'
                              : 'bg-emerald-100 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-400'
                      )}
                    >
                      {finding.severity === 'Critical' ? 'CRIT' : finding.severity === 'High' ? 'HIGH' : finding.severity === 'Medium' ? 'MED' : 'LOW'}
                    </div>

                    <div>
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider',
                            severityColor(finding.severity)
                          )}
                        >
                          {finding.severity}
                        </span>
                        <span className="text-[11px] font-semibold text-indigo-700 dark:text-indigo-300 bg-indigo-50 dark:bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-200/50 dark:border-indigo-800">
                          {typeLabelMap[finding.type] || finding.type}
                        </span>
                        {finding.mitreId && (
                          <span className="text-[10px] font-mono font-bold text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded border border-slate-200/50 dark:border-slate-700">
                            MITRE: {finding.mitreTactic} ({finding.mitreId})
                          </span>
                        )}
                        <span className="text-[10px] text-slate-400 dark:text-slate-500 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {new Date(finding.timestamp).toLocaleString()}
                        </span>
                      </div>

                      <h3 className="text-base font-bold text-slate-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400">
                        {finding.title}
                      </h3>
                      <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 line-clamp-2 leading-relaxed">
                        {finding.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                    <div className="text-right">
                      <span className="text-[10px] uppercase font-bold text-slate-400 dark:text-slate-500 block">
                        {t.analysis_confidence}
                      </span>
                      <span className="text-sm font-black text-slate-800 dark:text-slate-200 font-mono">
                        {finding.confidence}%
                      </span>
                    </div>

                    <button
                      type="button"
                      className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                      ) : (
                        <ChevronRight className="w-5 h-5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Expanded Detailed SOC Forensic View */}
                {isExpanded && (
                  <div className="px-5 pb-6 pt-2 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 space-y-5">
                    {/* Justification & Grounded Evidence */}
                    <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-2">
                      <div className="flex items-center gap-2 text-indigo-600 dark:text-indigo-400 font-bold text-xs uppercase tracking-wider">
                        <BookOpen className="w-3.5 h-3.5" />
                        <span>{t.analysis_justification}</span>
                      </div>
                      <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                        {finding.justification}
                      </p>
                    </div>

                    {/* Affected Assets & Indicators Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Assets */}
                      <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-2">
                        <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300 font-bold text-xs uppercase tracking-wider">
                          <Server className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                          <span>{t.analysis_affected_assets}</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {finding.affectedAssets.map((asset, idx) => (
                            <span
                              key={idx}
                              className="px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 font-mono text-[11px] font-semibold"
                            >
                              {asset}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* IoCs */}
                      <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-2">
                        <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300 font-bold text-xs uppercase tracking-wider">
                          <Crosshair className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
                          <span>{t.analysis_indicators}</span>
                        </div>
                        <ul className="space-y-1 text-xs text-slate-600 dark:text-slate-400">
                          {finding.indicators.map((ind, idx) => (
                            <li key={idx} className="flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                              <span className="font-mono text-[11px]">{ind}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {/* Recommendations */}
                    <div className="p-4 rounded-xl bg-indigo-50/70 dark:bg-indigo-950/40 border border-indigo-200/80 dark:border-indigo-900/60 space-y-1.5">
                      <div className="flex items-center gap-2 text-indigo-900 dark:text-indigo-300 font-bold text-xs uppercase tracking-wider">
                        <AlertTriangle className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                        <span>{t.analysis_recommendation}</span>
                      </div>
                      <p className="text-xs text-indigo-950 dark:text-indigo-200 font-medium leading-relaxed">
                        {finding.recommendation}
                      </p>
                    </div>

                    {/* Action button to inspect supporting raw SIEM logs */}
                    <div className="flex items-center justify-between pt-2">
                      <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                        {finding.relatedLogIds.length} SIEM raw logs directly correlate to this finding
                      </span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setInspectingLogsFinding(finding);
                        }}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 dark:bg-slate-800 text-white text-xs font-semibold hover:bg-slate-800 dark:hover:bg-slate-700 transition shadow-sm"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>
                          {language === 'en' ? 'Inspect Related SIEM Logs' : 'Inspeccionar Logs SIEM Relacionados'}
                        </span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Correlated Logs Modal Inspector */}
      {inspectingLogsFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-in">
          <div className="bg-white dark:bg-slate-900 rounded-2xl max-w-4xl w-full max-h-[85vh] flex flex-col shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between bg-slate-50 dark:bg-slate-950">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                      severityColor(inspectingLogsFinding.severity)
                    )}
                  >
                    {inspectingLogsFinding.severity}
                  </span>
                  <span className="text-xs font-bold text-indigo-600 dark:text-indigo-400">
                    {typeLabelMap[inspectingLogsFinding.type]}
                  </span>
                </div>
                <h3 className="font-bold text-base text-slate-900 dark:text-white">
                  {inspectingLogsFinding.title}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Showing {inspectingLogsFinding.relatedLogIds.length} underlying logs registered in database
                </p>
              </div>

              <button
                onClick={() => setInspectingLogsFinding(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-200/50 dark:hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Log List */}
            <div className="p-5 overflow-y-auto space-y-3 flex-1 font-mono text-xs">
              {inspectingLogsFinding.relatedLogIds.map((logId, idx) => {
                const log = logMap.get(logId);
                if (!log) return null;
                return (
                  <div
                    key={logId || idx}
                    className="p-3 rounded-xl bg-slate-900 dark:bg-slate-950 text-slate-200 space-y-1.5 border border-slate-800"
                  >
                    <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-400 border-b border-slate-800 pb-1">
                      <span className="text-indigo-400 font-bold">
                        {log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}
                      </span>
                      <span>SRC: <span className="text-emerald-400">{log.source_ip || 'N/A'}</span> → DST: <span className="text-cyan-400">{log.destination_ip || 'N/A'}</span></span>
                      <span>USER: <span className="text-amber-300">{log.user || 'N/A'}</span></span>
                    </div>
                    <div className="text-slate-300 font-sans text-xs">
                      {log.message}
                    </div>
                    {log.raw_log && (
                      <div className="text-[10px] text-slate-500 break-all bg-slate-950 p-1.5 rounded border border-slate-800/80">
                        {log.raw_log}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex justify-end bg-slate-50 dark:bg-slate-950">
              <button
                onClick={() => setInspectingLogsFinding(null)}
                className="px-4 py-2 bg-slate-900 dark:bg-slate-800 text-white rounded-xl text-xs font-semibold hover:bg-slate-800 dark:hover:bg-slate-700 transition"
              >
                {language === 'en' ? 'Close Inspector' : 'Cerrar Inspector'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
