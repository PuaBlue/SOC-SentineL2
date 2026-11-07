'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { cn, severityColor, severityDotColor } from '@/lib/utils';
import { ThreatIntelModal } from '@/components/threat-intel/ThreatIntelModal';
import {
  ShieldAlert,
  Activity,
  Users,
  Globe,
  AlertTriangle,
  ArrowUpRight,
  TrendingUp,
  Clock,
  ExternalLink,
  Flame,
  RefreshCw,
  ShieldCheck,
  Key,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  AreaChart,
  Area,
} from 'recharts';

const SEVERITY_COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
};

const CHART_PALETTE = [
  '#6366f1', '#8b5cf6', '#ec4899', '#f43f5e', '#ef4444',
  '#f97316', '#eab308', '#10b981', '#06b6d4', '#3b82f6',
];

export function DashboardView() {
  const { state, language, theme, setView, enrichThreatIntel } = useApp();
  const [isThreatIntelOpen, setIsThreatIntelOpen] = useState(false);
  const t = translations[language];
  const stats = state.stats;

  if (!stats) return null;

  const isDark = theme === 'dark';
  const gridStroke = isDark ? '#1e293b' : '#f1f5f9';
  const textFill = isDark ? '#94a3b8' : '#64748b';

  const reputations = state.threatIntel.reputations;
  const isEnriching = state.threatIntel.isEnriching;
  const reputationList = Object.values(reputations);
  const maliciousIpsCount = reputationList.filter((r) => r.verdict === 'Malicious').length;
  const totalEnrichedIps = reputationList.length;

  const severityData = [
    { name: t.dash_critical, value: stats.criticalCount, color: SEVERITY_COLORS.Critical },
    { name: t.dash_high, value: stats.highCount, color: SEVERITY_COLORS.High },
    { name: t.dash_medium, value: stats.mediumCount, color: SEVERITY_COLORS.Medium },
    { name: t.dash_low, value: stats.lowCount, color: SEVERITY_COLORS.Low },
  ].filter((d) => d.value > 0);

  const findingTypeData = stats.findingsByType
    .filter((f) => f.count > 0)
    .map((f) => {
      const typeKey = `finding_${f.type}` as keyof typeof t;
      return {
        name: t[typeKey] || f.type.replace('_', ' '),
        count: f.count,
        type: f.type,
      };
    });

  const timelineData = stats.timelineData.map((d) => {
    const dateObj = new Date(d.timestamp);
    return {
      ...d,
      time: !isNaN(dateObj.getTime())
        ? dateObj.toLocaleTimeString(language === 'es' ? 'es-ES' : 'en-US', {
            hour: '2-digit',
            minute: '2-digit',
          })
        : d.timestamp,
    };
  });

  // Recharts tooltip styling for dark and light theme
  const tooltipProps = {
    contentStyle: {
      backgroundColor: isDark ? '#0f172a' : '#ffffff',
      borderColor: isDark ? '#334155' : '#e2e8f0',
      borderRadius: '0.75rem',
      color: isDark ? '#f8fafc' : '#0f172a',
      boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -4px rgba(0, 0, 0, 0.2)',
      padding: '8px 12px',
    },
    itemStyle: {
      color: isDark ? '#f8fafc' : '#0f172a',
      fontSize: '12px',
      fontWeight: 600,
    },
    labelStyle: {
      color: isDark ? '#f8fafc' : '#0f172a',
      fontSize: '12px',
      fontWeight: 700,
      marginBottom: '4px',
    },
  };

  return (
    <>
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Top Banner / Breadcrumb */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-semibold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200/60 dark:border-indigo-800 px-2.5 py-0.5 rounded-full">
                {language === 'en' ? 'SOC Level 2 Telemetry' : 'Telemetría SOC Nivel 2'}
              </span>
              <span className="text-xs text-slate-400 dark:text-slate-500 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {stats.timeRange.start
                  ? `${new Date(stats.timeRange.start).toLocaleDateString()} — ${new Date(stats.timeRange.end).toLocaleDateString()}`
                  : 'Current Session'}
              </span>
            </div>
            <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
              {t.dash_title}
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {language === 'en' ? 'Active Investigation Source:' : 'Fuente de investigación activa:'}{' '}
              <span className="font-semibold text-slate-700 dark:text-slate-300">{state.fileName}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsThreatIntelOpen(true)}
              className="inline-flex items-center gap-2 px-3.5 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-800 hover:border-indigo-500 rounded-xl text-xs font-semibold text-slate-800 dark:text-slate-200 shadow-sm transition"
            >
              <Globe className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              <span>{t.ti_title}</span>
            </button>

            <button
              onClick={() => setView('analysis')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-xl text-xs font-semibold hover:bg-indigo-700 transition shadow-sm shadow-indigo-600/20"
            >
              <span>{language === 'en' ? 'Inspect Correlated Findings' : 'Inspeccionar Hallazgos'}</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Threat Intelligence Telemetry Card */}
        <div className="p-4 rounded-2xl glass-card border border-indigo-100 dark:border-indigo-900/60 bg-gradient-to-r from-indigo-50/50 via-white dark:via-slate-900 to-purple-50/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-indigo-600 text-white flex items-center justify-center shrink-0 shadow-md shadow-indigo-600/25">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-xs text-slate-900 dark:text-white uppercase tracking-wider">
                  {language === 'en' ? 'Threat Intelligence Feeds' : 'Inteligencia Externa de Amenazas'}
                </h3>
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-indigo-100 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800">
                  VirusTotal v3 + AbuseIPDB v2
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
                {totalEnrichedIps > 0 ? (
                  <span>
                    {language === 'en'
                      ? `Corroborated ${totalEnrichedIps} Source IPs across global threat databases. `
                      : `Corroboradas ${totalEnrichedIps} IPs origen en bases de datos globales de amenazas. `}
                    {maliciousIpsCount > 0 ? (
                      <strong className="text-rose-600 dark:text-rose-400">
                        {maliciousIpsCount} {language === 'en' ? 'flagged as MALICIOUS' : 'identificadas como MALICIOSAS'}.
                      </strong>
                    ) : (
                      <strong className="text-emerald-600 dark:text-emerald-400">
                        {language === 'en' ? 'No malicious reputation flags detected.' : 'Sin banderas de reputación maliciosa.'}
                      </strong>
                    )}
                  </span>
                ) : (
                  <span>
                    {language === 'en'
                      ? 'Ready to query external reputation for observed IPs.'
                      : 'Listo para consultar reputación externa de las IPs observadas.'}
                  </span>
                )}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setIsThreatIntelOpen(true)}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:border-indigo-500 text-slate-700 dark:text-slate-300 transition flex items-center gap-1.5"
            >
              <Key className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>{language === 'en' ? 'API Settings & Results' : 'Configurar Claves / Resultados'}</span>
            </button>

            <button
              onClick={() => enrichThreatIntel()}
              disabled={isEnriching}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white transition flex items-center gap-1.5 disabled:opacity-50 shadow-sm"
            >
              <RefreshCw className={cn('w-3.5 h-3.5', isEnriching && 'animate-spin')} />
              <span>{isEnriching ? t.ti_enriching : t.ti_enrich_btn}</span>
            </button>
          </div>
        </div>

        {/* KPI Cards Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="stat-card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t.dash_total_logs}
              </span>
              <div className="w-8 h-8 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
                <Activity className="w-4 h-4" />
              </div>
            </div>
            <p className="text-3xl font-black text-slate-900 dark:text-white">{stats.totalLogs.toLocaleString()}</p>
            <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">SIEM normalized events</p>
          </div>

          <div className="stat-card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t.dash_findings}
              </span>
              <div className="w-8 h-8 rounded-lg bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400 flex items-center justify-center">
                <ShieldAlert className="w-4 h-4" />
              </div>
            </div>
            <p className="text-3xl font-black text-rose-600 dark:text-rose-400">{stats.totalFindings}</p>
            <p className="text-[11px] text-rose-500 dark:text-rose-400 font-semibold mt-1 flex items-center gap-1">
              <Flame className="w-3 h-3" />
              {language === 'en'
                ? `${stats.criticalCount} ${t.dash_critical.toLowerCase()} threats identified`
                : `${stats.criticalCount} amenazas críticas identificadas`}
            </p>
          </div>

          <div className="stat-card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t.dash_unique_ips}
              </span>
              <div className="w-8 h-8 rounded-lg bg-cyan-50 dark:bg-cyan-950/60 text-cyan-600 dark:text-cyan-400 flex items-center justify-center">
                <Globe className="w-4 h-4" />
              </div>
            </div>
            <p className="text-3xl font-black text-slate-900 dark:text-white">{stats.uniqueSourceIPs.toLocaleString()}</p>
            <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Distinct inbound & internal addresses</p>
          </div>

          <div className="stat-card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t.dash_unique_users}
              </span>
              <div className="w-8 h-8 rounded-lg bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-400 flex items-center justify-center">
                <Users className="w-4 h-4" />
              </div>
            </div>
            <p className="text-3xl font-black text-slate-900 dark:text-white">{stats.uniqueUsers.toLocaleString()}</p>
            <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Authenticated identity accounts</p>
          </div>
        </div>

        {/* Criticality Breakdown Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: t.dash_critical, count: stats.criticalCount, sev: 'Critical', bg: 'bg-rose-50 dark:bg-rose-950/30', text: 'text-rose-700 dark:text-rose-400', border: 'border-rose-200 dark:border-rose-900/60' },
            { label: t.dash_high, count: stats.highCount, sev: 'High', bg: 'bg-orange-50 dark:bg-orange-950/30', text: 'text-orange-700 dark:text-orange-400', border: 'border-orange-200 dark:border-orange-900/60' },
            { label: t.dash_medium, count: stats.mediumCount, sev: 'Medium', bg: 'bg-amber-50 dark:bg-amber-950/30', text: 'text-amber-700 dark:text-amber-400', border: 'border-amber-200 dark:border-amber-900/60' },
            { label: t.dash_low, count: stats.lowCount, sev: 'Low', bg: 'bg-emerald-50 dark:bg-emerald-950/30', text: 'text-emerald-700 dark:text-emerald-400', border: 'border-emerald-200 dark:border-emerald-900/60' },
          ].map((item) => (
            <div
              key={item.sev}
              className={cn(
                'rounded-xl p-3.5 border flex items-center justify-between transition-all hover:shadow-sm',
                item.bg,
                item.border
              )}
            >
              <div>
                <p className={cn('text-2xl font-black', item.text)}>{item.count}</p>
                <p className={cn('text-xs font-bold uppercase tracking-wider', item.text)}>
                  {item.label}
                </p>
              </div>
              <div className={cn('w-3.5 h-3.5 rounded-full', severityDotColor(item.sev))} />
            </div>
          ))}
        </div>

        {/* Charts Grid Row 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Severity Distribution */}
          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                {t.dash_severity_dist}
              </h3>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">Risk Ratio</span>
            </div>
            <div className="h-64 flex items-center justify-center">
              {severityData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={3}
                      dataKey="value"
                      label={({ name, value }) => `${name} (${value})`}
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip {...tooltipProps} />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-xs text-slate-400">{t.common_no_data}</p>
              )}
            </div>
          </div>

          {/* Attack Types Bar Chart */}
          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                {t.dash_findings_by_type}
              </h3>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">TTPs</span>
            </div>
            <div className="h-64">
              {findingTypeData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={findingTypeData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                    <XAxis type="number" tick={{ fontSize: 11, fill: textFill }} />
                    <YAxis
                      dataKey="name"
                      type="category"
                      width={140}
                      tick={{ fontSize: 10, fill: textFill }}
                    />
                    <Tooltip {...tooltipProps} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {findingTypeData.map((_, i) => (
                        <Cell key={i} fill={CHART_PALETTE[i % CHART_PALETTE.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-slate-400">
                  {t.common_no_data}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Timeline Chart */}
        {timelineData.length > 0 && (
          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                {t.dash_events_timeline}
              </h3>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">
                Critical Incident Density
              </span>
            </div>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: textFill }} />
                  <YAxis tick={{ fontSize: 11, fill: textFill }} />
                  <Tooltip {...tooltipProps} />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    name={t.dash_critical}
                    stackId="1"
                    stroke="#ef4444"
                    fill="#ef4444"
                    fillOpacity={0.7}
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    name={t.dash_high}
                    stackId="1"
                    stroke="#f97316"
                    fill="#f97316"
                    fillOpacity={0.7}
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    name={t.dash_medium}
                    stackId="1"
                    stroke="#eab308"
                    fill="#eab308"
                    fillOpacity={0.7}
                  />
                  <Area
                    type="monotone"
                    dataKey="low"
                    name={t.dash_low}
                    stackId="1"
                    stroke="#22c55e"
                    fill="#22c55e"
                    fillOpacity={0.7}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Top Entities Section (Top IPs & Top Users) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top Source IPs with Threat Intel Reputation Badges */}
          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Globe className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                {t.dash_top_sources}
              </h3>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">
                Event Volume & Reputation
              </span>
            </div>
            <div className="space-y-3.5">
              {stats.topSourceIPs.slice(0, 6).map((item, idx) => {
                const maxVal = stats.topSourceIPs[0]?.count || 1;
                const pct = (item.count / maxVal) * 100;
                const rep = reputations[item.ip];

                return (
                  <div key={idx} className="space-y-1.5 p-2 rounded-lg bg-slate-50/50 dark:bg-slate-900/40 border border-slate-100 dark:border-slate-800/80">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-slate-900 dark:text-white font-bold">{item.ip}</span>

                        {/* Threat Intel Reputation Pill */}
                        {rep ? (
                          <span
                            className={cn(
                              'px-2 py-0.5 rounded text-[10px] font-sans font-bold uppercase tracking-wider',
                              rep.verdict === 'Malicious'
                                ? 'bg-rose-100 dark:bg-rose-950/70 text-rose-700 dark:text-rose-400 border border-rose-300 dark:border-rose-800'
                                : rep.verdict === 'Suspicious'
                                  ? 'bg-orange-100 dark:bg-orange-950/70 text-orange-700 dark:text-orange-400 border border-orange-300 dark:border-orange-800'
                                  : rep.verdict === 'Private'
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                                    : 'bg-emerald-100 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800'
                            )}
                          >
                            {rep.verdict === 'Malicious'
                              ? `VT: ${rep.vtMalicious ?? 0} • Abuse: ${rep.abuseConfidenceScore ?? 0}%`
                              : rep.verdict === 'Suspicious'
                                ? 'Suspicious'
                                : rep.verdict === 'Private'
                                  ? 'Private Subnet'
                                  : 'Clean'}
                          </span>
                        ) : (
                          <button
                            onClick={() => enrichThreatIntel([item.ip])}
                            disabled={isEnriching}
                            className="text-[10px] font-sans text-indigo-600 dark:text-indigo-400 hover:underline"
                          >
                            Verify
                          </button>
                        )}
                      </div>

                      <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px]">{item.count} hits</span>
                    </div>

                    <div className="w-full bg-slate-200 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={cn(
                          'h-1.5 rounded-full',
                          rep?.verdict === 'Malicious'
                            ? 'bg-rose-600 dark:bg-rose-500'
                            : 'bg-indigo-600 dark:bg-indigo-500'
                        )}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Top Users */}
          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Users className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                {t.dash_top_users}
              </h3>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">Identity Frequency</span>
            </div>
            <div className="space-y-3">
              {stats.topUsers.slice(0, 6).map((item, idx) => {
                const maxVal = stats.topUsers[0]?.count || 1;
                const pct = (item.count / maxVal) * 100;
                return (
                  <div key={idx} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-800 dark:text-slate-200 truncate max-w-[200px]">
                        {item.user}
                      </span>
                      <span className="text-slate-500 dark:text-slate-400 font-mono text-[11px]">{item.count} events</span>
                    </div>
                    <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className="bg-purple-600 dark:bg-purple-500 h-1.5 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Top Event Types */}
        {stats.eventsByType.length > 0 && (
          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <ArrowUpRight className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                {t.dash_events_by_type}
              </h3>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">Action Breakdown</span>
            </div>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.eventsByType.slice(0, 8)}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                  <XAxis dataKey="type" tick={{ fontSize: 10, fill: textFill }} />
                  <YAxis tick={{ fontSize: 11, fill: textFill }} />
                  <Tooltip {...tooltipProps} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {stats.eventsByType.slice(0, 8).map((_, i) => (
                      <Cell key={i} fill={CHART_PALETTE[i % CHART_PALETTE.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>

      {/* Threat Intelligence Modal */}
      <ThreatIntelModal
        isOpen={isThreatIntelOpen}
        onClose={() => setIsThreatIntelOpen(false)}
      />
    </>
  );
}
