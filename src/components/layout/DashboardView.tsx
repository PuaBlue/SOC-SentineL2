'use client';

import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { cn, severityColor, severityDotColor } from '@/lib/utils';
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
  const { state, language, theme, setView } = useApp();
  const t = translations[language];
  const stats = state.stats;

  if (!stats) return null;

  const isDark = theme === 'dark';
  const gridStroke = isDark ? '#1e293b' : '#f1f5f9';
  const textFill = isDark ? '#94a3b8' : '#64748b';

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

  return (
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

        <button
          onClick={() => setView('analysis')}
          className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-xl text-xs font-semibold hover:bg-indigo-700 transition shadow-sm shadow-indigo-600/20"
        >
          <span>{language === 'en' ? 'Inspect Correlated Findings' : 'Inspeccionar Hallazgos'}</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </button>
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
            {stats.criticalCount} {t.dash_critical.toLowerCase()} threats identified
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
                  <Tooltip
                    contentStyle={{
                      backgroundColor: isDark ? '#0f172a' : '#ffffff',
                      borderColor: isDark ? '#334155' : '#e2e8f0',
                      borderRadius: '0.75rem',
                      color: isDark ? '#f8fafc' : '#0f172a',
                    }}
                  />
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
                <BarChart data={findingTypeData} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                  <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: textFill }} />
                  <YAxis dataKey="name" type="category" width={140} tick={{ fontSize: 11, fill: textFill }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: isDark ? '#0f172a' : '#ffffff',
                      borderColor: isDark ? '#334155' : '#e2e8f0',
                      borderRadius: '0.75rem',
                      color: isDark ? '#f8fafc' : '#0f172a',
                    }}
                  />
                  <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center">
                <p className="text-xs text-slate-400">{t.common_no_data}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Timeline Area Chart */}
      {timelineData.length > 0 && (
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              {t.dash_events_timeline}
            </h3>
            <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">Hourly Volumetry</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: textFill }} />
                <YAxis tick={{ fontSize: 11, fill: textFill }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? '#0f172a' : '#ffffff',
                    borderColor: isDark ? '#334155' : '#e2e8f0',
                    borderRadius: '0.75rem',
                    color: isDark ? '#f8fafc' : '#0f172a',
                  }}
                />
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
        {/* Top Source IPs */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              {t.dash_top_sources}
            </h3>
            <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase font-semibold">Event Volume</span>
          </div>
          <div className="space-y-3">
            {stats.topSourceIPs.slice(0, 6).map((item, idx) => {
              const maxVal = stats.topSourceIPs[0]?.count || 1;
              const pct = (item.count / maxVal) * 100;
              return (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-800 dark:text-slate-200 font-semibold">{item.ip}</span>
                    <span className="text-slate-500 dark:text-slate-400 font-sans">{item.count} hits</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-indigo-600 dark:bg-indigo-500 h-1.5 rounded-full"
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
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? '#0f172a' : '#ffffff',
                    borderColor: isDark ? '#334155' : '#e2e8f0',
                    borderRadius: '0.75rem',
                    color: isDark ? '#f8fafc' : '#0f172a',
                  }}
                />
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
  );
}
