'use client';

import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { cn } from '@/lib/utils';
import {
  Upload,
  LayoutDashboard,
  Search,
  FileText,
  Shield,
  Globe,
  Trash2,
  FileCheck2,
  Sun,
  Moon,
} from 'lucide-react';

export function Sidebar() {
  const { state, language, setLanguage, theme, toggleTheme, setView, clearData } = useApp();
  const t = translations[language];
  const hasData = state.logs.length > 0;
  const hasFindings = state.findings.length > 0;

  const navItems = [
    { id: 'upload' as const, label: t.nav_upload, icon: Upload, enabled: true },
    { id: 'dashboard' as const, label: t.nav_dashboard, icon: LayoutDashboard, enabled: hasFindings },
    { id: 'analysis' as const, label: t.nav_analysis, icon: Search, enabled: hasFindings },
    { id: 'reports' as const, label: t.nav_reports, icon: FileText, enabled: hasFindings },
  ];

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-slate-950 text-slate-100 flex flex-col z-50 border-r border-slate-800">
      {/* Brand Header */}
      <div className="p-6 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-md shadow-indigo-600/30">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-tight text-white flex items-center gap-1.5">
              SOC Sentinel
              <span className="text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                L2
              </span>
            </h1>
            <p className="text-xs text-slate-400">Threat Intel & Reports</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1.5">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = state.currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => item.enabled && setView(item.id)}
              disabled={!item.enabled}
              className={cn(
                'w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all duration-150',
                isActive
                  ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 font-semibold'
                  : item.enabled
                    ? 'text-slate-300 hover:bg-slate-900 hover:text-white'
                    : 'text-slate-600 cursor-not-allowed opacity-50'
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
              {item.id === 'analysis' && state.findings.length > 0 && (
                <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                  {state.findings.length}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Loaded file information pill */}
      {hasData && (
        <div className="mx-4 mb-3 p-3 bg-slate-900/90 rounded-xl border border-slate-800 text-xs space-y-1">
          <div className="flex items-center gap-1.5 text-indigo-400 font-medium truncate">
            <FileCheck2 className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">{state.fileName}</span>
          </div>
          <div className="text-slate-400 text-[11px] flex justify-between">
            <span>{state.logs.length.toLocaleString()} {t.upload_records}</span>
            {hasFindings && (
              <span className="text-amber-400">{state.findings.length} findings</span>
            )}
          </div>
        </div>
      )}

      {/* Bottom controls: Theme, language & reset */}
      <div className="p-4 border-t border-slate-800/80 space-y-1.5">
        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-300 hover:bg-slate-900 transition-colors"
          title={theme === 'dark' ? t.theme_light : t.theme_dark}
        >
          <span className="flex items-center gap-2">
            {theme === 'dark' ? (
              <Sun className="w-3.5 h-3.5 text-amber-400" />
            ) : (
              <Moon className="w-3.5 h-3.5 text-indigo-400" />
            )}
            <span>{theme === 'dark' ? t.theme_light : t.theme_dark}</span>
          </span>
          <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
            {theme === 'dark' ? 'DARK' : 'LIGHT'}
          </span>
        </button>

        {/* Language toggle */}
        <button
          onClick={() => setLanguage(language === 'en' ? 'es' : 'en')}
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-300 hover:bg-slate-900 transition-colors"
          title="Toggle Language"
        >
          <span className="flex items-center gap-2">
            <Globe className="w-3.5 h-3.5 text-indigo-400" />
            <span>{language === 'en' ? 'Language: English' : 'Idioma: Español'}</span>
          </span>
          <span className="uppercase text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
            {language}
          </span>
        </button>

        {/* Clear data */}
        {hasData && (
          <button
            onClick={clearData}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>{t.common_clear}</span>
          </button>
        )}
      </div>
    </aside>
  );
}
