'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { cn } from '@/lib/utils';
import { extractIP, isValidIP } from '@/lib/threatIntel';
import {
  Globe,
  Key,
  Save,
  RefreshCw,
  X,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Server,
  Lock,
  Layers,
  Search,
  ShieldCheck,
  ShieldAlert,
  Trash2,
} from 'lucide-react';

export function ThreatIntelModal({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const { state, language, updateThreatConfig, clearThreatSessionKeys, enrichThreatIntel } = useApp();
  const t = translations[language];

  const config = state.threatIntel.config;
  const reputations = state.threatIntel.reputations;
  const isEnriching = state.threatIntel.isEnriching;

  const [abuseKey, setAbuseKey] = useState('');
  const [vtKey, setVtKey] = useState('');
  const [autoEnrich, setAutoEnrich] = useState(config.autoEnrich ?? true);
  const [isSaved, setIsSaved] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');

  if (!isOpen) return null;

  const handleSaveKeys = async () => {
    await updateThreatConfig({
      abuseApiKey: abuseKey.trim() || undefined,
      vtApiKey: vtKey.trim() || undefined,
      autoEnrich,
    });
    // Immediately clear sensitive plaintext keys from component state
    setAbuseKey('');
    setVtKey('');
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2500);
  };

  const handleClearSessionKeys = async () => {
    await clearThreatSessionKeys();
    setAbuseKey('');
    setVtKey('');
  };

  const handleEnrichAll = async () => {
    await enrichThreatIntel(undefined, true);
  };

  const allReputationList = Object.values(reputations)
    .filter((rep, index, self) => {
      const clean = extractIP(rep.ip);
      if (!clean || !isValidIP(clean)) return false;
      return self.findIndex((r) => (extractIP(r.ip) || r.ip) === clean) === index;
    })
    .map((rep) => ({
      ...rep,
      ip: extractIP(rep.ip) || rep.ip,
    }))
    .filter((rep) => {
      if (!searchFilter) return true;
      const term = searchFilter.toLowerCase();
      return (
        rep.ip.toLowerCase().includes(term) ||
        (rep.isp && rep.isp.toLowerCase().includes(term)) ||
        (rep.country && rep.country.toLowerCase().includes(term)) ||
        rep.verdict.toLowerCase().includes(term)
      );
    });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-in">
      <div className="bg-white dark:bg-slate-900 rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between bg-slate-50 dark:bg-slate-950">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600 text-white flex items-center justify-center shadow-md shadow-indigo-600/30">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                {t.ti_title}
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-indigo-100 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800">
                  VirusTotal + AbuseIPDB
                </span>
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {t.ti_subtitle}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-200/50 dark:hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* Security Notice: No localStorage Exposure */}
          <div className="p-3.5 rounded-xl bg-indigo-50/70 dark:bg-indigo-950/40 border border-indigo-200/80 dark:border-indigo-900/60 flex items-start gap-3">
            <Lock className="w-4 h-4 text-indigo-600 dark:text-indigo-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-bold text-slate-900 dark:text-slate-200">
                {language === 'en'
                  ? 'Enterprise Security Architecture (Zero localStorage Exposure)'
                  : 'Arquitectura Segura SOC (Protección contra XSS - Cero localStorage)'}
              </p>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                {language === 'en'
                  ? 'API keys are strictly NEVER stored in browser localStorage. Keys are loaded directly from server environment variables (.env.local) or held in secure HttpOnly server session cookies inaccessible to client-side scripts.'
                  : 'Las claves de API NUNCA se guardan en localStorage del navegador. Se cargan directamente desde variables de entorno del servidor (.env.local) o en cookies de sesión seguras HttpOnly inaccesibles para cualquier script de cliente.'}
              </p>
            </div>
          </div>

          {/* Current Key Status Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* AbuseIPDB Status */}
            <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                  <span>AbuseIPDB (v2)</span>
                </span>
                <span
                  className={cn(
                    'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                    config.abuseConfigured
                      ? 'bg-emerald-100 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800'
                      : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                  )}
                >
                  {config.abuseConfigured ? (language === 'en' ? 'Active' : 'Activo') : (language === 'en' ? 'Simulated' : 'Simulado')}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {config.abuseConfigured
                  ? config.abuseSource === 'env'
                    ? (language === 'en' ? 'Connected via Server .env.local' : 'Conectado vía .env.local del Servidor')
                    : (language === 'en' ? 'Active via HttpOnly Session Cookie' : 'Activo vía Cookie de Sesión HttpOnly')
                  : (language === 'en' ? 'High-fidelity SOC telemetry emulation' : 'Emulación de telemetría SOC de alta fidelidad')}
              </p>
            </div>

            {/* VirusTotal Status */}
            <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                  <span>VirusTotal (v3)</span>
                </span>
                <span
                  className={cn(
                    'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                    config.vtConfigured
                      ? 'bg-emerald-100 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800'
                      : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                  )}
                >
                  {config.vtConfigured ? (language === 'en' ? 'Active' : 'Activo') : (language === 'en' ? 'Simulated' : 'Simulado')}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {config.vtConfigured
                  ? config.vtSource === 'env'
                    ? (language === 'en' ? 'Connected via Server .env.local' : 'Conectado vía .env.local del Servidor')
                    : (language === 'en' ? 'Active via HttpOnly Session Cookie' : 'Activo vía Cookie de Sesión HttpOnly')
                  : (language === 'en' ? 'High-fidelity SOC telemetry emulation' : 'Emulación de telemetría SOC de alta fidelidad')}
              </p>
            </div>
          </div>

          {/* Session Key Configuration Card */}
          <div className="glass-card p-5 space-y-4 border border-indigo-100 dark:border-indigo-900/60 bg-gradient-to-r from-indigo-50/40 via-white dark:via-slate-900 to-purple-50/30">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2.5">
              <span className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Key className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                <span>{language === 'en' ? 'Configure Session Keys (HttpOnly Cookie)' : 'Configurar Claves de Sesión (Cookie HttpOnly)'}</span>
              </span>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                XSS-Protected
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* AbuseIPDB Key */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="font-semibold text-slate-700 dark:text-slate-300">
                    {t.ti_abuse_key}
                  </label>
                  <a
                    href="https://www.abuseipdb.com/pricing"
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] text-indigo-600 dark:text-indigo-400 hover:underline inline-flex items-center gap-1"
                  >
                    <span>Get Free Key</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
                <input
                  type="password"
                  placeholder={config.abuseConfigured ? "•••••••••••••••• (Configured)" : "Paste AbuseIPDB key..."}
                  value={abuseKey}
                  onChange={(e) => setAbuseKey(e.target.value)}
                  className="w-full text-xs font-mono px-3 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 text-slate-900 dark:text-slate-100"
                />
              </div>

              {/* VirusTotal Key */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="font-semibold text-slate-700 dark:text-slate-300">
                    {t.ti_vt_key}
                  </label>
                  <a
                    href="https://www.virustotal.com/gui/my-apikey"
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] text-indigo-600 dark:text-indigo-400 hover:underline inline-flex items-center gap-1"
                  >
                    <span>Get Free Key</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
                <input
                  type="password"
                  placeholder={config.vtConfigured ? "•••••••••••••••• (Configured)" : "Paste VirusTotal v3 key..."}
                  value={vtKey}
                  onChange={(e) => setVtKey(e.target.value)}
                  className="w-full text-xs font-mono px-3 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 text-slate-900 dark:text-slate-100"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <label className="flex items-center gap-2 cursor-pointer text-slate-700 dark:text-slate-300">
                <input
                  type="checkbox"
                  checked={autoEnrich}
                  onChange={(e) => setAutoEnrich(e.target.checked)}
                  className="rounded text-indigo-600 dark:bg-slate-900 dark:border-slate-700 focus:ring-indigo-500"
                />
                <span>
                  {language === 'en'
                    ? 'Automatically enrich Source IPs during security analysis'
                    : 'Enriquecer automáticamente IPs origen durante el análisis de seguridad'}
                </span>
              </label>

              <div className="flex items-center gap-2">
                {(config.abuseSource === 'cookie' || config.vtSource === 'cookie') && (
                  <button
                    onClick={handleClearSessionKeys}
                    type="button"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-900 rounded-lg font-semibold transition hover:bg-rose-100"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>{language === 'en' ? 'Purge Session Keys' : 'Purgar Sesión'}</span>
                  </button>
                )}

                <button
                  onClick={handleSaveKeys}
                  disabled={!abuseKey.trim() && !vtKey.trim()}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-slate-900 dark:bg-slate-800 hover:bg-slate-800 text-white rounded-lg font-semibold transition disabled:opacity-40"
                >
                  {isSaved ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Save className="w-3.5 h-3.5" />}
                  <span>{isSaved ? (language === 'en' ? 'Saved to HttpOnly Cookie!' : '¡Guardado en Cookie HttpOnly!') : (language === 'en' ? 'Save to Secure Session' : 'Guardar en Sesión Segura')}</span>
                </button>

                <button
                  onClick={handleEnrichAll}
                  disabled={isEnriching}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-semibold transition shadow-sm disabled:opacity-50"
                >
                  <RefreshCw className={cn('w-3.5 h-3.5', isEnriching && 'animate-spin')} />
                  <span>{isEnriching ? t.ti_enriching : t.ti_enrich_btn}</span>
                </button>
              </div>
            </div>
          </div>

          {/* IP Reputation Results Table */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-slate-900 dark:text-white">
                  {language === 'en' ? 'Observed IP Reputations' : 'Reputación de IPs Observadas'}
                </h3>
                <span className="text-slate-400 dark:text-slate-500 font-mono text-[11px]">
                  ({allReputationList.length} IPs)
                </span>
              </div>

              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
                <input
                  type="text"
                  placeholder={language === 'en' ? 'Filter by IP, country, verdict...' : 'Filtrar por IP, país, veredicto...'}
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="pl-8 pr-3 py-1 text-xs bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 text-slate-800 dark:text-slate-200 w-56"
                />
              </div>
            </div>

            {allReputationList.length === 0 ? (
              <div className="p-8 text-center bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-dashed border-slate-300 dark:border-slate-800 space-y-2">
                <Server className="w-8 h-8 mx-auto text-slate-400" />
                <p className="font-semibold text-slate-700 dark:text-slate-300">
                  {language === 'en' ? 'No IP reputation data enriched yet' : 'Aún no hay datos de reputación de IPs'}
                </p>
                <p className="text-[11px] text-slate-400 dark:text-slate-500">
                  {language === 'en'
                    ? 'Click "Enrich Threat Intelligence" to query AbuseIPDB and VirusTotal for all observed Source IPs.'
                    : 'Haga clic en "Enriquecer Inteligencia IP" para consultar AbuseIPDB y VirusTotal para todas las IPs observadas.'}
                </p>
                <button
                  onClick={handleEnrichAll}
                  disabled={isEnriching}
                  className="mt-2 inline-flex items-center gap-1.5 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-semibold transition"
                >
                  <RefreshCw className={cn('w-3.5 h-3.5', isEnriching && 'animate-spin')} />
                  <span>{isEnriching ? t.ti_enriching : t.ti_enrich_btn}</span>
                </button>
              </div>
            ) : (
              <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                <div className="overflow-x-auto max-h-80">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-200 dark:border-slate-800 sticky top-0">
                      <tr>
                        <th className="px-3.5 py-2.5">{language === 'en' ? 'IP Address' : 'Dirección IP'}</th>
                        <th className="px-3.5 py-2.5">{language === 'en' ? 'Verdict' : 'Veredicto'}</th>
                        <th className="px-3.5 py-2.5">{language === 'en' ? 'AbuseIPDB Score' : 'Puntaje AbuseIPDB'}</th>
                        <th className="px-3.5 py-2.5">VirusTotal</th>
                        <th className="px-3.5 py-2.5">{language === 'en' ? 'ISP / Country' : 'Proveedor / País'}</th>
                        <th className="px-3.5 py-2.5">{language === 'en' ? 'Source' : 'Origen'}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                      {allReputationList.map((rep) => (
                        <tr key={rep.ip} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/50 transition">
                          <td className="px-3.5 py-2 font-bold text-slate-900 dark:text-white">
                            {rep.ip}
                          </td>
                          <td className="px-3.5 py-2 font-sans">
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                                rep.verdict === 'Malicious'
                                  ? 'bg-rose-100 dark:bg-rose-950/70 text-rose-700 dark:text-rose-400'
                                  : rep.verdict === 'Suspicious'
                                    ? 'bg-orange-100 dark:bg-orange-950/70 text-orange-700 dark:text-orange-400'
                                    : rep.verdict === 'Private'
                                      ? 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                                      : 'bg-emerald-100 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-400'
                              )}
                            >
                              {rep.verdict === 'Malicious'
                                ? t.ti_verdict_malicious
                                : rep.verdict === 'Suspicious'
                                  ? t.ti_verdict_suspicious
                                  : rep.verdict === 'Private'
                                    ? t.ti_verdict_private
                                    : t.ti_verdict_clean}
                            </span>
                          </td>
                          <td className="px-3.5 py-2">
                            {rep.isPrivate ? (
                              <span className="text-slate-400 font-sans">{language === 'en' ? 'N/A (Private / Reserved)' : 'N/A (Privada / Reservada)'}</span>
                            ) : rep.abuseConfidenceScore !== undefined ? (
                              <span
                                className={cn(
                                  'font-bold',
                                  rep.abuseConfidenceScore >= 80
                                    ? 'text-rose-600 dark:text-rose-400'
                                    : rep.abuseConfidenceScore >= 20
                                      ? 'text-orange-600 dark:text-orange-400'
                                      : 'text-emerald-600 dark:text-emerald-400'
                                )}
                              >
                                {rep.abuseConfidenceScore}% ({rep.totalReports || 0} {language === 'en' ? 'reports' : 'reportes'})
                              </span>
                            ) : (
                              <span className="text-slate-400 font-sans">-</span>
                            )}
                          </td>
                          <td className="px-3.5 py-2">
                            {rep.isPrivate ? (
                              <span className="text-slate-400 font-sans">N/A</span>
                            ) : rep.vtMalicious !== undefined ? (
                              <span
                                className={cn(
                                  'font-bold',
                                  rep.vtMalicious > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'
                                )}
                              >
                                {rep.vtMalicious} / {rep.vtTotalVendors || 90} {language === 'en' ? 'engines' : 'motores'}
                              </span>
                            ) : (
                              <span className="text-slate-400 font-sans">-</span>
                            )}
                          </td>
                          <td className="px-3.5 py-2 font-sans truncate max-w-[200px]" title={`${rep.isp || ''} - ${rep.country || ''}`}>
                            {rep.isp || rep.country || '-'}
                          </td>
                          <td className="px-3.5 py-2 font-sans text-slate-400 text-[10px]">
                            {rep.source}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-950">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            {language === 'en'
              ? 'External threat intelligence feeds corroborate incident evidence without altering raw log records.'
              : 'Las fuentes externas de inteligencia corroboran la evidencia sin alterar los registros inmutables.'}
          </p>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-900 dark:bg-slate-800 text-white rounded-xl text-xs font-semibold hover:bg-slate-800 transition"
          >
            {language === 'en' ? 'Close' : 'Cerrar'}
          </button>
        </div>
      </div>
    </div>
  );
}
