'use client';

import { useState, useCallback, useRef } from 'react';
import { useApp } from '@/context/AppContext';
import { translations } from '@/i18n/translations';
import { parseExcelFile } from '@/lib/excelParser';
import { generateSampleSIEMLogs, downloadSampleExcelFile } from '@/lib/sampleData';
import { cn } from '@/lib/utils';
import {
  Upload,
  FileSpreadsheet,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Play,
  X,
  Table,
  Download,
  Sparkles,
  ShieldAlert,
  Database,
} from 'lucide-react';

export function UploadView() {
  const { state, language, importLogs, runAnalysis } = useApp();
  const t = translations[language];
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [previewFilter, setPreviewFilter] = useState('');

  const processFile = useCallback(
    async (file: File) => {
      if (!file.name.endsWith('.xlsx') && !file.name.endsWith('.xls')) {
        setError(t.upload_error);
        return;
      }

      setIsProcessing(true);
      setError(null);

      try {
        const buffer = await file.arrayBuffer();
        const logs = parseExcelFile(buffer);

        if (logs.length === 0) {
          setError(
            language === 'en'
              ? 'No valid log records found in the Excel file. Please ensure columns like Timestamp, Source_IP, or Action are present.'
              : 'No se encontraron registros válidos en el archivo Excel. Asegúrese de que contenga columnas como Timestamp, Source_IP o Action.'
          );
          setIsProcessing(false);
          return;
        }

        importLogs(logs, file.name);
      } catch (err) {
        console.error('Parse error:', err);
        setError(t.upload_error);
      } finally {
        setIsProcessing(false);
      }
    },
    [importLogs, language, t]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  const loadSampleDataset = () => {
    setIsProcessing(true);
    setError(null);
    setTimeout(() => {
      const sampleLogs = generateSampleSIEMLogs();
      importLogs(sampleLogs, 'SIEM_Corporate_Incident_Export.xlsx');
      setIsProcessing(false);
    }, 300);
  };

  const hasLogs = state.logs.length > 0;

  const filteredPreview = state.logs.filter((l) => {
    if (!previewFilter) return true;
    const term = previewFilter.toLowerCase();
    return (
      (l.user && l.user.toLowerCase().includes(term)) ||
      (l.source_ip && l.source_ip.toLowerCase().includes(term)) ||
      (l.destination_ip && l.destination_ip.toLowerCase().includes(term)) ||
      (l.action && l.action.toLowerCase().includes(term)) ||
      (l.message && l.message.toLowerCase().includes(term)) ||
      (l.severity && l.severity.toLowerCase().includes(term))
    );
  });

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200/60 dark:border-indigo-800 px-2.5 py-1 rounded-full">
            SOC Level 2 Platform
          </span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          {t.upload_title}
        </h1>
        <p className="text-slate-500 dark:text-slate-400 mt-1 max-w-2xl text-sm leading-relaxed">
          {t.upload_subtitle}
        </p>
      </div>

      {/* Main Drag & Drop Card */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={cn(
          'relative border-2 border-dashed rounded-2xl p-10 text-center transition-all duration-200',
          isDragging
            ? 'border-indigo-500 bg-indigo-50/70 dark:bg-indigo-950/40 scale-[1.005]'
            : hasLogs
              ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50/30 dark:bg-emerald-950/20'
              : 'border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 hover:border-indigo-400 dark:hover:border-indigo-600 hover:bg-slate-50/50 dark:hover:bg-slate-900 shadow-sm'
        )}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".xlsx,.xls"
          onChange={handleFileChange}
          className="hidden"
        />

        {isProcessing ? (
          <div className="py-8 space-y-4">
            <Loader2 className="w-12 h-12 mx-auto text-indigo-600 dark:text-indigo-400 animate-spin" />
            <p className="text-indigo-700 dark:text-indigo-300 font-medium">{t.upload_processing}</p>
          </div>
        ) : hasLogs ? (
          <div className="py-4 space-y-4">
            <div className="w-14 h-14 mx-auto rounded-2xl bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shadow-inner">
              <CheckCircle2 className="w-8 h-8" />
            </div>
            <div>
              <p className="text-emerald-800 dark:text-emerald-300 font-bold text-lg">{t.upload_success}</p>
              <div className="inline-flex items-center gap-2 mt-2 px-3 py-1.5 rounded-lg bg-emerald-100/70 dark:bg-emerald-900/40 text-emerald-800 dark:text-emerald-200 text-sm font-medium">
                <FileSpreadsheet className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                <span>{state.fileName}</span>
                <span className="text-emerald-600/70 dark:text-emerald-400/70">•</span>
                <span>{state.logs.length.toLocaleString()} {t.upload_records}</span>
              </div>
            </div>
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-2 text-xs font-semibold text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 transition shadow-sm"
              >
                {language === 'en' ? 'Replace Excel File' : 'Reemplazar Archivo Excel'}
              </button>
            </div>
          </div>
        ) : (
          <div className="py-6 space-y-4">
            <div className="w-16 h-16 mx-auto bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 rounded-2xl flex items-center justify-center border border-indigo-100 dark:border-indigo-900">
              <Upload className="w-8 h-8" />
            </div>
            <div>
              <p className="text-slate-800 dark:text-slate-200 font-semibold text-lg">{t.upload_drag}</p>
              <p className="text-slate-400 dark:text-slate-500 text-xs mt-1">{t.upload_supported}</p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-5 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition shadow-sm shadow-indigo-600/20"
              >
                {t.upload_browse}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Helper Tools: Sample Data & Download Sample */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm flex items-start gap-3">
          <div className="p-2 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 shrink-0">
            <Sparkles className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              {language === 'en' ? 'Instant Test Scenario' : 'Escenario de Prueba Inmediato'}
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {language === 'en'
                ? 'Load pre-configured SIEM logs containing Brute Force, Escalation, Lateral Movement, and Suspicious Logins.'
                : 'Cargar logs SIEM preconfigurados con Fuerza Bruta, Escalamiento, Movimiento Lateral e Inicios Sospechosos.'}
            </p>
            <button
              onClick={loadSampleDataset}
              className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 dark:bg-slate-800 text-white hover:bg-slate-800 dark:hover:bg-slate-700 transition shadow-sm"
            >
              <Database className="w-3.5 h-3.5" />
              {language === 'en' ? 'Load SOC Sample Dataset' : 'Cargar Dataset de Prueba SOC'}
            </button>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm flex items-start gap-3">
          <div className="p-2 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 shrink-0">
            <Download className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              {language === 'en' ? 'Download Sample .XLSX' : 'Descargar .XLSX de Ejemplo'}
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {language === 'en'
                ? 'Download a valid SIEM export Excel spreadsheet formatted for testing with SheetJS.'
                : 'Descargue una planilla Excel exportada de SIEM válida formateada para pruebas.'}
            </p>
            <button
              onClick={downloadSampleExcelFile}
              className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition shadow-sm"
            >
              <Download className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              {language === 'en' ? 'Export Template .xlsx' : 'Exportar Plantilla .xlsx'}
            </button>
          </div>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/60 rounded-xl text-rose-700 dark:text-rose-300 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <p className="flex-1">{error}</p>
          <button onClick={() => setError(null)} className="text-rose-500 hover:text-rose-700">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Run Analysis Action Section */}
      {hasLogs && (
        <div className="glass-card p-6 border-indigo-200/80 dark:border-indigo-900/60 bg-gradient-to-r from-indigo-500/5 via-white dark:via-slate-900 to-purple-500/5">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-indigo-600 text-white flex items-center justify-center shrink-0">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-slate-900 dark:text-white">
                  {language === 'en' ? 'AI Analytical Engine Ready' : 'Motor Analítico de IA Listo'}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {language === 'en'
                    ? 'Correlates timestamps, IP frequencies, privilege assignments, and command executions.'
                    : 'Correlaciona marcas de tiempo, frecuencia de IPs, asignación de privilegios y ejecución de comandos.'}
                </p>
              </div>
            </div>

            <button
              onClick={runAnalysis}
              disabled={state.isAnalyzing}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-6 py-3 bg-indigo-600 text-white rounded-xl font-semibold text-sm hover:bg-indigo-700 transition shadow-lg shadow-indigo-600/25 disabled:opacity-50"
            >
              {state.isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>{t.report_generating}</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>{t.upload_analyze}</span>
                </>
              )}
            </button>
          </div>

          {/* Progress bar */}
          {state.isAnalyzing && (
            <div className="mt-6 pt-6 border-t border-slate-200/60 dark:border-slate-800 space-y-2">
              <div className="flex justify-between text-xs font-semibold text-slate-700 dark:text-slate-300">
                <span>
                  {state.analysisProgress < 30
                    ? (language === 'en' ? 'Normalizing SIEM timestamps & fields...' : 'Normalizando tiempos y campos SIEM...')
                    : state.analysisProgress < 60
                      ? (language === 'en' ? 'Detecting brute force & anomalous commands...' : 'Detectando fuerza bruta y comandos anómalos...')
                      : state.analysisProgress < 85
                        ? (language === 'en' ? 'Correlating lateral movement & privileges...' : 'Correlacionando movimiento lateral y privilegios...')
                        : (language === 'en' ? 'Synthesizing evidence & severity scoring...' : 'Sintetizando evidencias y puntuación de severidad...')}
                </span>
                <span className="font-mono text-indigo-600 dark:text-indigo-400">{state.analysisProgress}%</span>
              </div>
              <div className="w-full bg-slate-200 dark:bg-slate-800 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-indigo-600 h-2 rounded-full progress-bar"
                  style={{ width: `${state.analysisProgress}%` }}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Log Data Preview Table */}
      {hasLogs && (
        <div className="glass-card overflow-hidden">
          <div className="p-4 border-b border-slate-200/80 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Table className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                {language === 'en' ? 'Imported SIEM Logs' : 'Logs SIEM Importados'}
              </h3>
              <span className="text-xs text-slate-400 dark:text-slate-500">
                ({filteredPreview.length} / {state.logs.length})
              </span>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder={language === 'en' ? 'Filter by user, IP, action...' : 'Filtrar por usuario, IP, acción...'}
                value={previewFilter}
                onChange={(e) => setPreviewFilter(e.target.value)}
                className="px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 w-64 text-slate-800 dark:text-slate-200"
              />
              {previewFilter && (
                <button
                  onClick={() => setPreviewFilter('')}
                  className="text-xs text-slate-400 hover:text-slate-600"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-50 dark:bg-slate-900 text-slate-600 dark:text-slate-400 font-semibold uppercase tracking-wider sticky top-0 border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Source IP</th>
                  <th className="px-4 py-3">Destination IP</th>
                  <th className="px-4 py-3">User</th>
                  <th className="px-4 py-3">Action / Event</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300 font-mono">
                {filteredPreview.slice(0, 50).map((log, idx) => (
                  <tr key={log.id || idx} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/50 transition-colors">
                    <td className="px-4 py-2.5 whitespace-nowrap text-slate-500 dark:text-slate-400 text-[11px]">
                      {log.timestamp ? new Date(log.timestamp).toLocaleString() : '-'}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-indigo-600 dark:text-indigo-400 font-medium">
                      {log.source_ip || '-'}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-slate-600 dark:text-slate-400">
                      {log.destination_ip || '-'}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap font-medium text-slate-900 dark:text-white">
                      {log.user || '-'}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-slate-600 dark:text-slate-400">
                      {log.action || log.event_type || '-'}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                          log.severity?.toLowerCase() === 'critical'
                            ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400'
                            : log.severity?.toLowerCase() === 'high'
                              ? 'bg-orange-100 dark:bg-orange-950/60 text-orange-700 dark:text-orange-400'
                              : log.severity?.toLowerCase() === 'medium'
                                ? 'bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400'
                                : 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400'
                        )}
                      >
                        {log.severity || 'Info'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 max-w-xs truncate text-slate-500 dark:text-slate-400 font-sans" title={log.message}>
                      {log.message || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filteredPreview.length > 50 && (
            <div className="p-2.5 text-center bg-slate-50/60 dark:bg-slate-900/60 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
              {language === 'en'
                ? `Showing first 50 of ${filteredPreview.length} entries`
                : `Mostrando las primeras 50 de ${filteredPreview.length} entradas`}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
