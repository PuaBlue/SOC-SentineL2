'use client';

import React, { createContext, useContext, useReducer, useCallback, useEffect, useState, ReactNode } from 'react';
import {
  LogEntry,
  SecurityFinding,
  DashboardStats,
  Language,
  Theme,
  AppState,
  IPReputation,
  ThreatIntelConfig,
} from '@/types';
import { analyzeSecurityLogs, computeStats } from '@/lib/securityEngine';
import { enrichIPs, extractIP, isValidIP } from '@/lib/threatIntel';

interface AppContextType {
  state: AppState;
  language: Language;
  setLanguage: (lang: Language) => void;
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  importLogs: (logs: LogEntry[], fileName: string) => void;
  runAnalysis: () => Promise<void>;
  enrichThreatIntel: (specificIps?: string[], forceRefresh?: boolean) => Promise<void>;
  updateThreatConfig: (config: Partial<ThreatIntelConfig>) => void;
  clearThreatSessionKeys: () => Promise<void>;
  setView: (view: AppState['currentView']) => void;
  clearData: () => void;
}

type Action =
  | { type: 'IMPORT_LOGS'; logs: LogEntry[]; fileName: string }
  | { type: 'SET_ANALYZING'; isAnalyzing: boolean; progress?: number }
  | { type: 'SET_FINDINGS'; findings: SecurityFinding[]; stats: DashboardStats }
  | { type: 'SET_VIEW'; view: AppState['currentView'] }
  | { type: 'SET_ENRICHING'; isEnriching: boolean }
  | { type: 'SET_REPUTATIONS'; reputations: Record<string, IPReputation> }
  | { type: 'SET_THREAT_CONFIG'; config: ThreatIntelConfig }
  | { type: 'CLEAR_DATA' };

const initialThreatConfig: ThreatIntelConfig = {
  autoEnrich: true,
  abuseConfigured: false,
  vtConfigured: false,
  abuseSource: 'none',
  vtSource: 'none',
};

const initialState: AppState = {
  logs: [],
  findings: [],
  stats: null,
  isAnalyzing: false,
  analysisProgress: 0,
  fileName: '',
  uploadDate: '',
  currentView: 'upload',
  threatIntel: {
    reputations: {},
    isEnriching: false,
    config: initialThreatConfig,
  },
};

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'IMPORT_LOGS':
      return {
        ...state,
        logs: action.logs,
        fileName: action.fileName,
        uploadDate: new Date().toISOString(),
        findings: [],
        stats: null,
      };
    case 'SET_ANALYZING':
      return {
        ...state,
        isAnalyzing: action.isAnalyzing,
        analysisProgress: action.progress ?? state.analysisProgress,
      };
    case 'SET_FINDINGS':
      return {
        ...state,
        findings: action.findings,
        stats: action.stats,
        isAnalyzing: false,
        analysisProgress: 100,
      };
    case 'SET_VIEW':
      return { ...state, currentView: action.view };
    case 'SET_ENRICHING':
      return {
        ...state,
        threatIntel: {
          ...state.threatIntel,
          isEnriching: action.isEnriching,
        },
      };
    case 'SET_REPUTATIONS': {
      const mergedReps = {
        ...state.threatIntel.reputations,
        ...action.reputations,
      };

      // Annotate findings with threat intelligence corroboration
      const enrichedFindings = state.findings.map((finding) => {
        const findingReps: Record<string, IPReputation> = {};
        let elevatedConfidence = finding.confidence;
        const newIndicators = [...finding.indicators];

        finding.affectedAssets.forEach((asset) => {
          const clean = extractIP(asset);
          if (!clean) return; // Non-IP assets (users, hostnames) do not have external threat reputation

          const rep = mergedReps[clean] || mergedReps[asset];
          if (rep) {
            findingReps[asset] = {
              ...rep,
              ip: clean, // Keep clean IP representation
            };

            // Elevate confidence if verified malicious by VirusTotal or AbuseIPDB
            if (rep.verdict === 'Malicious' && !rep.isPrivate) {
              elevatedConfidence = Math.min(99, Math.max(elevatedConfidence, 92));
              const tiIndicator = `Threat Intel: ${clean} flagged as ${rep.verdict} (${rep.abuseConfidenceScore ?? 0}% Abuse Score, ${rep.vtMalicious ?? 0} VT Detections)`;
              if (!newIndicators.includes(tiIndicator)) {
                newIndicators.push(tiIndicator);
              }
            }
          }
        });

        return {
          ...finding,
          confidence: elevatedConfidence,
          indicators: newIndicators,
          threatIntel: Object.keys(findingReps).length > 0 ? findingReps : finding.threatIntel,
        };
      });

      return {
        ...state,
        findings: enrichedFindings,
        threatIntel: {
          ...state.threatIntel,
          reputations: mergedReps,
          isEnriching: false,
        },
      };
    }
    case 'SET_THREAT_CONFIG':
      return {
        ...state,
        threatIntel: {
          ...state.threatIntel,
          config: action.config,
        },
      };
    case 'CLEAR_DATA':
      return {
        ...initialState,
        threatIntel: {
          ...initialState.threatIntel,
          config: state.threatIntel.config, // preserve configured status
        },
      };
    default:
      return state;
  }
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [language, setLanguage] = useState<Language>('en');
  const [theme, setThemeState] = useState<Theme>('light');

  // Load theme and query secure server key availability
  useEffect(() => {
    try {
      const savedTheme = localStorage.getItem('soc_theme') as Theme | null;
      if (savedTheme === 'dark' || savedTheme === 'light') {
        setThemeState(savedTheme);
        if (savedTheme === 'dark') {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
      } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        setThemeState('dark');
        document.documentElement.classList.add('dark');
      }

      // SECURITY: Explicitly remove any legacy plaintext API keys from localStorage
      localStorage.removeItem('soc_threat_config');

      // Check server for environment variables or existing secure HttpOnly session cookies
      fetch('/api/threat-intel/keys')
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data) {
            dispatch({
              type: 'SET_THREAT_CONFIG',
              config: {
                autoEnrich: true,
                abuseConfigured: data.abuseConfigured,
                vtConfigured: data.vtConfigured,
                abuseSource: data.abuseSource,
                vtSource: data.vtSource,
              },
            });
          }
        })
        .catch(() => {});
    } catch {
      // ignore
    }
  }, []);

  const setTheme = useCallback((newTheme: Theme) => {
    setThemeState(newTheme);
    try {
      localStorage.setItem('soc_theme', newTheme);
      if (newTheme === 'dark') {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
    } catch {
      // ignore
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  }, [theme, setTheme]);

  // Update threat configuration via secure server-side HttpOnly cookies
  const updateThreatConfig = useCallback(async (configUpdates: Partial<ThreatIntelConfig>) => {
    // If keys were entered in UI, send them directly to secure HttpOnly session endpoint
    if (configUpdates.abuseApiKey !== undefined || configUpdates.vtApiKey !== undefined) {
      try {
        const res = await fetch('/api/threat-intel/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            abuseApiKey: configUpdates.abuseApiKey,
            vtApiKey: configUpdates.vtApiKey,
          }),
        });
        if (res.ok) {
          const data = await res.json();
          configUpdates.abuseConfigured = data.abuseConfigured;
          configUpdates.vtConfigured = data.vtConfigured;
          configUpdates.abuseSource = data.abuseConfigured ? 'cookie' : 'none';
          configUpdates.vtSource = data.vtConfigured ? 'cookie' : 'none';
        }
      } catch (err) {
        console.error('Failed to sync session keys with server:', err);
      }
    }

    // Do NOT store raw API keys in client state or localStorage
    const safeConfig: ThreatIntelConfig = {
      ...state.threatIntel.config,
      autoEnrich: configUpdates.autoEnrich ?? state.threatIntel.config.autoEnrich,
      abuseConfigured: configUpdates.abuseConfigured ?? state.threatIntel.config.abuseConfigured,
      vtConfigured: configUpdates.vtConfigured ?? state.threatIntel.config.vtConfigured,
      abuseSource: configUpdates.abuseSource ?? state.threatIntel.config.abuseSource,
      vtSource: configUpdates.vtSource ?? state.threatIntel.config.vtSource,
    };

    dispatch({ type: 'SET_THREAT_CONFIG', config: safeConfig });
  }, [state.threatIntel.config]);

  const clearThreatSessionKeys = useCallback(async () => {
    try {
      await fetch('/api/threat-intel/keys', { method: 'DELETE' });
      // Re-fetch key status to see if server .env keys are still present
      const res = await fetch('/api/threat-intel/keys');
      if (res.ok) {
        const data = await res.json();
        dispatch({
          type: 'SET_THREAT_CONFIG',
          config: {
            autoEnrich: state.threatIntel.config.autoEnrich,
            abuseConfigured: data.abuseConfigured,
            vtConfigured: data.vtConfigured,
            abuseSource: data.abuseSource,
            vtSource: data.vtSource,
          },
        });
      }
    } catch (err) {
      console.error('Failed to clear threat session keys:', err);
    }
  }, [state.threatIntel.config.autoEnrich]);

  const enrichThreatIntel = useCallback(async (specificIps?: string[], forceRefresh = true) => {
    dispatch({ type: 'SET_ENRICHING', isEnriching: true });

    // Collect all candidate IPs: source IPs, destination IPs, and assets
    const targetIps = specificIps && specificIps.length > 0
      ? specificIps
      : Array.from(
          new Set(
            [
              ...state.logs.map((l) => l.source_ip),
              ...state.logs.map((l) => l.destination_ip),
              ...state.findings.flatMap((f) => f.affectedAssets),
            ]
              .map((item) => extractIP(item))
              .filter((ip): ip is string => isValidIP(ip))
          )
        );

    try {
      const reputations = await enrichIPs(targetIps, state.threatIntel.config, forceRefresh);
      dispatch({ type: 'SET_REPUTATIONS', reputations });
    } catch (err) {
      console.error('Threat intelligence enrichment error:', err);
      dispatch({ type: 'SET_ENRICHING', isEnriching: false });
    }
  }, [state.logs, state.findings, state.threatIntel.config]);

  const importLogs = useCallback((logs: LogEntry[], fileName: string) => {
    dispatch({ type: 'IMPORT_LOGS', logs, fileName });
  }, []);

  const runAnalysis = useCallback(async () => {
    dispatch({ type: 'SET_ANALYZING', isAnalyzing: true, progress: 0 });

    const progressSteps = [10, 25, 40, 55, 70, 85, 95];
    for (const p of progressSteps) {
      await new Promise((r) => setTimeout(r, 180 + Math.random() * 200));
      dispatch({ type: 'SET_ANALYZING', isAnalyzing: true, progress: p });
    }

    const findings = analyzeSecurityLogs(state.logs);
    const stats = computeStats(state.logs, findings);

    dispatch({ type: 'SET_FINDINGS', findings, stats });
    dispatch({ type: 'SET_VIEW', view: 'dashboard' });

    // If autoEnrich is enabled, kick off threat intelligence background enrichment
    if (state.threatIntel.config.autoEnrich) {
      setTimeout(() => {
        const candidateIps = Array.from(
          new Set(
            [
              ...state.logs.map((l) => l.source_ip),
              ...state.logs.map((l) => l.destination_ip),
              ...findings.flatMap((f) => f.affectedAssets),
            ]
              .map((item) => extractIP(item))
              .filter((ip): ip is string => isValidIP(ip))
          )
        );
        enrichIPs(candidateIps, state.threatIntel.config, false).then((reps) => {
          dispatch({ type: 'SET_REPUTATIONS', reputations: reps });
        });
      }, 400);
    }
  }, [state.logs, state.threatIntel.config]);

  const setView = useCallback((view: AppState['currentView']) => {
    dispatch({ type: 'SET_VIEW', view });
  }, []);

  const clearData = useCallback(() => {
    dispatch({ type: 'CLEAR_DATA' });
  }, []);

  return (
    <AppContext.Provider
      value={{
        state,
        language,
        setLanguage,
        theme,
        setTheme,
        toggleTheme,
        importLogs,
        runAnalysis,
        enrichThreatIntel,
        updateThreatConfig,
        clearThreatSessionKeys,
        setView,
        clearData,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp(): AppContextType {
  const context = useContext(AppContext);
  if (!context) throw new Error('useApp must be used within AppProvider');
  return context;
}
