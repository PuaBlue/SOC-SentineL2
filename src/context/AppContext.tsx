'use client';

import React, { createContext, useContext, useReducer, useCallback, useEffect, useState, ReactNode } from 'react';
import { LogEntry, SecurityFinding, DashboardStats, Language, Theme, AppState } from '@/types';
import { analyzeSecurityLogs, computeStats } from '@/lib/securityEngine';

interface AppContextType {
  state: AppState;
  language: Language;
  setLanguage: (lang: Language) => void;
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  importLogs: (logs: LogEntry[], fileName: string) => void;
  runAnalysis: () => Promise<void>;
  setView: (view: AppState['currentView']) => void;
  clearData: () => void;
}

type Action =
  | { type: 'IMPORT_LOGS'; logs: LogEntry[]; fileName: string }
  | { type: 'SET_ANALYZING'; isAnalyzing: boolean; progress?: number }
  | { type: 'SET_FINDINGS'; findings: SecurityFinding[]; stats: DashboardStats }
  | { type: 'SET_VIEW'; view: AppState['currentView'] }
  | { type: 'CLEAR_DATA' };

const initialState: AppState = {
  logs: [],
  findings: [],
  stats: null,
  isAnalyzing: false,
  analysisProgress: 0,
  fileName: '',
  uploadDate: '',
  currentView: 'upload',
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
    case 'CLEAR_DATA':
      return initialState;
    default:
      return state;
  }
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [language, setLanguage] = useState<Language>('en');
  const [theme, setThemeState] = useState<Theme>('light');

  // Initialize theme from localStorage or system preference
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
    } catch {
      // ignore SSR or storage exceptions
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

  const importLogs = useCallback((logs: LogEntry[], fileName: string) => {
    dispatch({ type: 'IMPORT_LOGS', logs, fileName });
  }, []);

  const runAnalysis = useCallback(async () => {
    dispatch({ type: 'SET_ANALYZING', isAnalyzing: true, progress: 0 });

    const progressSteps = [10, 25, 40, 55, 70, 85, 95];
    for (const p of progressSteps) {
      await new Promise((r) => setTimeout(r, 200 + Math.random() * 250));
      dispatch({ type: 'SET_ANALYZING', isAnalyzing: true, progress: p });
    }

    const findings = analyzeSecurityLogs(state.logs);
    const stats = computeStats(state.logs, findings);

    dispatch({ type: 'SET_FINDINGS', findings, stats });
    dispatch({ type: 'SET_VIEW', view: 'dashboard' });
  }, [state.logs]);

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
