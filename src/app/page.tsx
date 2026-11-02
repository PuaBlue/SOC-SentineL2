'use client';

import { useApp } from '@/context/AppContext';
import { Sidebar } from '@/components/layout/Sidebar';
import { UploadView } from '@/components/upload/UploadView';
import { DashboardView } from '@/components/layout/DashboardView';
import { AnalysisView } from '@/components/analysis/AnalysisView';
import { ReportsView } from '@/components/reports/ReportsView';

export default function Home() {
  const { state } = useApp();

  const renderView = () => {
    switch (state.currentView) {
      case 'upload':
        return <UploadView />;
      case 'dashboard':
        return <DashboardView />;
      case 'analysis':
        return <AnalysisView />;
      case 'reports':
        return <ReportsView />;
      default:
        return <UploadView />;
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-50 dark:bg-slate-950 transition-colors duration-200">
      <Sidebar />
      <main className="flex-1 ml-64 p-8 overflow-y-auto min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 transition-colors">
        {renderView()}
      </main>
    </div>
  );
}
