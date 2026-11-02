import type { Metadata } from 'next';
import './globals.css';
import { AppProvider } from '@/context/AppContext';

export const metadata: Metadata = {
  title: 'SOC Sentinel — Security Log Analyzer & Reporting',
  description: 'AI-powered security log analysis and automated report generation for SOC Level 2 analysts',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-50 text-slate-900 font-sans antialiased">
        <AppProvider>{children}</AppProvider>
      </body>
    </html>
  );
}
