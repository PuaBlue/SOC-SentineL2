import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

export function formatTimestamp(ts: string): string {
  try {
    const date = new Date(ts);
    if (isNaN(date.getTime())) return ts;
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return ts;
  }
}

export function severityColor(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical') return 'text-red-500 bg-red-500/10 border-red-500/30';
  if (s === 'high') return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
  if (s === 'medium') return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
  if (s === 'low') return 'text-green-500 bg-green-500/10 border-green-500/30';
  return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
}

export function severityDotColor(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical') return 'bg-red-500';
  if (s === 'high') return 'bg-orange-500';
  if (s === 'medium') return 'bg-yellow-500';
  if (s === 'low') return 'bg-green-500';
  return 'bg-slate-500';
}

export function severityBgClass(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical') return 'bg-red-500';
  if (s === 'high') return 'bg-orange-500';
  if (s === 'medium') return 'bg-yellow-500';
  if (s === 'low') return 'bg-green-500';
  return 'bg-slate-500';
}
