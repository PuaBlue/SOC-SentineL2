// Security Log Entry - represents a single log line from SIEM export
export interface LogEntry {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  user: string;
  action: string;
  event_type: string;
  severity: string;
  message: string;
  protocol?: string;
  port?: number;
  status?: string;
  device?: string;
  raw_log?: string;
  [key: string]: unknown;
}

// Severity levels for security findings
export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

// Threat Intelligence IP Reputation (AbuseIPDB & VirusTotal)
export interface IPReputation {
  ip: string;
  isPrivate: boolean;
  country?: string;
  countryCode?: string;
  isp?: string;
  domain?: string;
  usageType?: string;
  // AbuseIPDB
  abuseConfidenceScore?: number; // 0 - 100
  totalReports?: number;
  lastReportedAt?: string;
  // VirusTotal
  vtMalicious?: number;
  vtSuspicious?: number;
  vtHarmless?: number;
  vtUndetected?: number;
  vtTotalVendors?: number;
  vtReputationScore?: number;
  // Verdict
  verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Private' | 'Unknown';
  source: 'AbuseIPDB' | 'VirusTotal' | 'Both' | 'Internal' | 'Simulated';
  checkedAt: string;
}

export interface ThreatIntelConfig {
  autoEnrich: boolean;
  abuseApiKey?: string;
  vtApiKey?: string;
  abuseConfigured?: boolean;
  vtConfigured?: boolean;
  abuseSource?: 'env' | 'cookie' | 'none';
  vtSource?: 'env' | 'cookie' | 'none';
}

// Security finding detected by the AI analysis engine
export interface SecurityFinding {
  id: string;
  type: FindingType;
  severity: SeverityLevel;
  title: string;
  description: string;
  justification: string;
  affectedAssets: string[];
  relatedLogIds: string[];
  indicators: string[];
  recommendation: string;
  mitreTactic?: string;
  mitreId?: string;
  timestamp: string;
  confidence: number; // 0-100
  threatIntel?: Record<string, IPReputation>;
}

export type FindingType =
  | 'brute_force'
  | 'suspicious_login'
  | 'privilege_escalation'
  | 'anomalous_command'
  | 'lateral_movement';

// Dashboard statistics
export interface DashboardStats {
  totalLogs: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  uniqueSourceIPs: number;
  uniqueUsers: number;
  timeRange: { start: string; end: string };
  topSourceIPs: { ip: string; count: number }[];
  topUsers: { user: string; count: number }[];
  eventsByType: { type: string; count: number }[];
  findingsByType: { type: FindingType; count: number }[];
  timelineData: { timestamp: string; critical: number; high: number; medium: number; low: number }[];
}

// Report configuration
export interface ReportConfig {
  type: 'executive' | 'technical';
  language: 'en' | 'es';
  title: string;
  author: string;
  organization: string;
  includeCharts: boolean;
  includeRawLogs: boolean;
  selectedFindings: string[];
  dateRange?: { start: string; end: string };
}

// Application state
export interface AppState {
  logs: LogEntry[];
  findings: SecurityFinding[];
  stats: DashboardStats | null;
  isAnalyzing: boolean;
  analysisProgress: number;
  fileName: string;
  uploadDate: string;
  currentView: 'upload' | 'dashboard' | 'analysis' | 'reports';
  threatIntel: {
    reputations: Record<string, IPReputation>;
    isEnriching: boolean;
    config: ThreatIntelConfig;
  };
}

// Language & Theme
export type Language = 'en' | 'es';
export type Theme = 'light' | 'dark';

export interface TranslationStrings {
  // Navigation
  nav_upload: string;
  nav_dashboard: string;
  nav_analysis: string;
  nav_reports: string;
  
  // Upload
  upload_title: string;
  upload_subtitle: string;
  upload_drag: string;
  upload_browse: string;
  upload_supported: string;
  upload_processing: string;
  upload_success: string;
  upload_error: string;
  upload_records: string;
  upload_analyze: string;
  
  // Dashboard
  dash_title: string;
  dash_total_logs: string;
  dash_findings: string;
  dash_critical: string;
  dash_high: string;
  dash_medium: string;
  dash_low: string;
  dash_unique_ips: string;
  dash_unique_users: string;
  dash_severity_dist: string;
  dash_events_timeline: string;
  dash_top_sources: string;
  dash_top_users: string;
  dash_findings_by_type: string;
  dash_events_by_type: string;
  
  // Analysis
  analysis_title: string;
  analysis_subtitle: string;
  analysis_filter_severity: string;
  analysis_filter_type: string;
  analysis_filter_all: string;
  analysis_no_findings: string;
  analysis_affected_assets: string;
  analysis_indicators: string;
  analysis_recommendation: string;
  analysis_justification: string;
  analysis_related_logs: string;
  analysis_confidence: string;
  analysis_mitre: string;
  
  // Findings types
  finding_brute_force: string;
  finding_suspicious_login: string;
  finding_privilege_escalation: string;
  finding_anomalous_command: string;
  finding_lateral_movement: string;
  
  // Reports
  report_title: string;
  report_subtitle: string;
  report_type: string;
  report_executive: string;
  report_technical: string;
  report_language: string;
  report_lang_en: string;
  report_lang_es: string;
  report_doc_title: string;
  report_author: string;
  report_organization: string;
  report_include_charts: string;
  report_include_raw: string;
  report_generate: string;
  report_generating: string;
  report_preview: string;
  report_download: string;
  report_select_findings: string;
  report_all_findings: string;
  report_filter_by_severity: string;
  
  // Threat Intelligence
  ti_title: string;
  ti_subtitle: string;
  ti_enrich_btn: string;
  ti_enriching: string;
  ti_api_keys: string;
  ti_save_keys: string;
  ti_abuse_key: string;
  ti_vt_key: string;
  ti_reputation: string;
  ti_confidence: string;
  ti_reports: string;
  ti_verdict_malicious: string;
  ti_verdict_suspicious: string;
  ti_verdict_clean: string;
  ti_verdict_private: string;
  
  // Theme
  theme_toggle: string;
  theme_light: string;
  theme_dark: string;
  
  // Common
  common_loading: string;
  common_error: string;
  common_no_data: string;
  common_export: string;
  common_back: string;
  common_next: string;
  common_search: string;
  common_clear: string;
}
