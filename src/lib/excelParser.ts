import * as XLSX from 'xlsx';
import { LogEntry } from '@/types';
import { generateId } from './utils';

// Common column name mappings from various SIEM exports
const COLUMN_MAP: Record<string, keyof LogEntry> = {
  // Timestamp variants
  timestamp: 'timestamp',
  time: 'timestamp',
  date: 'timestamp',
  datetime: 'timestamp',
  event_time: 'timestamp',
  eventtime: 'timestamp',
  '@timestamp': 'timestamp',
  log_time: 'timestamp',
  created: 'timestamp',
  generated: 'timestamp',
  timecreated: 'timestamp',
  timegenerated: 'timestamp',
  
  // Source IP variants
  source_ip: 'source_ip',
  sourceip: 'source_ip',
  src_ip: 'source_ip',
  srcip: 'source_ip',
  src: 'source_ip',
  source: 'source_ip',
  source_address: 'source_ip',
  sourceaddress: 'source_ip',
  client_ip: 'source_ip',
  clientip: 'source_ip',
  ipaddress: 'source_ip',
  
  // Destination IP variants
  destination_ip: 'destination_ip',
  destinationip: 'destination_ip',
  dst_ip: 'destination_ip',
  dstip: 'destination_ip',
  dst: 'destination_ip',
  destination: 'destination_ip',
  dest_ip: 'destination_ip',
  destip: 'destination_ip',
  destination_address: 'destination_ip',
  target: 'destination_ip',
  target_ip: 'destination_ip',
  
  // User variants
  user: 'user',
  username: 'user',
  user_name: 'user',
  account: 'user',
  account_name: 'user',
  accountname: 'user',
  subject: 'user',
  actor: 'user',
  identity: 'user',
  targetusername: 'user',
  target_user: 'user',
  
  // Action variants
  action: 'action',
  activity: 'action',
  operation: 'action',
  event_action: 'action',
  eventaction: 'action',
  operationname: 'action',
  
  // Event type variants
  event_type: 'event_type',
  eventtype: 'event_type',
  type: 'event_type',
  category: 'event_type',
  event_category: 'event_type',
  eventcategory: 'event_type',
  event_id: 'event_type',
  eventid: 'event_type',
  
  // Severity variants
  severity: 'severity',
  level: 'severity',
  priority: 'severity',
  risk: 'severity',
  risk_level: 'severity',
  threat_level: 'severity',
  
  // Message variants
  message: 'message',
  msg: 'message',
  description: 'message',
  details: 'message',
  summary: 'message',
  event_message: 'message',
  log_message: 'message',
  raw: 'message',
  
  // Protocol variants
  protocol: 'protocol',
  proto: 'protocol',
  
  // Port variants
  port: 'port',
  dest_port: 'port',
  destination_port: 'port',
  dstport: 'port',
  dst_port: 'port',
  
  // Status variants
  status: 'status',
  result: 'status',
  outcome: 'status',
  event_outcome: 'status',
  logon_type: 'status',
  
  // Device variants
  device: 'device',
  hostname: 'device',
  host: 'device',
  computer: 'device',
  computername: 'device',
  machine: 'device',
  source_host: 'device',
  
  // Raw log
  raw_log: 'raw_log',
  rawlog: 'raw_log',
  original: 'raw_log',
  raw_event: 'raw_log',
};

function mapColumnName(col: string): keyof LogEntry | null {
  const normalized = col.trim().toLowerCase().replace(/[\s\-\.]+/g, '_');
  return COLUMN_MAP[normalized] || null;
}

function parseExcelDate(value: unknown): string {
  if (!value) return '';
  
  // If it's a number, treat as Excel serial date
  if (typeof value === 'number') {
    try {
      const date = XLSX.SSF.parse_date_code(value);
      if (date) {
        return new Date(date.y, date.m - 1, date.d, date.H || 0, date.M || 0, date.S || 0).toISOString();
      }
    } catch {
      // fall through
    }
  }
  
  // Try parsing as string
  const str = String(value).trim();
  const parsed = new Date(str);
  if (!isNaN(parsed.getTime())) return parsed.toISOString();
  
  return str;
}

export function parseExcelFile(buffer: ArrayBuffer): LogEntry[] {
  const workbook = XLSX.read(buffer, { type: 'array', cellDates: true });
  const logs: LogEntry[] = [];

  for (const sheetName of workbook.SheetNames) {
    const sheet = workbook.Sheets[sheetName];
    const rawData = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: '' });

    if (rawData.length === 0) continue;

    // Map columns
    const firstRow = rawData[0];
    const columnMapping: Record<string, keyof LogEntry> = {};
    const unmappedColumns: string[] = [];

    for (const col of Object.keys(firstRow)) {
      const mapped = mapColumnName(col);
      if (mapped) {
        columnMapping[col] = mapped;
      } else {
        unmappedColumns.push(col);
      }
    }

    for (const row of rawData) {
      const entry: LogEntry = {
        id: generateId(),
        timestamp: '',
        source_ip: '',
        destination_ip: '',
        user: '',
        action: '',
        event_type: '',
        severity: '',
        message: '',
      };

      // Map known columns
      for (const [origCol, mappedField] of Object.entries(columnMapping)) {
        const value = row[origCol];
        if (mappedField === 'timestamp') {
          entry.timestamp = parseExcelDate(value);
        } else if (mappedField === 'port') {
          entry.port = Number(value) || undefined;
        } else {
          (entry as Record<string, unknown>)[mappedField] = value != null ? String(value).trim() : '';
        }
      }

      // Store unmapped columns as extra fields
      for (const col of unmappedColumns) {
        const value = row[col];
        if (value != null && String(value).trim()) {
          entry[col] = value;
        }
      }

      // Build raw_log from all fields if not present
      if (!entry.raw_log) {
        entry.raw_log = Object.entries(row)
          .map(([k, v]) => `${k}=${v}`)
          .join(' | ');
      }

      // Build message from available fields if not present
      if (!entry.message) {
        const parts = [entry.action, entry.event_type, entry.status].filter(Boolean);
        entry.message = parts.join(' - ') || 'No message';
      }

      // Only add if we have at least a timestamp or some meaningful content
      if (entry.timestamp || entry.message !== 'No message' || entry.source_ip || entry.user) {
        logs.push(entry);
      }
    }
  }

  return logs;
}
