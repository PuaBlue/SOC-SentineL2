import {
  LogEntry,
  SecurityFinding,
  SeverityLevel,
  FindingType,
  DashboardStats,
} from '@/types';
import { generateId } from './utils';

// ──────────────────────────────────────────────
// Helper: normalize field values for matching
// ──────────────────────────────────────────────
function norm(val: unknown): string {
  if (val === null || val === undefined) return '';
  return String(val).trim().toLowerCase();
}

function fieldMatch(entry: LogEntry, needles: string[]): boolean {
  const haystack = [
    norm(entry.action),
    norm(entry.event_type),
    norm(entry.message),
    norm(entry.status),
    norm(entry.raw_log),
  ].join(' ');
  return needles.some((n) => haystack.includes(n));
}

// ──────────────────────────────────────────────
// 1. Brute Force Detection
// ──────────────────────────────────────────────
function detectBruteForce(logs: LogEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const failedBySource: Record<string, LogEntry[]> = {};

  for (const log of logs) {
    const isFailed = fieldMatch(log, [
      'fail', 'failed', 'denied', 'invalid', 'wrong password',
      'authentication failure', 'logon failure', 'bad password',
      'account lockout', 'locked out', 'incorrect password',
    ]);
    if (isFailed) {
      const key = `${log.source_ip}__${log.user || 'unknown'}`;
      if (!failedBySource[key]) failedBySource[key] = [];
      failedBySource[key].push(log);
    }
  }

  for (const [key, entries] of Object.entries(failedBySource)) {
    if (entries.length < 3) continue; // At least 3 failures to flag

    const [ip, user] = key.split('__');
    const timestamps = entries
      .map((e) => new Date(e.timestamp).getTime())
      .filter((t) => !isNaN(t))
      .sort((a, b) => a - b);

    // Check if failures happened in a short window (within 10 min between first and last)
    const windowMs = timestamps.length >= 2 ? timestamps[timestamps.length - 1] - timestamps[0] : 0;
    const isRapid = windowMs > 0 && windowMs < 600_000; // 10 minutes

    let severity: SeverityLevel = 'Low';
    let confidence = 40;
    if (entries.length >= 10 && isRapid) {
      severity = 'Critical';
      confidence = 95;
    } else if (entries.length >= 10) {
      severity = 'High';
      confidence = 80;
    } else if (entries.length >= 5 && isRapid) {
      severity = 'High';
      confidence = 75;
    } else if (entries.length >= 5) {
      severity = 'Medium';
      confidence = 60;
    }

    // Check for eventual success after failures (credential compromise indicator)
    const successAfterFail = logs.find(
      (l) =>
        l.source_ip === ip &&
        (l.user || '').toLowerCase() === (user || '').toLowerCase() &&
        fieldMatch(l, ['success', 'successful', 'logon success', 'authenticated']) &&
        new Date(l.timestamp).getTime() > (timestamps[timestamps.length - 1] || 0)
    );
    if (successAfterFail) {
      severity = 'Critical';
      confidence = Math.min(98, confidence + 20);
    }

    findings.push({
      id: generateId(),
      type: 'brute_force',
      severity,
      title: `Brute Force Attack Detected — ${ip} → ${user}`,
      description: `${entries.length} failed authentication attempts detected from source IP ${ip} targeting user "${user}".${isRapid ? ` Attempts occurred within a ${Math.round(windowMs / 1000)}s window, indicating automated attack tooling.` : ''}${successAfterFail ? ' A successful authentication was observed AFTER the failed attempts, indicating possible credential compromise.' : ''}`,
      justification: `Evidence based on ${entries.length} log entries showing failed authentication events from IP ${ip} for user "${user}". ${isRapid ? 'The rapid succession of attempts is consistent with automated brute-force tooling. ' : ''}Log IDs: ${entries.slice(0, 5).map((e) => e.id).join(', ')}${entries.length > 5 ? ` and ${entries.length - 5} more` : ''}.`,
      affectedAssets: [ip, user].filter(Boolean),
      relatedLogIds: entries.map((e) => e.id),
      indicators: [
        `${entries.length} failed auth attempts`,
        `Source: ${ip}`,
        `Target user: ${user}`,
        ...(isRapid ? [`Time window: ${Math.round(windowMs / 1000)}s`] : []),
        ...(successAfterFail ? ['Successful login after failures'] : []),
      ],
      recommendation: successAfterFail
        ? 'IMMEDIATE: Force password reset for the affected account. Block the source IP. Review all activity from this account post-compromise. Enable MFA if not already in place.'
        : 'Block or rate-limit the source IP. Enforce account lockout policies. Verify the affected account has MFA enabled. Monitor for further attempts.',
      mitreTactic: 'Credential Access',
      mitreId: 'T1110',
      timestamp: entries[0]?.timestamp || new Date().toISOString(),
      confidence,
    });
  }

  return findings;
}

// ──────────────────────────────────────────────
// 2. Suspicious Login Detection
// ──────────────────────────────────────────────
function detectSuspiciousLogins(logs: LogEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const loginsByUser: Record<string, LogEntry[]> = {};

  for (const log of logs) {
    const isLogin = fieldMatch(log, [
      'login', 'logon', 'sign in', 'signin', 'authenticated',
      'session started', 'success', 'successful login',
    ]);
    if (isLogin && log.user) {
      if (!loginsByUser[log.user]) loginsByUser[log.user] = [];
      loginsByUser[log.user].push(log);
    }
  }

  for (const [user, entries] of Object.entries(loginsByUser)) {
    // Detect logins from multiple distinct IPs
    const uniqueIPs = [...new Set(entries.map((e) => e.source_ip).filter(Boolean))];
    if (uniqueIPs.length >= 3) {
      const sortedEntries = [...entries].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
      // Check for geographically impossible travel (IPs changing rapidly)
      const rapidIpChanges: LogEntry[] = [];
      for (let i = 1; i < sortedEntries.length; i++) {
        const timeDiff =
          new Date(sortedEntries[i].timestamp).getTime() -
          new Date(sortedEntries[i - 1].timestamp).getTime();
        if (
          sortedEntries[i].source_ip !== sortedEntries[i - 1].source_ip &&
          timeDiff < 300_000 // 5 min
        ) {
          rapidIpChanges.push(sortedEntries[i - 1], sortedEntries[i]);
        }
      }

      const hasRapidChanges = rapidIpChanges.length > 0;
      const severity: SeverityLevel = hasRapidChanges
        ? uniqueIPs.length >= 5
          ? 'Critical'
          : 'High'
        : uniqueIPs.length >= 5
          ? 'Medium'
          : 'Low';

      findings.push({
        id: generateId(),
        type: 'suspicious_login',
        severity,
        title: `Suspicious Login Pattern — User "${user}"`,
        description: `User "${user}" authenticated from ${uniqueIPs.length} distinct source IPs.${hasRapidChanges ? ' Rapid IP changes detected within 5-minute windows, suggesting possible credential sharing or session hijacking.' : ''} Source IPs: ${uniqueIPs.slice(0, 6).join(', ')}${uniqueIPs.length > 6 ? '...' : ''}.`,
        justification: `Analysis of ${entries.length} login events for user "${user}" reveals authentication from ${uniqueIPs.length} unique IP addresses. ${hasRapidChanges ? `${rapidIpChanges.length / 2} rapid IP transitions detected (different IPs within 5-minute windows). ` : ''}This pattern is inconsistent with normal user behavior. Log IDs: ${entries.slice(0, 5).map((e) => e.id).join(', ')}${entries.length > 5 ? ` and ${entries.length - 5} more` : ''}.`,
        affectedAssets: [user, ...uniqueIPs.slice(0, 5)],
        relatedLogIds: entries.map((e) => e.id),
        indicators: [
          `${uniqueIPs.length} unique source IPs`,
          `User: ${user}`,
          ...(hasRapidChanges ? ['Rapid IP switching detected'] : []),
        ],
        recommendation: 'Verify with the user whether all login locations are legitimate. Enable MFA. Review session tokens for hijacking indicators. Consider implementing conditional access policies based on IP reputation.',
        mitreTactic: 'Initial Access',
        mitreId: 'T1078',
        timestamp: entries[0]?.timestamp || new Date().toISOString(),
        confidence: hasRapidChanges ? 80 : 55,
      });
    }

    // Detect off-hours logins
    const offHoursLogins = entries.filter((e) => {
      const hour = new Date(e.timestamp).getHours();
      return hour < 6 || hour > 22; // Before 6 AM or after 10 PM
    });
    if (offHoursLogins.length >= 2) {
      findings.push({
        id: generateId(),
        type: 'suspicious_login',
        severity: offHoursLogins.length >= 5 ? 'Medium' : 'Low',
        title: `Off-Hours Login Activity — User "${user}"`,
        description: `${offHoursLogins.length} login events detected for user "${user}" outside normal business hours (10 PM – 6 AM).`,
        justification: `${offHoursLogins.length} login events for user "${user}" occurred outside the 06:00–22:00 window. While some off-hours activity may be legitimate, repeated instances warrant verification. Timestamps: ${offHoursLogins.slice(0, 3).map((e) => e.timestamp).join(', ')}.`,
        affectedAssets: [user],
        relatedLogIds: offHoursLogins.map((e) => e.id),
        indicators: [
          `${offHoursLogins.length} off-hours logins`,
          `User: ${user}`,
        ],
        recommendation: 'Verify with the user whether off-hours access is expected. Implement time-based access controls if applicable.',
        mitreTactic: 'Initial Access',
        mitreId: 'T1078',
        timestamp: offHoursLogins[0]?.timestamp || new Date().toISOString(),
        confidence: 45,
      });
    }
  }

  return findings;
}

// ──────────────────────────────────────────────
// 3. Privilege Escalation Detection
// ──────────────────────────────────────────────
function detectPrivilegeEscalation(logs: LogEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const privEvents: LogEntry[] = [];

  for (const log of logs) {
    const isPrivEsc = fieldMatch(log, [
      'privilege', 'escalat', 'admin', 'root', 'sudo', 'runas',
      'elevated', 'role change', 'group add', 'added to admin',
      'permission change', 'security group', 'member added',
      'special privileges', 'sensitive privilege', 'token elevation',
      'new logon', 'elevated token',
    ]);
    if (isPrivEsc) privEvents.push(log);
  }

  // Group by user
  const byUser: Record<string, LogEntry[]> = {};
  for (const ev of privEvents) {
    const user = ev.user || 'unknown';
    if (!byUser[user]) byUser[user] = [];
    byUser[user].push(ev);
  }

  for (const [user, entries] of Object.entries(byUser)) {
    if (entries.length < 1) continue;

    const hasDirectEscalation = entries.some((e) =>
      fieldMatch(e, ['escalat', 'elevated', 'token elevation', 'runas', 'sudo'])
    );
    const hasGroupChange = entries.some((e) =>
      fieldMatch(e, ['group add', 'added to admin', 'member added', 'security group'])
    );

    let severity: SeverityLevel = 'Medium';
    let confidence = 55;
    if (hasDirectEscalation && entries.length >= 3) {
      severity = 'Critical';
      confidence = 85;
    } else if (hasDirectEscalation || hasGroupChange) {
      severity = 'High';
      confidence = 70;
    }

    findings.push({
      id: generateId(),
      type: 'privilege_escalation',
      severity,
      title: `Privilege Escalation Activity — User "${user}"`,
      description: `${entries.length} privilege-related event(s) detected for user "${user}".${hasDirectEscalation ? ' Direct privilege escalation indicators found.' : ''}${hasGroupChange ? ' Security group membership changes detected.' : ''}`,
      justification: `${entries.length} log entries for user "${user}" contain privilege escalation keywords. ${hasDirectEscalation ? 'Entries include direct escalation indicators (elevation, runas, sudo). ' : ''}${hasGroupChange ? 'Entries include security group membership modifications. ' : ''}Log IDs: ${entries.slice(0, 5).map((e) => e.id).join(', ')}${entries.length > 5 ? ` and ${entries.length - 5} more` : ''}.`,
      affectedAssets: [user, ...new Set(entries.map((e) => e.destination_ip || e.source_ip).filter(Boolean))].slice(0, 5),
      relatedLogIds: entries.map((e) => e.id),
      indicators: [
        `${entries.length} privilege events`,
        `User: ${user}`,
        ...(hasDirectEscalation ? ['Direct escalation detected'] : []),
        ...(hasGroupChange ? ['Group membership change'] : []),
      ],
      recommendation: 'Verify whether the privilege changes were authorized through proper change management. Review the user\'s subsequent activity for signs of abuse. Implement just-in-time (JIT) privileged access if not already in place.',
      mitreTactic: 'Privilege Escalation',
      mitreId: 'T1078.002',
      timestamp: entries[0]?.timestamp || new Date().toISOString(),
      confidence,
    });
  }

  return findings;
}

// ──────────────────────────────────────────────
// 4. Anomalous Command Detection
// ──────────────────────────────────────────────
function detectAnomalousCommands(logs: LogEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const suspiciousCommands: LogEntry[] = [];

  const dangerousPatterns = [
    'powershell', 'cmd.exe', 'bash', 'wget', 'curl', 'certutil',
    'bitsadmin', 'mshta', 'regsvr32', 'rundll32', 'wscript',
    'cscript', 'net user', 'net group', 'net localgroup',
    'whoami', 'systeminfo', 'ipconfig', 'nslookup', 'tasklist',
    'sc query', 'wmic', 'mimikatz', 'procdump', 'psexec',
    'invoke-expression', 'iex', 'downloadstring', 'invoke-webrequest',
    'base64', 'encodedcommand', '-enc', '-nop', '-w hidden',
    'bypass', 'unrestricted', 'set-executionpolicy',
    'new-object', 'net.webclient', 'reflection.assembly',
    'add-type', 'compile', 'netsh', 'iptables', 'chmod 777',
    'reverse shell', 'bind shell', 'nc -e', 'ncat',
  ];

  for (const log of logs) {
    if (fieldMatch(log, dangerousPatterns)) {
      suspiciousCommands.push(log);
    }
  }

  // Group by user + source
  const grouped: Record<string, LogEntry[]> = {};
  for (const cmd of suspiciousCommands) {
    const key = `${cmd.user || 'unknown'}__${cmd.source_ip || 'unknown'}`;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(cmd);
  }

  for (const [key, entries] of Object.entries(grouped)) {
    const [user, ip] = key.split('__');

    const hasEncodedCmd = entries.some((e) =>
      fieldMatch(e, ['base64', 'encodedcommand', '-enc', 'downloadstring'])
    );
    const hasRecon = entries.some((e) =>
      fieldMatch(e, ['whoami', 'systeminfo', 'ipconfig', 'nslookup', 'tasklist', 'net user'])
    );
    const hasExfil = entries.some((e) =>
      fieldMatch(e, ['wget', 'curl', 'certutil', 'bitsadmin', 'invoke-webrequest'])
    );
    const hasMalware = entries.some((e) =>
      fieldMatch(e, ['mimikatz', 'procdump', 'psexec', 'reverse shell', 'bind shell'])
    );

    let severity: SeverityLevel = 'Medium';
    let confidence = 50;
    if (hasMalware) {
      severity = 'Critical';
      confidence = 90;
    } else if (hasEncodedCmd && entries.length >= 3) {
      severity = 'Critical';
      confidence = 85;
    } else if (hasEncodedCmd || (hasRecon && hasExfil)) {
      severity = 'High';
      confidence = 75;
    } else if (entries.length >= 5) {
      severity = 'High';
      confidence = 65;
    }

    findings.push({
      id: generateId(),
      type: 'anomalous_command',
      severity,
      title: `Anomalous Command Execution — ${user}@${ip}`,
      description: `${entries.length} suspicious command execution event(s) detected from user "${user}" on ${ip}.${hasEncodedCmd ? ' Encoded/obfuscated commands detected.' : ''}${hasRecon ? ' System reconnaissance commands observed.' : ''}${hasExfil ? ' Data download/exfiltration tools used.' : ''}${hasMalware ? ' Known offensive security tools detected.' : ''}`,
      justification: `${entries.length} log entries from user "${user}" (${ip}) match known suspicious command patterns. ${hasEncodedCmd ? 'Encoded/obfuscated PowerShell commands detected—common in fileless malware. ' : ''}${hasRecon ? 'System enumeration commands suggest reconnaissance activity. ' : ''}${hasExfil ? 'File download utilities detected—potential payload staging or data exfiltration. ' : ''}${hasMalware ? 'Known offensive security tools (e.g., Mimikatz, PsExec) identified in command logs. ' : ''}Log IDs: ${entries.slice(0, 5).map((e) => e.id).join(', ')}${entries.length > 5 ? ` and ${entries.length - 5} more` : ''}.`,
      affectedAssets: [user, ip].filter(Boolean),
      relatedLogIds: entries.map((e) => e.id),
      indicators: [
        `${entries.length} suspicious commands`,
        `User: ${user}`,
        `Host: ${ip}`,
        ...(hasEncodedCmd ? ['Encoded/obfuscated commands'] : []),
        ...(hasRecon ? ['Reconnaissance activity'] : []),
        ...(hasExfil ? ['Download/exfiltration tools'] : []),
        ...(hasMalware ? ['Offensive security tools'] : []),
      ],
      recommendation: hasMalware
        ? 'CRITICAL: Isolate the affected host immediately. Initiate incident response procedures. Capture forensic image. Block the user account. Review all lateral movement from this host.'
        : 'Investigate the context of command execution. Verify with the user/admin whether the activity was authorized. Implement application whitelisting. Enable PowerShell logging (ScriptBlock, Module, Transcription).',
      mitreTactic: 'Execution',
      mitreId: hasEncodedCmd ? 'T1059.001' : 'T1059',
      timestamp: entries[0]?.timestamp || new Date().toISOString(),
      confidence,
    });
  }

  return findings;
}

// ──────────────────────────────────────────────
// 5. Lateral Movement Detection
// ──────────────────────────────────────────────
function detectLateralMovement(logs: LogEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const movementByUser: Record<string, Set<string>> = {};
  const movementLogs: Record<string, LogEntry[]> = {};

  const lateralKeywords = [
    'remote', 'rdp', 'ssh', 'smb', 'wmi', 'winrm', 'psexec',
    'lateral', 'pivot', 'pass the hash', 'pth', 'pass the ticket',
    'dcom', 'remote desktop', 'remote login', 'network logon',
    'type 3', 'logon type 3', 'logon type 10',
    'scheduled task', 'at.exe', 'schtasks',
  ];

  for (const log of logs) {
    if (fieldMatch(log, lateralKeywords) && log.user) {
      if (!movementByUser[log.user]) {
        movementByUser[log.user] = new Set();
        movementLogs[log.user] = [];
      }
      if (log.destination_ip) movementByUser[log.user].add(log.destination_ip);
      if (log.source_ip) movementByUser[log.user].add(log.source_ip);
      movementLogs[log.user].push(log);
    }
  }

  for (const [user, ips] of Object.entries(movementByUser)) {
    const entries = movementLogs[user] || [];
    if (ips.size < 2) continue; // Need at least 2 unique hosts

    const uniqueHosts = [...ips];
    const hasPassTheHash = entries.some((e) =>
      fieldMatch(e, ['pass the hash', 'pth', 'pass the ticket', 'overpass'])
    );
    const hasPsExec = entries.some((e) =>
      fieldMatch(e, ['psexec', 'remote exec', 'wmi', 'winrm'])
    );

    let severity: SeverityLevel = 'Medium';
    let confidence = 55;
    if (hasPassTheHash) {
      severity = 'Critical';
      confidence = 90;
    } else if (uniqueHosts.length >= 5 || hasPsExec) {
      severity = 'High';
      confidence = 75;
    } else if (uniqueHosts.length >= 3) {
      severity = 'Medium';
      confidence = 60;
    }

    findings.push({
      id: generateId(),
      type: 'lateral_movement',
      severity,
      title: `Lateral Movement Detected — User "${user}"`,
      description: `User "${user}" shows remote access activity across ${uniqueHosts.length} distinct hosts.${hasPassTheHash ? ' Pass-the-Hash/Ticket indicators detected.' : ''}${hasPsExec ? ' Remote execution tools (PsExec/WMI/WinRM) observed.' : ''} Hosts: ${uniqueHosts.slice(0, 5).join(', ')}${uniqueHosts.length > 5 ? '...' : ''}.`,
      justification: `${entries.length} log entries for user "${user}" indicate remote access to ${uniqueHosts.length} hosts via network logon, RDP, SMB, or remote execution tools. ${hasPassTheHash ? 'Credential relay techniques (Pass-the-Hash/Ticket) detected. ' : ''}${hasPsExec ? 'Remote command execution via PsExec/WMI/WinRM detected. ' : ''}The pattern of moving between multiple hosts is consistent with lateral movement. Log IDs: ${entries.slice(0, 5).map((e) => e.id).join(', ')}${entries.length > 5 ? ` and ${entries.length - 5} more` : ''}.`,
      affectedAssets: [user, ...uniqueHosts.slice(0, 5)],
      relatedLogIds: entries.map((e) => e.id),
      indicators: [
        `${uniqueHosts.length} hosts accessed`,
        `User: ${user}`,
        ...(hasPassTheHash ? ['Pass-the-Hash/Ticket detected'] : []),
        ...(hasPsExec ? ['Remote execution tools used'] : []),
      ],
      recommendation: hasPassTheHash
        ? 'CRITICAL: Initiate incident response. Reset credentials for the affected user and service accounts. Deploy Credential Guard. Segment the network. Review all accessed hosts for compromise.'
        : 'Investigate whether the multi-host access is legitimate for the user\'s role. Implement network segmentation and micro-segmentation. Enable enhanced logging on all accessed hosts.',
      mitreTactic: 'Lateral Movement',
      mitreId: hasPassTheHash ? 'T1550.002' : 'T1021',
      timestamp: entries[0]?.timestamp || new Date().toISOString(),
      confidence,
    });
  }

  return findings;
}

// ──────────────────────────────────────────────
// Main analysis orchestrator
// ──────────────────────────────────────────────
export function analyzeSecurityLogs(logs: LogEntry[]): SecurityFinding[] {
  const allFindings: SecurityFinding[] = [
    ...detectBruteForce(logs),
    ...detectSuspiciousLogins(logs),
    ...detectPrivilegeEscalation(logs),
    ...detectAnomalousCommands(logs),
    ...detectLateralMovement(logs),
  ];

  // Sort by severity (Critical first) then by confidence
  const severityOrder: Record<string, number> = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
  };

  allFindings.sort((a, b) => {
    const sA = severityOrder[a.severity] ?? 4;
    const sB = severityOrder[b.severity] ?? 4;
    if (sA !== sB) return sA - sB;
    return b.confidence - a.confidence;
  });

  return allFindings;
}

// ──────────────────────────────────────────────
// Dashboard statistics computation
// ──────────────────────────────────────────────
export function computeStats(
  logs: LogEntry[],
  findings: SecurityFinding[]
): DashboardStats {
  const uniqueSourceIPs = new Set(logs.map((l) => l.source_ip).filter(Boolean));
  const uniqueUsers = new Set(logs.map((l) => l.user).filter(Boolean));

  // Time range
  const timestamps = logs
    .map((l) => new Date(l.timestamp).getTime())
    .filter((t) => !isNaN(t))
    .sort((a, b) => a - b);

  const timeRange = {
    start: timestamps.length ? new Date(timestamps[0]).toISOString() : '',
    end: timestamps.length ? new Date(timestamps[timestamps.length - 1]).toISOString() : '',
  };

  // Top source IPs
  const ipCounts: Record<string, number> = {};
  for (const l of logs) {
    if (l.source_ip) ipCounts[l.source_ip] = (ipCounts[l.source_ip] || 0) + 1;
  }
  const topSourceIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  // Top users
  const userCounts: Record<string, number> = {};
  for (const l of logs) {
    if (l.user) userCounts[l.user] = (userCounts[l.user] || 0) + 1;
  }
  const topUsers = Object.entries(userCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([user, count]) => ({ user, count }));

  // Events by type
  const typeCounts: Record<string, number> = {};
  for (const l of logs) {
    const t = l.event_type || l.action || 'unknown';
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  }
  const eventsByType = Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([type, count]) => ({ type, count }));

  // Findings by type
  const findingTypeCounts: Record<FindingType, number> = {
    brute_force: 0,
    suspicious_login: 0,
    privilege_escalation: 0,
    anomalous_command: 0,
    lateral_movement: 0,
  };
  for (const f of findings) {
    findingTypeCounts[f.type]++;
  }
  const findingsByType = (Object.entries(findingTypeCounts) as [FindingType, number][])
    .map(([type, count]) => ({ type, count }));

  // Timeline — bucket logs by hour
  const bucketSize = 3600_000; // 1 hour
  const timelineBuckets: Record<number, { critical: number; high: number; medium: number; low: number }> = {};
  for (const l of logs) {
    const t = new Date(l.timestamp).getTime();
    if (isNaN(t)) continue;
    const bucket = Math.floor(t / bucketSize) * bucketSize;
    if (!timelineBuckets[bucket]) timelineBuckets[bucket] = { critical: 0, high: 0, medium: 0, low: 0 };
    const sev = (l.severity || '').toLowerCase();
    if (sev === 'critical') timelineBuckets[bucket].critical++;
    else if (sev === 'high') timelineBuckets[bucket].high++;
    else if (sev === 'medium') timelineBuckets[bucket].medium++;
    else timelineBuckets[bucket].low++;
  }
  const timelineData = Object.entries(timelineBuckets)
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .map(([ts, data]) => ({
      timestamp: new Date(Number(ts)).toISOString(),
      ...data,
    }));

  return {
    totalLogs: logs.length,
    totalFindings: findings.length,
    criticalCount: findings.filter((f) => f.severity === 'Critical').length,
    highCount: findings.filter((f) => f.severity === 'High').length,
    mediumCount: findings.filter((f) => f.severity === 'Medium').length,
    lowCount: findings.filter((f) => f.severity === 'Low').length,
    uniqueSourceIPs: uniqueSourceIPs.size,
    uniqueUsers: uniqueUsers.size,
    timeRange,
    topSourceIPs,
    topUsers,
    eventsByType,
    findingsByType,
    timelineData,
  };
}
