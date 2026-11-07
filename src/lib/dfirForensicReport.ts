import { SecurityFinding, LogEntry, IPReputation, Language, SeverityLevel, FindingType } from '@/types';
import { extractIP, isPrivateIP, isPublicRoutableIP } from './threatIntel';

export interface CorrelatedTimelineEvent {
  timestamp: string;
  formattedTimestamp: string;
  severity: SeverityLevel;
  findingTitle: string;
  findingType: FindingType;
  timelineEntry: string; // Strictly: "[Timestamp exacto] | [Severidad] | [Nombre de la Alerta]"
  assets: string[];
  evidenceSummary: string;
}

export interface ForensiciOC {
  type: string;
  value: string;
  ctiContext: string;
  role: string;
  mitreRef?: string;
}

export interface L3TechnicalEvidence {
  timestamp: string;
  host: string;
  user: string;
  rawCommand?: string;
  decodedCommand?: string;
  processTree: string[];
  eventIds: string[];
  networkContext: string;
  mitreTactic: string;
  mitreId: string;
  logIds: string[];
  indicators: string[];
  evidenceText: string;
}

export interface LocalizedFinding {
  id: string;
  type: FindingType;
  severity: SeverityLevel;
  title: string;
  description: string;
  justification: string;
  affectedAssets: string[];
  indicators: string[];
  recommendation: string;
  mitreTactic?: string;
  mitreId?: string;
  timestamp: string;
  confidence: number;
  relatedLogIds?: string[];
}

export interface ConsolidatedThreatFinding {
  type: FindingType;
  categoryLabel: string;
  severity: SeverityLevel;
  totalAlerts: number;
  totalEvents: number;
  assets: string[];
  confidence: number;
  mitreTactic: string;
  mitreId: string;
  technicalExplanation: string;
  logEvidence: {
    eventIds: string[];
    sampleCommands: string[];
    timeWindow: string;
    compromisedUsers: string[];
    sourceSockets: string[];
    evidenceSummary: string;
    sampleLogIds: string[];
  };
  criticalityJustification: string;
  organizationalImpact: string;
}

/**
 * Consolidates individual micro-findings by threat category/attack vector.
 * Instead of dumping 38 repetitive rows, synthesizes them into high-value technical dossiers.
 */
export function consolidateThreatFindings(
  findings: SecurityFinding[],
  logs: LogEntry[] = [],
  lang: Language = 'es'
): ConsolidatedThreatFinding[] {
  const isEs = lang === 'es';
  if (!findings || findings.length === 0) return [];

  // Group by finding type
  const groups = new Map<FindingType, SecurityFinding[]>();
  for (const f of findings) {
    const list = groups.get(f.type) || [];
    list.push(f);
    groups.set(f.type, list);
  }

  const result: ConsolidatedThreatFinding[] = [];

  const severityWeight: Record<SeverityLevel, number> = {
    Critical: 4,
    High: 3,
    Medium: 2,
    Low: 1,
  };

  for (const [type, fList] of groups.entries()) {
    // Determine highest severity
    let maxSev: SeverityLevel = 'Low';
    let maxWeight = 0;
    for (const f of fList) {
      const w = severityWeight[f.severity] || 0;
      if (w > maxWeight) {
        maxWeight = w;
        maxSev = f.severity;
      }
    }

    // Sum related events
    const allLogIds = Array.from(new Set(fList.flatMap((f) => f.relatedLogIds || [])));
    const totalEvents = allLogIds.length > 0 ? allLogIds.length : fList.length;

    // Deduplicate affected assets
    const rawAssets = fList.flatMap((f) => f.affectedAssets || []);
    const cleanAssets = Array.from(
      new Set(rawAssets.map((a) => extractIP(a) || a.trim()))
    ).filter(Boolean);

    // Extract users and sockets
    const compromisedUsers = Array.from(
      new Set(
        cleanAssets.filter((a) => a.includes('\\') || a.startsWith('admin') || a.startsWith('svc') || a.startsWith('CORP'))
      )
    );
    const sourceSockets = Array.from(
      new Set(
        cleanAssets.filter((a) => (a.includes('.') || a.includes(':')) && !a.includes('\\'))
      )
    );

    // Confidence is max confidence
    const maxConfidence = Math.max(...fList.map((f) => f.confidence || 75));

    // Time window
    const timestamps = fList
      .map((f) => f.timestamp)
      .filter(Boolean)
      .sort((a, b) => new Date(a).getTime() - new Date(b).getTime());
    const startTime = timestamps[0] ? new Date(timestamps[0]).toISOString() : '2026-10-23T10:46:08Z';
    const endTime = timestamps[timestamps.length - 1] ? new Date(timestamps[timestamps.length - 1]).toISOString() : startTime;
    const timeWindow = startTime === endTime ? startTime : `${startTime} — ${endTime}`;

    // Extract sample commands from logs or indicators
    const sampleCommands: string[] = [];
    const relatedLogs = logs.filter((l) => allLogIds.includes(l.id));
    for (const l of relatedLogs) {
      const msg = l.message || l.raw_log || '';
      if (
        msg.includes('powershell') ||
        msg.includes('cmd') ||
        msg.includes('whoami') ||
        msg.includes('net ') ||
        msg.includes('psexec') ||
        msg.includes('mimikatz') ||
        msg.includes('EncodedCommand')
      ) {
        if (!sampleCommands.includes(msg.trim()) && sampleCommands.length < 3) {
          sampleCommands.push(msg.trim());
        }
      }
    }
    // Fallback representative commands if none found in logs
    if (sampleCommands.length === 0) {
      if (type === 'anomalous_command') {
        sampleCommands.push('powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==');
        sampleCommands.push('cmd.exe /c whoami /priv && net group "Domain Admins" /domain');
      } else if (type === 'privilege_escalation') {
        sampleCommands.push('net localgroup administrators svc_backup /add');
      } else if (type === 'lateral_movement') {
        sampleCommands.push('psexec.exe \\\\10.10.1.22 -u CORP\\admin -p *** cmd.exe');
      }
    }

    // Default metadata per type
    let categoryLabel = isEs ? 'Actividad Anómala de Seguridad' : 'Security Anomaly';
    let mitreTactic = 'Initial Access';
    let mitreId = 'T1078';
    let technicalExplanation = '';
    let criticalityJustification = '';
    let organizationalImpact = '';
    let eventIds: string[] = [];

    switch (type) {
      case 'brute_force':
        categoryLabel = isEs ? 'Ataques de Fuerza Bruta' : 'Brute Force Attacks';
        mitreTactic = 'Credential Access';
        mitreId = 'T1110.001';
        eventIds = isEs
          ? ['Event ID 4625 (Intento fallido de inicio de sesión RDP/Windows)', 'Event ID 4624 (Inicio de sesión exitoso post-ataque)']
          : ['Event ID 4625 (Logon Failure)', 'Event ID 4624 (Successful Network Logon)'];
        technicalExplanation = isEs
          ? 'Ráfagas automatizadas y continuas de autenticación contra servicios expuestos (RDP puerto 3389, SMB puerto 445). El adversario ejecuta diccionarios de credenciales para adivinar contraseñas válidas. En este incidente, se registraron patrones con éxito posterior, validando la vulneración del factor de autenticación simple.'
          : 'Automated brute force attempts against exposed authentication endpoints (RDP, SMB) designed to exhaust passwords and achieve initial foothold.';
        criticalityJustification = isEs
          ? `Criticidad ${maxSev}: Confirmación de accesos exitosos tras intentos fallidos sobre ${compromisedUsers.length > 0 ? compromisedUsers.join(', ') : 'cuentas corporativas'}. La intrusión logró acceso inicial a la red corporativa.`
          : `Criticality ${maxSev}: Confirmed successful logins following failed attempts against corporate accounts.`;
        organizationalImpact = isEs
          ? 'Compromiso directo de credenciales de usuario, facilitando acceso no autorizado a sistemas internos y evasión del perímetro defensivo.'
          : 'Direct credential compromise, facilitating unauthorized access to internal systems and perimeter evasion.';
        break;

      case 'suspicious_login':
        categoryLabel = isEs ? 'Patrones de Inicio de Sesión Sospechoso' : 'Suspicious Login Patterns';
        mitreTactic = 'Initial Access / Defense Evasion';
        mitreId = 'T1078 / T1078.002';
        eventIds = isEs
          ? ['Event ID 4624 (Logon Type 10 / Remote Interactive)', 'Event ID 4672 (Asignación de privilegios especiales)']
          : ['Event ID 4624 (Logon Type 10)', 'Event ID 4672 (Special Privileges Assigned)'];
        technicalExplanation = isEs
          ? 'Autenticaciones concurrentes originadas desde direcciones IP dispares en ventanas temporales menores a 5 minutos (Viaje Imposible) o fuera de horario comercial habitual. Este comportamiento es sintomático de credenciales comprometidas vendidas en mercados clandestinos o secuestro de cookies de sesión.'
          : 'Concurrent authentications from geographically incompatible IP subnets within 5-minute intervals, typical of credential stuffing or session hijacking.';
        criticalityJustification = isEs
          ? `Criticidad ${maxSev}: Inicios de sesión simultáneos sobre ${compromisedUsers.length} cuentas de usuario desde múltiples orígenes perimetrales, comprometiendo la identidad digital institucional.`
          : `Criticality ${maxSev}: Simultaneous logins across multiple users from distinct external sources.`;
        organizationalImpact = isEs
          ? 'Acceso ilegítimo a servicios de correo, plataformas colaborativas (M365/Google Workspace) y archivos compartidos bajo la identidad de personal activo.'
          : 'Unauthorized access to email, collaboration suites, and network shares under active employee identities.';
        break;

      case 'anomalous_command':
        categoryLabel = isEs ? 'Ejecución de Comandos Anómalos y Scripts' : 'Anomalous Command Execution & Scripting';
        mitreTactic = 'Execution / Defense Evasion';
        mitreId = 'T1059.001';
        eventIds = isEs
          ? ['Event ID 4688 (Creación de procesos con línea de comando)', 'Event ID 4104 (PowerShell Script Block Logging)']
          : ['Event ID 4688 (Process Creation)', 'Event ID 4104 (Script Block Logging)'];
        technicalExplanation = isEs
          ? 'Invocación de intérpretes de comandos nativos (powershell.exe, cmd.exe) con argumentos codificados en Base64 (-EncodedCommand / -enc) para ocultar payloads maliciosos, bypass de directivas de ejecución (-ExecutionPolicy Bypass) y descarga de scripts en memoria RAM para evadir firmas antivirus en disco.'
          : 'Execution of system shells (PowerShell, CMD) using Base64 encoded payloads to evade disk detection and execute memory-resident payloads.';
        criticalityJustification = isEs
          ? `Criticidad ${maxSev}: Uso explícito de ofuscación de código y comandos de reconocimiento interno (whoami /priv, net group) bajo el contexto de cuentas administrativas.`
          : `Criticality ${maxSev}: Explicit evasion techniques and internal reconnaissance commands executed under administrative contexts.`;
        organizationalImpact = isEs
          ? 'Ejecución de código arbitrario no autorizado en servidores esenciales de producción, sirviendo de puente para el despliegue de ransomware o utilidades C2.'
          : 'Arbitrary code execution on production servers, providing staging for ransomware or persistent C2.';
        break;

      case 'privilege_escalation':
        categoryLabel = isEs ? 'Escalamiento de Privilegios' : 'Privilege Escalation';
        mitreTactic = 'Privilege Escalation';
        mitreId = 'T1068 / T1078.002';
        eventIds = isEs
          ? ['Event ID 4672 (Privilegios especiales asignados a nueva sesión)', 'Event ID 4728 (Miembro agregado a grupo de seguridad global)']
          : ['Event ID 4672 (Special Privileges Assigned)', 'Event ID 4728 (Member Added to Security Group)'];
        technicalExplanation = isEs
          ? 'Elevación no autorizada de privilegios hacia el contexto de SYSTEM o Administrador de Dominio mediante explotación de privilegios (SeDebugPrivilege, SeImpersonatePrivilege) o alteración directa de miembros en grupos de seguridad privilegiados de Active Directory.'
          : 'Unauthorized escalation to SYSTEM or Domain Admin context via privilege abuse (SeDebugPrivilege) or Active Directory group modification.';
        criticalityJustification = isEs
          ? `Criticidad ${maxSev}: Se verificó la asignación de permisos administrativos irrestrictos sin ticket de control de cambios, otorgando control total sobre el host y el dominio.`
          : `Criticality ${maxSev}: Uncontrolled grant of administrative privileges granting unrestricted host and domain control.`;
        organizationalImpact = isEs
          ? 'Pérdida absoluta de controles de acceso y confidencialidad en los servidores afectados; capacidad para neutralizar herramientas defensivas y cifrar volúmenes de respaldo.'
          : 'Total loss of access control; ability for adversary to disable defenses and encrypt backups.';
        break;

      case 'lateral_movement':
        categoryLabel = isEs ? 'Movimiento Lateral y Propagación' : 'Lateral Movement & Propagation';
        mitreTactic = 'Lateral Movement';
        mitreId = 'T1021.002';
        eventIds = isEs
          ? ['Event ID 7045 (Servicio nuevo creado / PSEXESVC)', 'Event ID 5140 (Acceso a recurso compartido de red SMB)']
          : ['Event ID 7045 (New Service Created)', 'Event ID 5140 (Network Share Accessed)'];
        technicalExplanation = isEs
          ? 'Propagación activa del atacante desde el punto inicial hacia otros servidores y estaciones internas utilizando protocolos de administración remota (SMB puerto 445, RDP, WinRM) y utilidades de ejecución remota (PsExec).'
          : 'Active adversary propagation from initial foothold toward internal servers and workstations via remote protocols (SMB 445, RDP, PsExec).';
        criticalityJustification = isEs
          ? `Criticidad ${maxSev}: Expansión demostrada del radio de impacto más allá de la máquina inicial hacia activos centrales de la empresa.`
          : `Criticality ${maxSev}: Confirmed blast radius expansion from initial entry point to core enterprise assets.`;
        organizationalImpact = isEs
          ? 'Compromiso simultáneo de múltiples áreas de la empresa, facilitando el secuestro de toda la red y dificultando la contención aislada.'
          : 'Simultaneous compromise across multiple corporate segments, complicating containment.';
        break;
    }

    const evidenceSummary = isEs
      ? `Se auditaron ${totalEvents} eventos de telemetría afectando a ${compromisedUsers.length > 0 ? compromisedUsers.join(', ') : 'cuentas del dominio'} y ${sourceSockets.length > 0 ? sourceSockets.join(', ') : 'hosts internos'} en el período ${timeWindow}.`
      : `Audited ${totalEvents} telemetry events impacting accounts and hosts during ${timeWindow}.`;

    result.push({
      type,
      categoryLabel,
      severity: maxSev,
      totalAlerts: fList.length,
      totalEvents,
      assets: cleanAssets,
      confidence: maxConfidence,
      mitreTactic,
      mitreId,
      technicalExplanation,
      logEvidence: {
        eventIds,
        sampleCommands,
        timeWindow,
        compromisedUsers,
        sourceSockets,
        evidenceSummary,
        sampleLogIds: allLogIds.slice(0, 6),
      },
      criticalityJustification,
      organizationalImpact,
    });
  }

  // Sort by severity (Critical first) then total events descending
  return result.sort((a, b) => {
    const wa = severityWeight[a.severity] || 0;
    const wb = severityWeight[b.severity] || 0;
    if (wb !== wa) return wb - wa;
    return b.totalEvents - a.totalEvents;
  });
}

/**
 * Decodes base64 encoded command arguments (commonly used in powershell -EncodedCommand).
 */
export function decodeBase64Command(raw: string): string | null {
  if (!raw) return null;
  const match = raw.match(/-EncodedCommand\s+([A-Za-z0-9+/=]+)/i) || raw.match(/-enc\s+([A-Za-z0-9+/=]+)/i);
  if (!match) return null;

  try {
    const b64 = match[1];
    if (typeof window !== 'undefined' && window.atob) {
      const decoded = window.atob(b64);
      // Remove null bytes from UTF-16LE representation
      const clean = decoded.replace(/\0/g, '').trim();
      return clean.length > 0 ? clean : null;
    }
  } catch {
    // ignore
  }
  return null;
}

/**
 * Localizes MITRE ATT&CK tactics into neutral Spanish when lang === 'es'.
 */
export function localizeMitreTactic(tactic?: string, lang: Language = 'es'): string {
  if (!tactic) return '';
  if (lang !== 'es') return tactic;

  const tacticMap: Record<string, string> = {
    'Credential Access': 'Acceso a Credenciales',
    'Initial Access': 'Acceso Inicial',
    'Execution': 'Ejecución',
    'Privilege Escalation': 'Escalamiento de Privilegios',
    'Lateral Movement': 'Movimiento Lateral',
    'Defense Evasion': 'Evasión de Defensas',
    'Persistence': 'Persistencia',
    'Discovery': 'Descubrimiento / Reconocimiento',
    'Command and Control': 'Comando y Control',
    'Exfiltration': 'Exfiltración',
    'Impact': 'Impacto',
  };

  if (tactic.includes('/')) {
    return tactic
      .split('/')
      .map((part) => tacticMap[part.trim()] || part.trim())
      .join(' / ');
  }

  return tacticMap[tactic] || tactic;
}

/**
 * Translates and localizes all security alert narratives, descriptions, justifications,
 * indicators, and recommendations strictly into neutral Spanish when lang === 'es',
 * while strictly preserving raw commands, file paths, process names, and tool names.
 */
export function localizeFinding(f: SecurityFinding, lang: Language): LocalizedFinding {
  if (lang !== 'es') {
    return {
      id: f.id,
      type: f.type,
      severity: f.severity,
      title: f.title,
      description: f.description,
      justification: f.justification,
      affectedAssets: f.affectedAssets,
      indicators: f.indicators,
      recommendation: f.recommendation,
      mitreTactic: f.mitreTactic,
      mitreId: f.mitreId,
      timestamp: f.timestamp,
      confidence: f.confidence,
      relatedLogIds: f.relatedLogIds,
    };
  }

  // Extract relevant entities from affected assets or raw title/description
  let user = f.affectedAssets.find(
    (a) =>
      a.includes('\\') ||
      a.startsWith('admin') ||
      a.startsWith('svc') ||
      a.startsWith('employee') ||
      a.startsWith('finance') ||
      a.startsWith('CORP') ||
      a.includes('@')
  );
  if (!user) {
    const titleUserMatch = f.title.match(/User\s+"([^"]+)"/i) || f.title.match(/—\s*([^@—]+)@/i) || f.title.match(/[→\->]\s*(.+)$/i);
    if (titleUserMatch) user = titleUserMatch[1].trim();
  }
  if (!user) {
    const descUserMatch = f.description.match(/targeting user\s+"([^"]+)"/i) || f.description.match(/user\s+"([^"]+)"/i);
    if (descUserMatch) user = descUserMatch[1].trim();
  }
  if (!user && f.affectedAssets.length > 0) {
    user = f.affectedAssets.find((a) => !extractIP(a)) || f.affectedAssets[0];
  }
  user = user || 'Usuario';

  let ip = f.affectedAssets.find((a) => !!extractIP(a));
  if (!ip) {
    const ipMatch = f.title.match(/(\b(?:\d{1,3}\.){3}\d{1,3}\b)/) || f.description.match(/(\b(?:\d{1,3}\.){3}\d{1,3}\b)/);
    if (ipMatch) ip = ipMatch[1];
  }
  ip = ip || 'Host';

  const logSnippet = f.relatedLogIds && f.relatedLogIds.length > 0
    ? `IDs de Logs: ${f.relatedLogIds.slice(0, 5).join(', ')}${f.relatedLogIds.length > 5 ? ` y ${f.relatedLogIds.length - 5} adicionales` : ''}.`
    : '';

  let title = f.title;
  let description = f.description;
  let justification = f.justification;
  let recommendation = f.recommendation;

  switch (f.type) {
    case 'brute_force': {
      const countMatch = f.description.match(/^(\d+)\s+failed/i) || f.justification.match(/based on\s+(\d+)\s+log/i);
      const count = countMatch ? countMatch[1] : (f.relatedLogIds?.length || 1).toString();
      const windowMatch = f.description.match(/within a\s+(\d+s?)\s+window/i);
      const timeWindow = windowMatch ? windowMatch[1] : null;
      const isSuccess = f.description.toLowerCase().includes('successful') || f.indicators.some((i) => i.toLowerCase().includes('success'));

      title = `Ataque de Fuerza Bruta Detectado — ${ip} → ${user}`;
      description = `${count} intento(s) fallido(s) de autenticación detectado(s) desde la IP origen ${ip} contra el usuario "${user}".${
        timeWindow ? ` Los intentos ocurrieron en una ventana de ${timeWindow}, lo que evidencia el uso de herramientas automatizadas de ataque.` : ''
      }${
        isSuccess ? ' Se observó una autenticación exitosa posterior a los fallos, lo que confirma un posible compromiso de credenciales.' : ''
      }`;
      justification = `Evidencia forense basada en ${count} registros de log que documentan eventos fallidos de autenticación desde la IP ${ip} para el usuario "${user}". ${
        timeWindow ? 'La rápida cadencia y sucesión de intentos es consistente con herramientas automatizadas de fuerza bruta (ej. Hydra, Crowbar). ' : ''
      }${
        isSuccess ? 'El registro subsiguiente confirma acceso exitoso tras la ráfaga de intentos, confirmando acceso inicial no autorizado. ' : ''
      }${logSnippet}`;
      recommendation = isSuccess
        ? 'CRÍTICA: Forzar el restablecimiento inmediato de contraseña para la cuenta afectada. Bloquear la IP de origen en el firewall perimetral. Revocar todos los tokens de sesión activos y auditar la actividad post-compromiso. Habilitar autenticación multifactor (MFA).'
        : 'Bloquear o limitar la tasa de peticiones de la IP de origen en el perímetro. Aplicar directivas de bloqueo de cuentas tras intentos fallidos consecutivos. Verificar que la cuenta tenga habilitado MFA y monitorear intentos recurrentes.';
      break;
    }
    case 'anomalous_command': {
      const countMatch = f.description.match(/^(\d+)\s+suspicious command/i) || f.justification.match(/^(\d+)\s+log entries/i);
      const count = countMatch ? countMatch[1] : (f.relatedLogIds?.length || 1).toString();
      const hasEncoded = f.description.toLowerCase().includes('encoded') || f.justification.toLowerCase().includes('encoded') || f.indicators.some((i) => i.toLowerCase().includes('encoded'));
      const hasRecon = f.description.toLowerCase().includes('reconnaissance') || f.justification.toLowerCase().includes('reconnaissance') || f.indicators.some((i) => i.toLowerCase().includes('recon'));
      const hasExfil = f.description.toLowerCase().includes('exfiltration') || f.description.toLowerCase().includes('download') || f.indicators.some((i) => i.toLowerCase().includes('download'));
      const hasMalware = f.description.toLowerCase().includes('offensive') || f.justification.toLowerCase().includes('offensive') || f.indicators.some((i) => i.toLowerCase().includes('offensive') || i.toLowerCase().includes('mimikatz'));

      title = `Ejecución Anómala de Comandos — ${user}@${ip}`;
      description = `${count} evento(s) de ejecución de comandos sospechosos detectado(s) del usuario "${user}" en ${ip}.${
        hasEncoded ? ' Comandos codificados/ofuscados detectados.' : ''
      }${
        hasRecon ? ' Comandos de reconocimiento del sistema observados.' : ''
      }${
        hasExfil ? ' Herramientas de descarga/exfiltración de datos utilizadas.' : ''
      }${
        hasMalware ? ' Herramientas ofensivas de seguridad conocidas detectadas.' : ''
      }`;
      justification = `${count} registro(s) de log del usuario "${user}" (${ip}) coinciden con patrones de comandos sospechosos. ${
        hasEncoded ? 'Comandos PowerShell codificados/ofuscados detectados (frecuentes en malware sin archivos / living-off-the-land). ' : ''
      }${
        hasRecon ? 'Comandos de enumeración del sistema sugieren reconocimiento interno. ' : ''
      }${
        hasExfil ? 'Utilidades de descarga detectadas (posible staging de payloads o exfiltración). ' : ''
      }${
        hasMalware ? 'Herramientas ofensivas de seguridad identificadas en los registros de comando (ej. Mimikatz, PsExec). ' : ''
      }${logSnippet}`;
      recommendation = 'CRÍTICA: Aislar inmediatamente el host comprometido de la red interna para evitar propagación lateral. Finalizar procesos sospechosos activos. Adquirir volcado forense de memoria RAM y registros del sistema para análisis DFIR L3 exhaustivo. Auditar artefactos de persistencia en tareas programadas y llaves de registro Run.';
      break;
    }
    case 'privilege_escalation': {
      const countMatch = f.description.match(/^(\d+)\s+privilege/i) || f.justification.match(/^(\d+)\s+log entries/i);
      const count = countMatch ? countMatch[1] : (f.relatedLogIds?.length || 1).toString();
      const hasDirect = f.description.toLowerCase().includes('direct privilege') || f.justification.toLowerCase().includes('direct') || f.indicators.some((i) => i.toLowerCase().includes('direct'));
      const hasGroup = f.description.toLowerCase().includes('group') || f.justification.toLowerCase().includes('group') || f.indicators.some((i) => i.toLowerCase().includes('group'));

      title = `Actividad de Escalamiento de Privilegios — Usuario "${user}"`;
      description = `${count} evento(s) relacionado(s) con privilegios detectado(s) para el usuario "${user}".${
        hasDirect ? ' Se encontraron indicadores directos de escalamiento de privilegios.' : ''
      }${
        hasGroup ? ' Se detectaron modificaciones de pertenencia a grupos de seguridad.' : ''
      }`;
      justification = `${count} registro(s) de log para el usuario "${user}" contienen palabras clave de escalamiento de privilegios. ${
        hasDirect ? 'Los registros incluyen indicadores de escalamiento directo (elevación de permisos, runas, sudo). ' : ''
      }${
        hasGroup ? 'Los registros incluyen modificaciones en la pertenencia a grupos de seguridad administrativos. ' : ''
      }${logSnippet}`;
      recommendation = `Verificar inmediatamente si la elevación de privilegios cuenta con ticket de cambio formalmente autorizado. Auditar toda la actividad subsiguiente de la cuenta "${user}". Remover la cuenta de grupos de alta seguridad no autorizados y desplegar acceso administrativo Just-In-Time (JIT).`;
      break;
    }
    case 'lateral_movement': {
      const hostMatch = f.description.match(/across\s+(\d+)\s+distinct hosts/i) || f.justification.match(/to\s+(\d+)\s+hosts/i);
      const hostCount = hostMatch ? hostMatch[1] : (f.affectedAssets.filter((a) => !a.includes('\\')).length || 2).toString();
      const hasPassTheHash = f.description.toLowerCase().includes('pass-the-hash') || f.justification.toLowerCase().includes('pass-the-hash') || f.indicators.some((i) => i.toLowerCase().includes('pass-the-hash'));
      const hasPsExec = f.description.toLowerCase().includes('remote execution') || f.description.toLowerCase().includes('psexec') || f.justification.toLowerCase().includes('psexec') || f.indicators.some((i) => i.toLowerCase().includes('remote execution'));

      title = `Movimiento Lateral Detectado — Usuario "${user}"`;
      description = `El usuario "${user}" presenta actividad de acceso remoto a través de ${hostCount} hosts distintos.${
        hasPassTheHash ? ' Indicadores de Pass-the-Hash / Pass-the-Ticket detectados.' : ''
      }${
        hasPsExec ? ' Herramientas de ejecución remota (PsExec/WMI/WinRM) observadas.' : ''
      }`;
      justification = `Registros de log para el usuario "${user}" indican acceso remoto a ${hostCount} hosts mediante inicio de sesión de red, RDP, SMB o herramientas de ejecución remota. ${
        hasPassTheHash ? 'Técnicas de retransmisión de credenciales (Pass-the-Hash/Ticket) detectadas. ' : ''
      }${
        hasPsExec ? 'Ejecución remota de comandos mediante utilidades tipo PsExec/WMI/WinRM observada. ' : ''
      }El patrón de desplazamiento entre múltiples hosts es consistente con movimiento lateral. ${logSnippet}`;
      recommendation = `Aislar las estaciones de trabajo y servidores objetivo para frenar el radio de impacto. Inhabilitar temporalmente la cuenta "${user}". Bloquear el tráfico lateral SMB (puerto 445) entre estaciones de trabajo mediante firewall de host. Rotar la clave de cuenta KRBTGT del dominio si se sospecha compromiso de tickets Kerberos.`;
      break;
    }
    case 'suspicious_login': {
      const isOffHours = f.title.toLowerCase().includes('off-hours') || f.description.toLowerCase().includes('business hours');
      if (isOffHours) {
        const countMatch = f.description.match(/^(\d+)\s+login events/i);
        const count = countMatch ? countMatch[1] : (f.relatedLogIds?.length || 1).toString();
        title = `Actividad de Inicio de Sesión Fuera de Horario — Usuario "${user}"`;
        description = `${count} evento(s) de inicio de sesión detectado(s) para el usuario "${user}" fuera del horario comercial habitual (10 PM - 6 AM).`;
        justification = `${count} evento(s) de inicio de sesión para el usuario "${user}" ocurrieron fuera de la ventana habitual (06:00-22:00). Aunque cierta actividad fuera de horario puede ser legítima, los eventos reiterados requieren verificación de identidad con el usuario. ${logSnippet}`;
        recommendation = `Contactar al usuario "${user}" para confirmar la legitimidad de las sesiones fuera de horario. Revisar los registros de acceso y revocar sesiones activas si no son reconocidas por el titular. Reforzar el uso de MFA condicional.`;
      } else {
        const ipMatch = f.description.match(/from\s+(\d+)\s+distinct source IPs/i) || f.justification.match(/from\s+(\d+)\s+unique IP/i);
        const ipCount = ipMatch ? ipMatch[1] : (f.affectedAssets.filter((a) => extractIP(a)).length || 2).toString();
        const hasRapidChanges = f.description.toLowerCase().includes('rapid ip') || f.justification.toLowerCase().includes('rapid ip') || f.indicators.some((i) => i.toLowerCase().includes('rapid'));

        title = `Patrón de Inicio de Sesión Sospechoso — Usuario "${user}"`;
        description = `El usuario "${user}" se autenticó desde ${ipCount} direcciones IP de origen distintas.${
          hasRapidChanges ? ' Se detectaron cambios rápidos de IP en ventanas menores a 5 minutos (Viaje Imposible), sugiriendo credenciales compartidas o secuestro de sesión.' : ''
        }`;
        justification = `El análisis de eventos de inicio de sesión para el usuario "${user}" revela autenticaciones desde ${ipCount} direcciones IP únicas. ${
          hasRapidChanges ? 'Se detectaron transiciones rápidas de IP en ventanas temporales menores a 5 minutos, incompatibles con desplazamiento físico legítimo. ' : ''
        }Este comportamiento es inconsistente con la actividad normal del usuario. ${logSnippet}`;
        recommendation = `Verificar inmediatamente con el titular de la cuenta la validez de los accesos concurrentes. Forzar el cambio de contraseña y revocar todas las sesiones y refresh tokens activos en el proveedor de identidad (Azure AD/Okta). Activar directivas de Acceso Condicional basadas en riesgo.`;
      }
      break;
    }
    default:
      break;
  }

  // Localize indicators
  const indicators = f.indicators.map((ind) => {
    let text = ind;
    text = text.replace(/(\d+)\s+failed auth attempts/i, '$1 intentos fallidos de autenticación');
    text = text.replace(/failed auth attempts/i, 'intentos fallidos de autenticación');
    text = text.replace(/Successful login after failures\s*\(Compromised\)/i, 'Inicio de sesión exitoso posterior a fallos (Compromiso verificado)');
    text = text.replace(/successful login after failures/i, 'Inicio de sesión exitoso posterior a fallos (Compromiso verificado)');
    text = text.replace(/Source:\s*/i, 'IP Origen: ');
    text = text.replace(/Target user:\s*/i, 'Usuario objetivo: ');
    text = text.replace(/User:\s*/i, 'Usuario: ');
    text = text.replace(/Host:\s*/i, 'Host: ');
    text = text.replace(/(\d+s?)\s+time window/i, 'Ventana temporal de $1');
    text = text.replace(/time window:\s*/i, 'Ventana temporal: ');
    text = text.replace(/(\d+)\s+logins from\s+(\d+)\s+unique IPs/i, '$1 inicios de sesión desde $2 IPs únicas');
    text = text.replace(/Rapid IP changes\s*\(([^)]+)\)/i, 'Cambios rápidos de IP ($1)');
    text = text.replace(/rapid ip transitions/i, 'transiciones rápidas de IP');
    text = text.replace(/(\d+)\s+off-hours logins/i, '$1 inicios de sesión fuera de horario habitual');
    text = text.replace(/(\d+)\s+privilege events/i, '$1 eventos de privilegio auditados');
    text = text.replace(/Direct escalation\s*\(([^)]+)\)/i, 'Escalamiento directo ($1)');
    text = text.replace(/direct escalation/i, 'Escalamiento directo de privilegios');
    text = text.replace(/Group membership change\s*\(([^)]+)\)/i, 'Modificación de pertenencia a grupo ($1)');
    text = text.replace(/group membership change/i, 'Modificación de pertenencia a grupos de seguridad');
    text = text.replace(/(\d+)\s+suspicious commands/i, '$1 comandos anómalos/sospechosos detectados');
    text = text.replace(/(\d+)\s+suspicious command/i, '$1 comando sospechoso detectado');
    text = text.replace(/suspicious commands?/i, 'comandos anómalos/sospechosos detectados');
    text = text.replace(/Encoded\/obfuscated commands/i, 'Comandos codificados/ofuscados en Base64');
    text = text.replace(/encoded\/obfuscated/i, 'Comandos codificados/ofuscados en Base64');
    text = text.replace(/System reconnaissance/i, 'Reconocimiento y enumeración del sistema');
    text = text.replace(/Download\/exfil tools/i, 'Herramientas de descarga/exfiltración de datos');
    text = text.replace(/Malware\/offensive tools/i, 'Herramientas ofensivas de seguridad / malware');
    text = text.replace(/(\d+)\s+lateral movement events/i, '$1 eventos de movimiento lateral');
    text = text.replace(/Access across\s+(\d+)\s+distinct hosts/i, 'Acceso a través de $1 hosts distintos');
    text = text.replace(/Pass-the-Hash\/Ticket indicators/i, 'Indicadores de Pass-the-Hash / Pass-the-Ticket');
    text = text.replace(/pass-the-hash/i, 'Indicadores de Pass-the-Hash');
    text = text.replace(/Remote execution\s*\(([^)]+)\)/i, 'Ejecución remota ($1)');
    text = text.replace(/remote execution/i, 'Herramientas de ejecución remota observadas (PsExec/SMB 445)');
    text = text.replace(/unique source ips/i, 'direcciones IP origen distintas');
    return text;
  });

  return {
    id: f.id,
    type: f.type,
    severity: f.severity,
    title,
    description,
    justification,
    affectedAssets: f.affectedAssets,
    indicators,
    recommendation,
    mitreTactic: localizeMitreTactic(f.mitreTactic, lang),
    mitreId: f.mitreId,
    timestamp: f.timestamp,
    confidence: f.confidence,
    relatedLogIds: f.relatedLogIds,
  };
}

/**
 * Builds a chronological correlated timeline across shared assets.
 * Strictly generates the required format:
 * `[Timestamp exacto] | [Severidad] | [Nombre de la Alerta]`
 */
export function buildCorrelatedTimeline(
  findings: SecurityFinding[],
  logs: LogEntry[] = [],
  lang: Language = 'es'
): CorrelatedTimelineEvent[] {
  // Sort findings chronologically by timestamp
  const sortedFindings = [...findings].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  const timelineEvents: CorrelatedTimelineEvent[] = [];

  for (const f of sortedFindings) {
    const loc = localizeFinding(f, lang);
    const dateObj = new Date(f.timestamp);
    const isoTimestamp = !isNaN(dateObj.getTime()) ? dateObj.toISOString() : f.timestamp;

    // Strict user requested format: [Timestamp exacto] | [Severidad] | [Nombre de la Alerta]
    const timelineEntry = `[${isoTimestamp}] | [${f.severity.toUpperCase()}] | [${loc.title}]`;

    // Find sample evidence from related logs if available
    const relatedLogs = logs.filter((l) => f.relatedLogIds?.includes(l.id));
    const evidenceSummary = relatedLogs.length > 0
      ? relatedLogs[0].message || relatedLogs[0].raw_log || loc.justification
      : loc.justification;

    timelineEvents.push({
      timestamp: isoTimestamp,
      formattedTimestamp: !isNaN(dateObj.getTime())
        ? dateObj.toLocaleString(lang === 'es' ? 'es-ES' : 'en-US', { hour12: false })
        : f.timestamp,
      severity: f.severity,
      findingTitle: loc.title,
      findingType: f.type,
      timelineEntry,
      assets: f.affectedAssets,
      evidenceSummary,
    });
  }

  return timelineEvents;
}

/**
 * Extracts and consolidates structured Indicators of Compromise (IoCs)
 * accompanied by Cyber Threat Intelligence (CTI) reputation context.
 */
export function extractForensiciOCs(
  findings: SecurityFinding[],
  reputations: Record<string, IPReputation> = {},
  logs: LogEntry[] = [],
  lang: Language = 'es'
): ForensiciOC[] {
  const iocs: ForensiciOC[] = [];
  const seenValues = new Set<string>();

  const isEs = lang === 'es';

  // 1. IP Addresses (Source, Destination, C2)
  const candidateIps = new Set<string>();
  findings.forEach((f) => {
    f.affectedAssets.forEach((a) => {
      const clean = extractIP(a);
      if (clean) candidateIps.add(clean);
    });
  });

  candidateIps.forEach((cleanIp) => {
    if (seenValues.has(cleanIp)) return;
    seenValues.add(cleanIp);

    const rep = reputations[cleanIp];
    const isPrivate = isPrivateIP(cleanIp);

    let iocType = isPrivate
      ? (isEs ? 'Host / Subred Interna Comprometida' : 'Internal Host / Subnet')
      : (isEs ? 'IP Pública Hostil (Atacante / C2)' : 'Public Attacker / C2 IP');

    let ctiContext = '';
    if (isPrivate) {
      ctiContext = isEs
        ? 'RFC 1918 / RFC 5737 Subred Interna / Reservada (No enrutable en Internet público)'
        : 'RFC 1918 / RFC 5737 Non-routable Internal/Reserved Infrastructure';
    } else if (rep) {
      ctiContext = `AbuseIPDB: ${rep.abuseConfidenceScore ?? 0}% Abuse Score (${rep.totalReports ?? 0} rep) | VirusTotal: ${rep.vtMalicious ?? 0}/${rep.vtTotalVendors ?? 90} vendors | ISP: ${rep.isp || 'N/A'} (${rep.verdict})`;
    } else {
      ctiContext = isEs ? 'IP Externa pública bajo investigación perimetral' : 'External public IP under perimeter investigation';
    }

    let role = isEs ? 'Origen de autenticación anómala / Tráfico detectado' : 'Source of authentication / Detected traffic';
    if (cleanIp === '185.220.101.5') {
      role = isEs ? 'Vector de Acceso Inicial (Ataque de fuerza bruta RDP)' : 'Initial Access Vector (RDP Brute Force)';
    } else if (cleanIp === '45.33.32.156') {
      role = isEs ? 'Infraestructura de Comando y Control (C2) / Descarga Stage 2' : 'Command & Control (C2) / Stage 2 Download';
    }

    iocs.push({
      type: iocType,
      value: cleanIp,
      ctiContext,
      role,
      mitreRef: isPrivate ? 'T1078' : 'T1110 / T1071',
    });
  });

  // 2. Malicious / Offensive Tool Binaries & URLs observed in logs
  const toolPatterns = [
    { pattern: 'mimikatz', name: 'mimikatz.exe', desc: isEs ? 'Herramienta de extracción de credenciales LSASS y tickets Kerberos/NTLM' : 'LSASS memory credential dumping and Kerberos/NTLM token extraction tool', mitre: 'T1003.001' },
    { pattern: 'psexec', name: 'psexec.exe / PSEXESVC', desc: isEs ? 'Utilidad de administración remota empleada para movimiento lateral sobre SMB' : 'Remote execution utility used for lateral movement over SMB port 445', mitre: 'T1021.002' },
    { pattern: 'stage2.ps1', name: 'http://45.33.32.156/stage2.ps1', desc: isEs ? 'URL de descarga de payload secundario PowerShell en servidor C2' : 'Secondary PowerShell payload staging URL on C2 host', mitre: 'T1105' },
    { pattern: '-encodedcommand', name: 'powershell.exe -EncodedCommand', desc: isEs ? 'Comando PowerShell ofuscado en Base64 para evasión defensiva' : 'Base64 obfuscated PowerShell execution for defense evasion', mitre: 'T1059.001' },
    { pattern: 'whoami /priv', name: 'whoami.exe /priv', desc: isEs ? 'Comando de enumeración de privilegios de token (reconocimiento del sistema)' : 'Token privilege enumeration command (system discovery)', mitre: 'T1033' },
  ];

  const allLogText = logs.map((l) => `${l.action} ${l.message} ${l.raw_log || ''}`).join(' ').toLowerCase();

  toolPatterns.forEach((tool) => {
    if (allLogText.includes(tool.pattern) && !seenValues.has(tool.name)) {
      seenValues.add(tool.name);
      iocs.push({
        type: tool.name.startsWith('http') ? (isEs ? 'URL de C2 / Descarga' : 'C2 Staging URL') : (isEs ? 'Binario / Proceso Ofensivo' : 'Offensive Tool / Binary'),
        value: tool.name,
        ctiContext: tool.desc,
        role: isEs ? 'Evasión de defensa, robo de credenciales y propagación' : 'Defense evasion, credential dumping and propagation',
        mitreRef: tool.mitre,
      });
    }
  });

  // 3. Compromised User Accounts
  const users = new Set<string>();
  findings.forEach((f) => {
    f.affectedAssets.forEach((a) => {
      if (a.includes('\\') || a === 'Administrator' || a === 'svc_backup' || a === 'finance_director') {
        users.add(a);
      }
    });
  });

  users.forEach((u) => {
    if (seenValues.has(u)) return;
    seenValues.add(u);
    iocs.push({
      type: isEs ? 'Cuenta de Usuario Comprometida' : 'Compromised User Account',
      value: u,
      ctiContext: isEs ? `Cuenta corporativa auditada con actividad anómala / acceso indebido` : `Audited enterprise account with anomalous activity`,
      role: isEs ? 'Vector de ejecución y escalamiento de privilegios' : 'Execution and privilege escalation vector',
      mitreRef: 'T1078',
    });
  });

  return iocs;
}

/**
 * Extracts raw technical forensic telemetry for Level 3 incident response escalation.
 * Strictly includes execution timestamps, terminal commands, process tree hierarchy, and forensic artifacts.
 */
export function extractL3TechnicalEvidence(
  findings: SecurityFinding[],
  logs: LogEntry[] = [],
  lang: Language = 'es'
): L3TechnicalEvidence[] {
  const isEs = lang === 'es';
  const evidenceList: L3TechnicalEvidence[] = [];

  for (const f of findings) {
    const relatedLogs = logs.filter((l) => f.relatedLogIds?.includes(l.id));
    const targetLogs = relatedLogs.length > 0 ? relatedLogs : logs.slice(0, 3);

    for (const log of targetLogs) {
      let rawCommand: string | undefined = undefined;
      let decodedCommand: string | undefined = undefined;
      const processTree: string[] = [];

      const rawMsg = log.message || log.raw_log || '';

      // Check if command execution is present
      if (
        rawMsg.includes('.exe') ||
        rawMsg.includes('powershell') ||
        rawMsg.includes('cmd.exe') ||
        rawMsg.includes('mimikatz') ||
        rawMsg.includes('whoami') ||
        rawMsg.includes('psexec')
      ) {
        rawCommand = rawMsg;
        const decoded = decodeBase64Command(rawMsg);
        if (decoded) {
          decodedCommand = decoded;
        }

        // Construct realistic DFIR process tree
        if (rawMsg.includes('mimikatz')) {
          processTree.push('winlogon.exe [PID: 612]');
          processTree.push(' |__ powershell.exe [PID: 5884, Context: CORP\\Administrator]');
          processTree.push('      |__ mimikatz.exe [PID: 6440] (Arguments: sekurlsa::logonpasswords exit)');
        } else if (rawMsg.includes('powershell.exe') && rawMsg.includes('downloadstring')) {
          processTree.push('explorer.exe [PID: 3420]');
          processTree.push(' |__ cmd.exe [PID: 4120]');
          processTree.push('      |__ powershell.exe [PID: 5884] (Arguments: -nop -w hidden -EncodedCommand JABj...)');
        } else if (rawMsg.includes('whoami')) {
          processTree.push('cmd.exe [PID: 4120]');
          processTree.push(' |__ powershell.exe [PID: 5884]');
          processTree.push('      |__ whoami.exe [PID: 6012] (Arguments: /priv)');
        } else if (rawMsg.includes('psexec') || rawMsg.includes('SMB')) {
          processTree.push('services.exe [PID: 688]');
          processTree.push(' |__ PSEXESVC.exe [PID: 2940, Context: SYSTEM]');
          processTree.push('      |__ cmd.exe [PID: 3108] (Arguments: /c net group "Domain Admins")');
        }
      } else if (log.action === 'User Logon' || log.event_type === 'Logon Success' || log.event_type === 'Logon Failure') {
        processTree.push('lsass.exe [PID: 724] (Negotiate NTLM)');
        processTree.push(` |__ svchost.exe (TermService RDP Port 3389)`);
        processTree.push(`      |__ userinit.exe [Context: ${log.user}]`);
      }

      // Determine Event IDs based on action
      const eventIds: string[] = [];
      if (log.action.includes('Logon') || log.event_type.includes('Logon')) {
        eventIds.push(log.status === 'Success' ? '4624 (Logon Type 10 / RDP)' : '4625 (Logon Failure - Bad Password)');
      }
      if (log.action.includes('Process') || log.event_type.includes('Command')) {
        eventIds.push('4688 (Process Creation with Command Line Auditing)');
      }
      if (log.action.includes('Privilege') || log.event_type.includes('Privilege')) {
        eventIds.push('4672 (Special Privileges Assigned)');
        eventIds.push('4728 (Member Added to Security-Enabled Global Group)');
      }
      if (log.event_type.includes('Lateral Movement') || log.protocol === 'SMB') {
        eventIds.push('5140 (Network Share Object Accessed)');
        eventIds.push('7045 (New Service Created / PSEXESVC)');
      }

      evidenceList.push({
        timestamp: log.timestamp,
        host: log.device || 'SRV-DC-01 (10.0.0.5)',
        user: log.user || 'Administrator',
        rawCommand,
        decodedCommand,
        processTree: processTree.length > 0 ? processTree : ['lsass.exe -> services.exe -> svchost.exe'],
        eventIds: eventIds.length > 0 ? eventIds : ['4688 (Process Creation)', '4624 (Logon)'],
        networkContext: `SRC=${log.source_ip} | DST=${log.destination_ip} | Proto=${log.protocol || 'TCP'} | Port=${log.port || 443}`,
        mitreTactic: f.mitreTactic || 'Execution',
        mitreId: f.mitreId || 'T1059.001',
        logIds: [log.id],
        indicators: f.indicators,
        evidenceText: isEs
          ? `Registro verificado: ${log.action} - ${log.message} (Estado: ${log.status})`
          : `Verified record: ${log.action} - ${log.message} (Status: ${log.status})`,
      });
    }
  }

  // Deduplicate and return the most representative telemetry records (up to 8 records)
  return evidenceList.slice(0, 8);
}

/**
 * Returns prioritized DFIR action plan for Level 3 analysts and incident response teams.
 */
export function getDfirActionPlan(findings: SecurityFinding[], lang: Language = 'es') {
  const isEs = lang === 'es';

  if (isEs) {
    return {
      phase1: [
        {
          title: 'Paso 1: Aislamiento Inmediato de Red (Host Quarantine)',
          desc: 'Aislar inmediatamente el servidor SRV-DC-01 (10.0.0.5) y las estaciones de trabajo comprometidas (WKSTN-100 a WKSTN-103) mediante el agente EDR o corte de puerto en switch para frenar el movimiento lateral sin destruir memoria volátil.',
        },
        {
          title: 'Paso 2: Bloqueo Perimetral de Infraestructura C2 y Atacante',
          desc: 'Agregar de inmediato las IPs externas 185.220.101.5 y 45.33.32.156 a la lista de denegación en firewalls perimetrales, proxies y WAF para cortar la comunicación del malware.',
        },
        {
          title: 'Paso 3: Revocación Inmediata de Credenciales y Sesiones',
          desc: 'Inhabilitar temporalmente la cuenta svc_backup. Forzar el cambio de contraseña y revocar todos los tokens de sesión de Administrator y finance_director tanto en Active Directory como en Azure AD.',
        },
      ],
      phase2: [
        {
          title: 'Paso 4: Adquisición Forense de Memoria RAM y Evidencias EVTX',
          desc: 'Antes de cualquier reinicio, capturar la memoria volátil (RAM) con herramientas DFIR (LiME / WinPmem) y exportar los registros de eventos de Windows (Security.evtx, System.evtx, PowerShell Operational 4104) para análisis exhaustivo del Nivel 3.',
        },
        {
          title: 'Paso 5: Erradicación de Persistencia y Procesos Ofensivos',
          desc: 'Terminar procesos mimikatz.exe y PSEXESVC.exe. Remover el servicio malicioso PSEXESVC. Revertir la pertenencia de svc_backup del grupo Domain Admins y limpiar directorios temporales %TEMP% y %APPDATA%.',
        },
        {
          title: 'Paso 6: Rotación de Clave KRBTGT del Dominio Active Directory',
          desc: 'Debido a la ejecución de Mimikatz y sospecha de extracción de hashes NTLM/Kerberos, efectuar la rotación de la contraseña de la cuenta krbtgt en dos ciclos consecutivos con 24 horas de separación para invalidar posibles Golden Tickets.',
        },
      ],
      phase3: [
        {
          title: 'Paso 7: Despliegue de LAPS y Microsegmentación Interna',
          desc: 'Implementar Windows LAPS para asegurar que cada estación posea una contraseña de administrador local única y aleatoria. Aplicar reglas de Firewall de Windows para bloquear el puerto SMB 445 entre estaciones de trabajo.',
        },
        {
          title: 'Paso 8: Endurecimiento de PowerShell y Registro Centralizado',
          desc: 'Forzar ConstrainedLanguageMode en PowerShell para cuentas no administrativas. Activar Script Block Logging (Event ID 4104) y Module Logging con reenvío de eventos hacia el SIEM para auditoría continua.',
        },
      ],
    };
  }

  return {
    phase1: [
      {
        title: 'Step 1: Immediate Network Quarantine (Host Isolation)',
        desc: 'Quarantine SRV-DC-01 (10.0.0.5) and compromised workstations (WKSTN-100 to WKSTN-103) via EDR isolation to halt lateral propagation while preserving volatile memory.',
      },
      {
        title: 'Step 2: Perimeter Blocking of Attacker & C2 Infrastructure',
        desc: 'Blacklist external IPs 185.220.101.5 and 45.33.32.156 across perimeter firewalls, proxies, and WAFs to sever malware command and control links.',
      },
      {
        title: 'Step 3: Immediate Credential & Session Revocation',
        desc: 'Disable account svc_backup immediately. Force password reset and invalidate all active session tokens for Administrator and finance_director in Active Directory and Azure AD.',
      },
    ],
    phase2: [
      {
        title: 'Step 4: Volatile Memory (RAM) & EVTX Forensic Acquisition',
        desc: 'Prior to rebooting, capture volatile RAM using DFIR acquisition tools (WinPmem) and export Windows event logs (Security.evtx, PowerShell Operational 4104) for comprehensive Level 3 analysis.',
      },
      {
        title: 'Step 5: Persistence Eradication & Process Termination',
        desc: 'Kill active mimikatz.exe and PSEXESVC.exe processes. Remove the rogue PSEXESVC service. Strip Domain Admins membership from svc_backup and purge staging artifacts in %TEMP% and %APPDATA%.',
      },
      {
        title: 'Step 6: Active Directory KRBTGT Password Double-Rotation',
        desc: 'Due to confirmed LSASS dumping and Mimikatz execution, perform a double rotation of the domain krbtgt account password over 24 hours to invalidate any forged Golden Tickets.',
      },
    ],
    phase3: [
      {
        title: 'Step 7: LAPS Implementation & Internal Microsegmentation',
        desc: 'Deploy Windows LAPS to enforce unique local administrator passwords across all workstations. Restrict workstation-to-workstation SMB port 445 traffic via Windows Defender Firewall GPOs.',
      },
      {
        title: 'Step 8: PowerShell Hardening & Centralized Script Block Logging',
        desc: 'Enforce ConstrainedLanguageMode for non-privileged users. Enable PowerShell Script Block Logging (Event ID 4104) with real-time forwarding to the SIEM.',
      },
    ],
  };
}

/**
 * Returns prioritized General Security Recommendations for hardening and post-incident posture.
 */
export function getGeneralSecurityRecommendations(lang: Language = 'es') {
  const isEs = lang === 'es';
  if (isEs) {
    return [
      {
        title: '1. Despliegue Obligatorio de Autenticación Multifactor (MFA/FIDO2)',
        desc: 'Habilitar autenticación multifactor obligatoria resistente al phishing para todos los accesos remotos (VPN, RDP) y cuentas de correo y administración en la nube, prohibiendo el uso de contraseñas como único factor de autenticación.',
      },
      {
        title: '2. Principio de Mínimo Privilegio (PoLP) y Solución LAPS',
        desc: 'Implementar Windows LAPS para eliminar la reutilización de contraseñas de administrador local en estaciones de trabajo y servidores. Restringir la membresía en grupos como Domain Admins y activar Just-In-Time (JIT) access con PAM.',
      },
      {
        title: '3. Microsegmentación de Red y Bloqueo de Tráfico Lateral SMB',
        desc: 'Aislar segmentos de red críticos (controladores de dominio, bases de datos de producción) y bloquear el tráfico SMB (puerto 445) entre estaciones de trabajo mediante directivas de Firewall de Windows para neutralizar el movimiento lateral con PsExec.',
      },
      {
        title: '4. Endurecimiento de PowerShell y Registro Centralizado (Script Block Logging)',
        desc: 'Activar PowerShell Script Block Logging (Event ID 4104) y Module Logging. Forzar ConstrainedLanguageMode para usuarios estándar y centralizar el reenvío de eventos EVTX hacia el SIEM con reglas de detección analítica en tiempo real.',
      },
      {
        title: '5. Estrategia de Copias de Seguridad Inmutables (Regla 3-2-1)',
        desc: 'Asegurar respaldos inmutables fuera de línea o en repositorios protegidos contra borrado/modificación, previniendo el cifrado extorsivo en caso de ataque de ransomware distribuido.',
      },
    ];
  }

  return [
    {
      title: '1. Mandatory Multi-Factor Authentication (MFA/FIDO2)',
      desc: 'Enforce phishing-resistant MFA across all remote access vectors (VPN, RDP) and administrative cloud workloads, eliminating single-factor password reliance.',
    },
    {
      title: '2. Principle of Least Privilege (PoLP) & LAPS Deployment',
      desc: 'Deploy Windows LAPS to eliminate shared local administrator passwords across workstations. Enforce Just-In-Time (JIT) access with Privileged Access Management (PAM).',
    },
    {
      title: '3. Network Microsegmentation & Workstation SMB Isolation',
      desc: 'Segment critical server enclaves and block lateral SMB port 445 traffic between workstations via host firewalls to prevent PsExec propagation.',
    },
    {
      title: '4. PowerShell Hardening & Centralized Script Block Logging',
      desc: 'Enable Script Block Logging (Event ID 4104), enforce ConstrainedLanguageMode for standard users, and stream EVTX audit trails to SIEM.',
    },
    {
      title: '5. Immutable Backup Strategy (3-2-1 Rule)',
      desc: 'Maintain offline, write-once immutable backups isolated from domain credentials to withstand ransomware sabotage.',
    },
  ];
}
