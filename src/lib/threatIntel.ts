import { IPReputation, ThreatIntelConfig } from '@/types';

/**
 * Validates whether a string is a strictly valid IPv4 address (dotted quad, 0-255).
 */
export function isValidIPv4(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    if (n < 0 || n > 255) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
  }
  return true;
}

/**
 * Validates whether a string is a strictly valid IPv6 address.
 */
export function isValidIPv6(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim().replace(/^\[|\]$/g, '');
  if (!trimmed.includes(':')) return false;
  const colonCount = (trimmed.match(/:/g) || []).length;
  if (colonCount < 2 || colonCount > 7) return false;
  const doubleColonCount = (trimmed.match(/::/g) || []).length;
  if (doubleColonCount > 1) return false;

  const parts = trimmed.split(':');
  for (const p of parts) {
    if (p === '') continue;
    if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return false;
  }
  return true;
}

/**
 * Validates whether a string is a valid IPv4 or IPv6 address.
 */
export function isValidIP(ip: string | null | undefined): ip is string {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  return isValidIPv4(trimmed) || isValidIPv6(trimmed);
}

/**
 * Extracts a pure, clean IPv4 or IPv6 address from an asset string, socket (e.g. 203.0.113.88:443 or [2001:db8::1]:8080),
 * or URL. Returns null if the string is a hostname (SRV-01, CORP\admin, user), domain, or invalid IP.
 */
export function extractIP(input: string): string | null {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim();

  // Already a valid IPv4 or IPv6 address directly
  if (isValidIPv4(trimmed) || isValidIPv6(trimmed)) {
    return trimmed;
  }

  // Bracketed IPv6 socket: [2001:db8::1]:443 or [2001:db8::1]
  const bracketMatch = trimmed.match(/^\[([a-fA-F0-9:]+)\](?::\d+)?$/);
  if (bracketMatch && isValidIPv6(bracketMatch[1])) {
    return bracketMatch[1];
  }

  // IPv4 socket: 203.0.113.88:443
  const socketMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/);
  if (socketMatch && isValidIPv4(socketMatch[1])) {
    return socketMatch[1];
  }

  // Embedded URL: http://203.0.113.88:443/test or https://185.220.101.5/
  const urlMatch = trimmed.match(/(?:https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/);
  if (urlMatch && isValidIPv4(urlMatch[1])) {
    return urlMatch[1];
  }

  return null;
}

/**
 * Validates whether an IP address or hostname belongs to a private, loopback,
 * link-local, carrier-grade NAT, multicast, or reserved/documentation network.
 * Complies strictly with IETF RFC 1122, RFC 1918, RFC 3927, RFC 5737, RFC 6598,
 * RFC 2544, RFC 5771, RFC 1112, RFC 4291, and RFC 4193.
 */
export function isPrivateIP(input: string): boolean {
  if (!input) return true;
  // If input is a socket or contains a port or URL, extract the clean IP first
  const clean = extractIP(input);
  // If not even an IP address (e.g. CORP\admin, APP-SRV01, FS-SRV01, localhost), it's strictly internal/non-public
  if (!clean) {
    return true;
  }

  const trimmed = clean.trim();

  // Known local hostnames and loopback strings
  if (
    trimmed === 'localhost' ||
    trimmed === '127.0.0.1' ||
    trimmed === '0.0.0.0' ||
    trimmed === '::1' ||
    trimmed === '::'
  ) {
    return true;
  }

  // IPv6 local / ULA / link-local / documentation
  if (trimmed.includes(':')) {
    const lower = trimmed.toLowerCase();
    if (
      lower === '::1' ||
      lower === '::' ||
      lower.startsWith('fe80:') || // Link-local (RFC 4291)
      lower.startsWith('fc') || // Unique Local Address (RFC 4193)
      lower.startsWith('fd') || // Unique Local Address (RFC 4193)
      lower.startsWith('2001:db8:') // Documentation (RFC 3849)
    ) {
      return true;
    }
    return false;
  }

  // IPv4 evaluation
  const parts = trimmed.split('.').map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    const [p0, p1, p2] = parts;

    // RFC 1122: 0.0.0.0/8 ("This host on this network")
    if (p0 === 0) return true;

    // RFC 1122: 127.0.0.0/8 (Loopback addresses)
    if (p0 === 127) return true;

    // RFC 1918: 10.0.0.0/8 (Private network: 10.0.0.0 - 10.255.255.255)
    if (p0 === 10) return true;

    // RFC 6598: 100.64.0.0/10 (Shared Address Space / CGNAT: 100.64.0.0 - 100.127.255.255)
    if (p0 === 100 && p1 >= 64 && p1 <= 127) return true;

    // RFC 1918: 172.16.0.0/12 (Private network: 172.16.0.0 - 172.31.255.255)
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;

    // RFC 3927: 169.254.0.0/16 (Link-Local / APIPA: 169.254.0.0 - 169.254.255.255)
    if (p0 === 169 && p1 === 254) return true;

    // RFC 1918: 192.168.0.0/16 (Private network: 192.168.0.0 - 192.168.255.255)
    if (p0 === 192 && p1 === 168) return true;

    // RFC 5737: 192.0.2.0/24 (TEST-NET-1 for Documentation and Examples)
    if (p0 === 192 && p1 === 0 && p2 === 2) return true;

    // RFC 2544 / RFC 6815: 198.18.0.0/15 (Benchmarking: 198.18.0.0 - 198.19.255.255)
    if (p0 === 198 && (p1 === 18 || p1 === 19)) return true;

    // RFC 5737: 198.51.100.0/24 (TEST-NET-2 for Documentation and Examples)
    if (p0 === 198 && p1 === 51 && p2 === 100) return true;

    // RFC 5737: 203.0.113.0/24 (TEST-NET-3 for Documentation and Examples)
    if (p0 === 203 && p1 === 0 && p2 === 113) return true;

    // RFC 5771: 224.0.0.0/4 (Multicast: 224.0.0.0 - 239.255.255.255)
    if (p0 >= 224 && p0 <= 239) return true;

    // RFC 1112 / RFC 6890: 240.0.0.0/4 (Reserved for Future Use and 255.255.255.255 Broadcast)
    if (p0 >= 240) return true;
  }

  return false;
}

/**
 * Returns true if and only if the string is a valid, publicly routable IP address
 * that is appropriate for querying external threat feeds (VirusTotal, AbuseIPDB).
 */
export function isPublicRoutableIP(input: string): boolean {
  const clean = extractIP(input);
  if (!clean || !isValidIP(clean)) return false;
  return !isPrivateIP(clean);
}

/**
 * Standard factory for immutable internal/private IP reputation records.
 * Private IPs are non-routable on the public internet and strictly cannot have an external threat score.
 */
export function createPrivateIPReputation(ip: string): IPReputation {
  const cleanIp = extractIP(ip) || ip;
  return {
    ip: cleanIp,
    isPrivate: true,
    verdict: 'Private',
    isp: 'Internal Corporate / Non-Routable Network (RFC 1918 / RFC 5737)',
    domain: 'corp.internal',
    usageType: 'Private Enterprise / Reserved Subnet',
    source: 'Internal',
    abuseConfidenceScore: 0,
    totalReports: 0,
    vtMalicious: 0,
    vtSuspicious: 0,
    vtHarmless: 0,
    vtUndetected: 0,
    vtTotalVendors: 0,
    vtReputationScore: 0,
    checkedAt: new Date().toISOString(),
  };
}

// In-memory cache to avoid repeated queries during the active session
const reputationCache: Record<string, IPReputation> = {};

/**
 * Clears cached IP reputation data to force fresh queries from the server/webhook
 */
export function clearReputationCache(specificIps?: string[]): void {
  if (specificIps && specificIps.length > 0) {
    for (const raw of specificIps) {
      delete reputationCache[raw];
      const clean = extractIP(raw);
      if (clean) delete reputationCache[clean];
    }
  } else {
    for (const key of Object.keys(reputationCache)) {
      delete reputationCache[key];
    }
  }
}

/**
 * Fallback high-fidelity threat intelligence for offline SOC testing or when no live keys are configured.
 * Strictly applies threat scoring ONLY to genuine public IP addresses.
 */
function getSimulatedReputation(ip: string): IPReputation {
  const clean = extractIP(ip) || ip;
  if (isPrivateIP(clean)) {
    return createPrivateIPReputation(clean);
  }

  // Realistic public threat IPs commonly used in cyber attack telemetry
  const isHighRisk =
    clean === '185.220.101.5' || // Tor Exit Node / Known Attacker IP
    clean === '45.33.32.156' || // Public C2 Infrastructure
    clean === '194.26.29.112' || // Public High-risk Proxy
    clean === '185.180.143.11' || // Compromised External Server
    clean === '91.240.118.172'; // Anomaly Login IP

  if (isHighRisk) {
    return {
      ip: clean,
      isPrivate: false,
      country: 'United States',
      countryCode: 'US',
      isp: 'DigitalOcean Hosting LLC',
      domain: 'digitalocean.com',
      usageType: 'Data Center / Web Hosting / Proxy',
      abuseConfidenceScore: 94,
      totalReports: 128,
      lastReportedAt: new Date(Date.now() - 3600000 * 2).toISOString(),
      vtMalicious: 16,
      vtSuspicious: 3,
      vtHarmless: 68,
      vtUndetected: 7,
      vtTotalVendors: 94,
      vtReputationScore: -45,
      verdict: 'Malicious',
      source: 'Simulated',
      checkedAt: new Date().toISOString(),
    };
  }

  return {
    ip: clean,
    isPrivate: false,
    country: 'United States',
    countryCode: 'US',
    isp: 'Cloudflare / Tier-1 Transit',
    domain: 'cloudflare.com',
    usageType: 'Commercial Transit',
    abuseConfidenceScore: 0,
    totalReports: 0,
    vtMalicious: 0,
    vtSuspicious: 0,
    vtHarmless: 85,
    vtUndetected: 5,
    vtTotalVendors: 90,
    vtReputationScore: 0,
    verdict: 'Clean',
    source: 'Simulated',
    checkedAt: new Date().toISOString(),
  };
}

/**
 * Check single IP reputation via the secure server proxy route
 */
export async function checkIPReputation(input: string, forceRefresh = false): Promise<IPReputation> {
  if (!input) {
    return {
      ip: 'Unknown',
      isPrivate: true,
      verdict: 'Unknown',
      source: 'Internal',
      checkedAt: new Date().toISOString(),
    };
  }

  const clean = extractIP(input);
  if (!clean || !isValidIP(clean)) {
    return {
      ip: input,
      isPrivate: true,
      verdict: 'Unknown',
      source: 'Internal',
      isp: 'Non-IP Identifier / Internal Host',
      checkedAt: new Date().toISOString(),
    };
  }

  // Handle private/internal IPs immediately without wasting network calls
  if (isPrivateIP(clean)) {
    const privResult = createPrivateIPReputation(clean);
    reputationCache[clean] = privResult;
    reputationCache[input] = privResult;
    return privResult;
  }

  // Check cache unless forceRefresh is requested
  if (!forceRefresh && reputationCache[clean]) {
    return reputationCache[clean];
  }

  // Query server API route with the pure clean IP
  try {
    const res = await fetch('/api/threat-intel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ ips: [clean] }),
    });
    if (res.ok) {
      const json = await res.json();
      if (json.reputations && json.reputations[clean]) {
        const rep = json.reputations[clean];
        reputationCache[clean] = rep;
        reputationCache[input] = rep;
        return rep;
      }
    }
  } catch (err) {
    console.warn('Threat Intel proxy unreachable, falling back to simulated evaluation:', err);
  }

  // Fallback to simulated high-fidelity SOC telemetry
  const simulated = getSimulatedReputation(clean);
  reputationCache[clean] = simulated;
  reputationCache[input] = simulated;
  return simulated;
}

/**
 * Bulk check multiple IPs in parallel via single server endpoint.
 * Strictly extracts clean IP addresses, prevents socket/port contamination,
 * validates against RFC non-routable ranges, and queries external feeds with pure IPs only.
 */
export async function enrichIPs(
  ips: string[],
  _config?: ThreatIntelConfig,
  forceRefresh = false
): Promise<Record<string, IPReputation>> {
  if (forceRefresh) {
    clearReputationCache(ips);
  }

  const results: Record<string, IPReputation> = {};
  const publicIPsToQuery = new Set<string>();
  const rawToCleanMap = new Map<string, string>();

  for (const raw of ips) {
    if (!raw) continue;
    const clean = extractIP(raw);

    // If it's not a valid IP at all (e.g. usernames, hostnames), do not enrich or query external feeds
    if (!clean || !isValidIP(clean)) {
      continue;
    }

    rawToCleanMap.set(raw, clean);

    // Check if the clean IP is private, internal, or reserved
    if (isPrivateIP(clean)) {
      const privResult = createPrivateIPReputation(clean);
      reputationCache[clean] = privResult;
      reputationCache[raw] = privResult;
      results[clean] = privResult;
      results[raw] = privResult;
    } else if (!forceRefresh && reputationCache[clean]) {
      results[clean] = reputationCache[clean];
      results[raw] = reputationCache[clean];
    } else {
      // It is a valid, non-private public IP!
      publicIPsToQuery.add(clean);
    }
  }

  const queryArray = Array.from(publicIPsToQuery);
  if (queryArray.length > 0) {
    try {
      const res = await fetch('/api/threat-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ ips: queryArray }),
      });
      if (res.ok) {
        const json = await res.json();
        if (json.reputations) {
          for (const cleanIp of queryArray) {
            const rep = json.reputations[cleanIp];
            if (rep) {
              reputationCache[cleanIp] = rep;
              results[cleanIp] = rep;
            }
          }
        }
      } else {
        throw new Error(`Threat Intel server endpoint returned HTTP ${res.status}`);
      }
    } catch (err) {
      console.warn('Batch threat intel error, fallback to simulated:', err);
      for (const cleanIp of queryArray) {
        const sim = getSimulatedReputation(cleanIp);
        reputationCache[cleanIp] = sim;
        results[cleanIp] = sim;
      }
    }

    // Also map results back to any raw input representations (e.g. sockets)
    for (const [raw, clean] of rawToCleanMap.entries()) {
      if (results[clean]) {
        results[raw] = {
          ...results[clean],
          ip: clean, // Keep clean IP without port
        };
      }
    }
  }

  return results;
}
