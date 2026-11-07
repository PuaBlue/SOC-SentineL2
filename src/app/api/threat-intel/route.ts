import { NextRequest, NextResponse } from 'next/server';
import { IPReputation } from '@/types';
import {
  isPrivateIP,
  createPrivateIPReputation,
  extractIP,
  isValidIP,
} from '@/lib/threatIntel';

// Realistic fallback for offline demonstration or testing when no keys are configured
function getSimulatedFallback(ip: string): IPReputation {
  const clean = extractIP(ip) || ip;
  if (isPrivateIP(clean)) {
    return createPrivateIPReputation(clean);
  }

  const isHighRisk =
    clean === '185.220.101.5' || // Tor Exit Node / Attacker IP
    clean === '45.33.32.156' || // C2 Stage2 Infrastructure
    clean === '194.26.29.112' || // High-risk Proxy
    clean === '185.180.143.11' || // Compromised External Host
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

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { ips, abuseApiKey, vtApiKey } = body as {
      ips?: string[];
      abuseApiKey?: string;
      vtApiKey?: string;
    };

    if (!ips || !Array.isArray(ips)) {
      return NextResponse.json({ error: 'ips array is required' }, { status: 400 });
    }

    // Secure resolution: Environment variables (highest priority) -> HttpOnly Session Cookie -> Ephemeral body
    const cookieAbuse = req.cookies.get('soc_abuse_key')?.value;
    const cookieVt = req.cookies.get('soc_vt_key')?.value;

    const abuseKey = process.env.ABUSEIPDB_API_KEY || cookieAbuse || abuseApiKey || '';
    const vtKey = process.env.VIRUSTOTAL_API_KEY || cookieVt || vtApiKey || '';

    const reputations: Record<string, IPReputation> = {};

    for (const rawIp of ips) {
      if (!rawIp) continue;

      // Cleanse socket port or formatting to obtain pure IPv4 or IPv6
      const clean = extractIP(rawIp);

      if (!clean || !isValidIP(clean)) {
        // Not a valid IP address (e.g. hostnames, NetBIOS, users)
        const nonIpRep: IPReputation = {
          ip: rawIp,
          isPrivate: true,
          verdict: 'Unknown',
          isp: 'Non-IP Identifier / Internal Host',
          source: 'Internal',
          checkedAt: new Date().toISOString(),
        };
        reputations[rawIp] = nonIpRep;
        continue;
      }

      // Private / non-routable IPs are strictly handled internally and never sent to external APIs
      if (isPrivateIP(clean)) {
        const privRep = createPrivateIPReputation(clean);
        reputations[rawIp] = privRep;
        reputations[clean] = privRep;
        continue;
      }

      // Check AbuseIPDB with pure IP (never socket)
      let abuseData: Partial<IPReputation> | null = null;
      if (abuseKey) {
        try {
          const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(clean)}&maxAgeInDays=90&verbose`;
          const res = await fetch(url, {
            headers: {
              Key: abuseKey,
              Accept: 'application/json',
            },
          });
          if (res.ok) {
            const json = await res.json();
            const d = json.data;
            if (d) {
              abuseData = {
                country: d.countryName,
                countryCode: d.countryCode,
                isp: d.isp,
                domain: d.domain,
                usageType: d.usageType,
                abuseConfidenceScore: d.abuseConfidenceScore,
                totalReports: d.totalReports,
                lastReportedAt: d.lastReportedAt,
              };
            }
          } else {
            console.warn(`AbuseIPDB request for ${clean} returned HTTP ${res.status}`);
          }
        } catch (e) {
          console.error('AbuseIPDB request error:', e);
        }
      }

      // Check VirusTotal with pure IP (never socket)
      let vtData: Partial<IPReputation> | null = null;
      if (vtKey) {
        try {
          const url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(clean)}`;
          const res = await fetch(url, {
            headers: {
              'x-apikey': vtKey,
              Accept: 'application/json',
            },
          });
          if (res.ok) {
            const json = await res.json();
            const attrs = json.data?.attributes;
            if (attrs) {
              const stats = attrs.last_analysis_stats || {};
              const malicious = stats.malicious || 0;
              const suspicious = stats.suspicious || 0;
              const harmless = stats.harmless || 0;
              const undetected = stats.undetected || 0;
              vtData = {
                country: attrs.country,
                isp: attrs.as_owner,
                vtMalicious: malicious,
                vtSuspicious: suspicious,
                vtHarmless: harmless,
                vtUndetected: undetected,
                vtTotalVendors: malicious + suspicious + harmless + undetected,
                vtReputationScore: attrs.reputation,
              };
            }
          } else {
            console.warn(`VirusTotal request for ${clean} returned HTTP ${res.status}`);
          }
        } catch (e) {
          console.error('VirusTotal request error:', e);
        }
      }

      // If live feeds returned data, compute verdict
      if (abuseData || vtData) {
        const abuseScore = abuseData?.abuseConfidenceScore ?? 0;
        const vtMal = vtData?.vtMalicious ?? 0;

        let verdict: IPReputation['verdict'] = 'Clean';
        if (abuseScore >= 60 || vtMal >= 5) {
          verdict = 'Malicious';
        } else if (abuseScore >= 20 || vtMal >= 1) {
          verdict = 'Suspicious';
        }

        const rep: IPReputation = {
          ip: clean,
          isPrivate: false,
          country: vtData?.country || abuseData?.country || 'Unknown',
          countryCode: abuseData?.countryCode,
          isp: vtData?.isp || abuseData?.isp || 'Unknown',
          domain: abuseData?.domain,
          usageType: abuseData?.usageType,
          abuseConfidenceScore: abuseData?.abuseConfidenceScore,
          totalReports: abuseData?.totalReports,
          lastReportedAt: abuseData?.lastReportedAt,
          vtMalicious: vtData?.vtMalicious,
          vtSuspicious: vtData?.vtSuspicious,
          vtHarmless: vtData?.vtHarmless,
          vtUndetected: vtData?.vtUndetected,
          vtTotalVendors: vtData?.vtTotalVendors,
          vtReputationScore: vtData?.vtReputationScore,
          verdict,
          source: abuseData && vtData ? 'Both' : abuseData ? 'AbuseIPDB' : vtData ? 'VirusTotal' : 'Simulated',
          checkedAt: new Date().toISOString(),
        };

        reputations[clean] = rep;
        reputations[rawIp] = rep;
      } else {
        // Fallback simulation for demonstration / testing with genuine public IPs
        const fallback = getSimulatedFallback(clean);
        reputations[clean] = fallback;
        reputations[rawIp] = fallback;
      }
    }

    return NextResponse.json({ reputations, success: true, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Threat intelligence API error:', error);
    return NextResponse.json({ error: 'Internal server error processing threat intelligence' }, { status: 500 });
  }
}
