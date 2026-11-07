import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const envAbuse = !!process.env.ABUSEIPDB_API_KEY;
  const envVt = !!process.env.VIRUSTOTAL_API_KEY;

  const cookieAbuse = !!req.cookies.get('soc_abuse_key')?.value;
  const cookieVt = !!req.cookies.get('soc_vt_key')?.value;

  const abuseConfigured = envAbuse || cookieAbuse;
  const vtConfigured = envVt || cookieVt;

  const abuseSource = envAbuse ? 'env' : cookieAbuse ? 'cookie' : 'none';
  const vtSource = envVt ? 'env' : cookieVt ? 'cookie' : 'none';

  return NextResponse.json({
    abuseConfigured,
    vtConfigured,
    abuseSource,
    vtSource,
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { abuseApiKey, vtApiKey } = body as {
      abuseApiKey?: string;
      vtApiKey?: string;
    };

    const response = NextResponse.json({
      success: true,
      abuseConfigured: !!(abuseApiKey || process.env.ABUSEIPDB_API_KEY),
      vtConfigured: !!(vtApiKey || process.env.VIRUSTOTAL_API_KEY),
    });

    const isProd = process.env.NODE_ENV === 'production';
    const cookieOptions = {
      httpOnly: true, // Inaccessible to JavaScript (XSS-safe)
      secure: isProd,
      sameSite: 'strict' as const,
      path: '/',
      maxAge: 60 * 60 * 8, // 8-hour operational shift
    };

    if (abuseApiKey && abuseApiKey.trim()) {
      response.cookies.set('soc_abuse_key', abuseApiKey.trim(), cookieOptions);
    } else if (abuseApiKey === '') {
      response.cookies.delete('soc_abuse_key');
    }

    if (vtApiKey && vtApiKey.trim()) {
      response.cookies.set('soc_vt_key', vtApiKey.trim(), cookieOptions);
    } else if (vtApiKey === '') {
      response.cookies.delete('soc_vt_key');
    }

    return response;
  } catch (err) {
    console.error('Error saving threat intel session keys:', err);
    return NextResponse.json({ error: 'Failed to save session keys' }, { status: 500 });
  }
}

export async function DELETE() {
  const response = NextResponse.json({ success: true, cleared: true });
  response.cookies.delete('soc_abuse_key');
  response.cookies.delete('soc_vt_key');
  return response;
}
