// Cloudflare Functions compatible data sources
// Uses DNS-over-HTTPS instead of node:dns for DNSBL lookups
import type { GeoLocation, AsnInfo, NetworkTypeInfo, ProxyDetection, AbuseRecord, BlacklistRecord, DataSourceInfo } from './types'

const TIMEOUT = 5000

// Env vars will be set per-request
let _env: any = {}

export function setEnv(env: any) { _env = env }

function ds(name: string, status: string, latencyMs: number, err?: string): DataSourceInfo {
  return { name, status, latencyMs, errorMessage: err ?? null }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, init)
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json() as Promise<T>
}

// ---- ipapi.co ----
export async function callIpapiCo(ip: string): Promise<{
  geo: GeoLocation; asn: AsnInfo; networkType: NetworkTypeInfo; proxyDetection: ProxyDetection; status: DataSourceInfo
}> {
  const start = Date.now()
  try {
    const data: any = await fetchJson(`https://ipapi.co/${ip}/json/`)
    const latency = Date.now() - start
    if (data.error) {
      return { geo: { country: '', countryCode: '', region: '', city: '', latitude: null, longitude: null, timezone: '' }, asn: { asn: '', asnOrg: '', isp: '', org: null }, networkType: { type: 'unknown', confidence: 0, source: 'ipapi.co' }, proxyDetection: { isVpn: false, isProxy: false, isTor: false, isRelay: false, isHosting: false, isResidentialProxy: false, confidence: 0, source: 'ipapi.co', details: '' }, status: ds('ipapi.co', 'error', latency, data.reason) }
    }
    const sec = data.security
    return {
      geo: { country: data.country_name ?? '', countryCode: data.country_code ?? '', region: data.region ?? '', city: data.city ?? '', latitude: data.latitude ?? null, longitude: data.longitude ?? null, timezone: data.timezone ?? '' },
      asn: { asn: data.asn ?? '', asnOrg: data.org ?? '', isp: data.isp ?? '', org: data.org ?? null },
      networkType: sec?.is_hosting ? { type: 'hosting', confidence: 80, source: 'ipapi.co' } : { type: 'unknown', confidence: 0, source: 'ipapi.co' },
      proxyDetection: { isVpn: sec?.is_vpn ?? false, isProxy: sec?.is_proxy ?? false, isTor: sec?.is_tor ?? false, isRelay: sec?.is_relay ?? false, isHosting: sec?.is_hosting ?? false, isResidentialProxy: false, confidence: sec ? 70 : 0, source: 'ipapi.co', details: sec ? `VPN:${sec.is_vpn} Proxy:${sec.is_proxy} Tor:${sec.is_tor} Hosting:${sec.is_hosting}` : '' },
      status: ds('ipapi.co', 'success', latency),
    }
  } catch (e: any) {
    const latency = Date.now() - start
    return { geo: { country: '', countryCode: '', region: '', city: '', latitude: null, longitude: null, timezone: '' }, asn: { asn: '', asnOrg: '', isp: '', org: null }, networkType: { type: 'unknown', confidence: 0, source: 'ipapi.co' }, proxyDetection: { isVpn: false, isProxy: false, isTor: false, isRelay: false, isHosting: false, isResidentialProxy: false, confidence: 0, source: 'ipapi.co', details: '' }, status: ds('ipapi.co', 'error', latency, e.message) }
  }
}

// ---- IPinfo ----
export async function callIpinfo(ip: string): Promise<{
  geo: GeoLocation; asn: AsnInfo; networkType: NetworkTypeInfo; proxyDetection: ProxyDetection; status: DataSourceInfo
} | null> {
  const key = _env.IPINFO_API_KEY
  if (!key) return null
  const start = Date.now()
  try {
    const data: any = await fetchJson(`https://ipinfo.io/${ip}?token=${key}`)
    const latency = Date.now() - start
    const [lat, lon] = (data.loc ?? '').split(',').map(Number)
    const asnMatch = data.org?.match(/^(AS\d+)\s+(.+)/)
    return {
      geo: { country: data.country ?? '', countryCode: data.country ?? '', region: data.region ?? '', city: data.city ?? '', latitude: lat || null, longitude: lon || null, timezone: data.timezone ?? '' },
      asn: { asn: asnMatch?.[1] ?? '', asnOrg: asnMatch?.[2] ?? data.org ?? '', isp: data.org ?? '', org: data.org ?? null },
      networkType: { type: 'unknown', confidence: 0, source: 'IPinfo' },
      proxyDetection: { isVpn: false, isProxy: false, isTor: false, isRelay: false, isHosting: false, isResidentialProxy: false, confidence: 0, source: 'IPinfo', details: 'Free tier: no privacy data' },
      status: ds('IPinfo', 'success', latency),
    }
  } catch (e: any) {
    const latency = Date.now() - start
    return { geo: { country: '', countryCode: '', region: '', city: '', latitude: null, longitude: null, timezone: '' }, asn: { asn: '', asnOrg: '', isp: '', org: null }, networkType: { type: 'unknown', confidence: 0, source: 'IPinfo' }, proxyDetection: { isVpn: false, isProxy: false, isTor: false, isRelay: false, isHosting: false, isResidentialProxy: false, confidence: 0, source: 'IPinfo', details: '' }, status: ds('IPinfo', 'error', latency, e.message) }
  }
}

// ---- AbuseIPDB ----
export async function callAbuseIPDB(ip: string): Promise<{
  abuseRecord: AbuseRecord | null; blacklistRecords: BlacklistRecord[]; status: DataSourceInfo
} | null> {
  const key = _env.ABUSEIPDB_API_KEY
  if (!key) return null
  const start = Date.now()
  try {
    const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, { headers: { Key: key, Accept: 'application/json' } })
    const json: any = await resp.json()
    const latency = Date.now() - start
    const record = json?.data
    const abuseRecord: AbuseRecord = { confidenceScore: record?.abuseConfidenceScore ?? 0, totalReports: record?.totalReports ?? 0, lastReportedAt: record?.lastReportedAt ?? null, categories: [], source: 'AbuseIPDB' }
    return { abuseRecord, blacklistRecords: [{ listed: record?.abuseConfidenceScore > 0, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' }], status: ds('AbuseIPDB', 'success', latency) }
  } catch (e: any) {
    const latency = Date.now() - start
    return { abuseRecord: null, blacklistRecords: [], status: ds('AbuseIPDB', 'error', latency, e.message) }
  }
}

// ---- DNSBL via DNS-over-HTTPS ----
const DNSBL_LIST = [
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', type: 'spam' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org', type: 'spam' },
  { name: 'SpamCop', zone: 'bl.spamcop.net', type: 'spam' },
  { name: 'Sorbs', zone: 'dnsbl.sorbs.net', type: 'spam' },
  { name: 'SURBL (multi)', zone: 'multi.surbl.org', type: 'phishing' },
  { name: 'Tor Exit Node', zone: 'dnsel.torproject.org', type: 'tor' },
]

function reverseIp4(ip: string): string { return ip.split('.').reverse().join('.') }

function reverseIp6(ip: string): string {
  // Expand :: to full form, then reverse nibbles
  try {
    const parts = ip.split(':')
    const expanded: string[] = []
    for (const part of parts) {
      if (part === '') {
        // :: compression — fill to 8 groups
        const fill = 8 - parts.filter(p => p !== '').length
        for (let i = 0; i <= fill; i++) expanded.push('0000')
      } else {
        expanded.push(part.padStart(4, '0'))
      }
    }
    return expanded.join('').split('').reverse().join('.')
  } catch {
    return ''
  }
}

export async function callDnsbl(ip: string): Promise<{
  blacklistRecords: BlacklistRecord[]; status: DataSourceInfo
}> {
  const start = Date.now()
  const results: BlacklistRecord[] = []

  if (ip.includes(':')) {
    // IPv6 DNSBL via DoH
    const reversed = reverseIp6(ip)
    if (!reversed || reversed.length < 60) {
      results.push(...DNSBL_LIST.map(p => ({ listed: false, listName: p.name, listType: p.type, source: 'DNSBL' })))
      return { blacklistRecords: results, status: ds('DNSBL', 'not_configured', 0, 'IPv6 reverse failed') }
    }
    const lookups = DNSBL_LIST.map(async (provider) => {
      const url = `https://dns.google/resolve?name=${reversed}.${provider.zone}&type=AAAA`
      try {
        const data: any = await fetchJson(url)
        const listed = data.Answer?.some((a: any) => a.data?.startsWith?.('::'))
        results.push({ listed: !!listed, listName: provider.name, listType: provider.type, source: 'DNSBL' })
      } catch {
        results.push({ listed: false, listName: provider.name, listType: provider.type, source: 'DNSBL' })
      }
    })
    await Promise.allSettled(lookups)
    const latency = Date.now() - start
    return { blacklistRecords: results, status: ds('DNSBL', 'success', latency) }
  }

  const reversed = reverseIp4(ip)
  const lookups = DNSBL_LIST.map(async (provider) => {
    const url = `https://dns.google/resolve?name=${reversed}.${provider.zone}&type=A`
    try {
      const data: any = await fetchJson(url)
      const listed = data.Answer?.some((a: any) => a.data?.startsWith?.('127.'))
      results.push({ listed: !!listed, listName: provider.name, listType: provider.type, source: 'DNSBL' })
    } catch {
      results.push({ listed: false, listName: provider.name, listType: provider.type, source: 'DNSBL' })
    }
  })
  await Promise.allSettled(lookups)
  const latency = Date.now() - start
  return { blacklistRecords: results, status: ds('DNSBL', 'success', latency) }
}

// ---- ip-api.com — free tier, no key, 45 req/min — fallback for ipapi.co ----
export async function callIpApiCom(ip: string): Promise<{
  geo: GeoLocation; asn: AsnInfo; networkType: NetworkTypeInfo; proxyDetection: ProxyDetection; status: DataSourceInfo
}> {
  const start = Date.now()
  try {
    const data: any = await fetchJson(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,city,lat,lon,timezone,as,org,isp,proxy,hosting,mobile,query`)
    const latency = Date.now() - start
    if (data.status !== 'success') {
      return { geo: { country: '', countryCode: '', region: '', city: '', latitude: null, longitude: null, timezone: '' }, asn: { asn: '', asnOrg: '', isp: '', org: null }, networkType: { type: 'unknown', confidence: 0, source: 'ip-api.com' }, proxyDetection: { isVpn: false, isProxy: false, isTor: false, isRelay: false, isHosting: false, isResidentialProxy: false, confidence: 0, source: 'ip-api.com', details: '' }, status: ds('ip-api.com', 'error', latency, data.message) }
    }
    const asnMatch = data.as?.match(/^(AS\d+)\s+(.+)/)
    let ntType = 'unknown'; let ntConf = 0
    if (data.hosting) { ntType = 'hosting'; ntConf = 60 }
    else if (data.mobile) { ntType = 'mobile'; ntConf = 60 }
    return {
      geo: { country: data.country ?? '', countryCode: data.countryCode ?? '', region: data.region ?? '', city: data.city ?? '', latitude: data.lat ?? null, longitude: data.lon ?? null, timezone: data.timezone ?? '' },
      asn: { asn: asnMatch?.[1] ?? data.as ?? '', asnOrg: asnMatch?.[2] ?? data.org ?? '', isp: data.isp ?? '', org: data.org ?? null },
      networkType: { type: ntType as any, confidence: ntConf, source: 'ip-api.com' },
      proxyDetection: { isVpn: false, isProxy: data.proxy ?? false, isTor: false, isRelay: false, isHosting: data.hosting ?? false, isResidentialProxy: false, confidence: (data.proxy || data.hosting) ? 60 : 0, source: 'ip-api.com', details: `Proxy:${data.proxy} Hosting:${data.hosting}` },
      status: ds('ip-api.com', 'success', latency),
    }
  } catch (e: any) {
    const latency = Date.now() - start
    return { geo: { country: '', countryCode: '', region: '', city: '', latitude: null, longitude: null, timezone: '' }, asn: { asn: '', asnOrg: '', isp: '', org: null }, networkType: { type: 'unknown', confidence: 0, source: 'ip-api.com' }, proxyDetection: { isVpn: false, isProxy: false, isTor: false, isRelay: false, isHosting: false, isResidentialProxy: false, confidence: 0, source: 'ip-api.com', details: '' }, status: ds('ip-api.com', 'error', latency, e.message) }
  }
}

// ---- Network quality ----
export async function fetchNetworkQuality(): Promise<{
  networkQuality: { latencyMs: number | null; packetLoss: number | null; ipv4Supported: boolean; ipv6Supported: boolean; connectivityScore: number }; status: DataSourceInfo
}> {
  const start = Date.now()
  let latencyMs: number | null = null
  try {
    const t0 = Date.now()
    await fetch('https://httpbin.org/ip')
    latencyMs = Date.now() - t0
  } catch { latencyMs = null }
  const latency = Date.now() - start
  return {
    networkQuality: { latencyMs, packetLoss: null, ipv4Supported: true, ipv6Supported: false, connectivityScore: latencyMs ? (latencyMs < 200 ? 10 : latencyMs < 500 ? 7 : 4) : 0 },
    status: ds('Network', latencyMs ? 'success' : 'error', latency),
  }
}
