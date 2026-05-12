import dns from 'node:dns/promises'
import type {
  GeoLocation,
  AsnInfo,
  NetworkTypeInfo,
  ProxyDetection,
  AbuseRecord,
  BlacklistRecord,
  NetworkQuality,
  DataSourceInfo,
} from '../src/types/ipCheck'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TIMEOUT_MS = 5_000

async function fetchWithTimeout<T>(
  url: string,
  init?: RequestInit & { timeoutMs?: number },
): Promise<T> {
  const timeoutMs = init?.timeoutMs ?? TIMEOUT_MS
  const { timeoutMs: _, ...fetchInit } = init ?? {}
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, { ...fetchInit, signal: controller.signal })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    return (await response.json()) as T
  } finally {
    clearTimeout(timer)
  }
}

async function fetchTextWithTimeout(
  url: string,
  init?: RequestInit & { timeoutMs?: number },
): Promise<string> {
  const timeoutMs = init?.timeoutMs ?? TIMEOUT_MS
  const { timeoutMs: _, ...fetchInit } = init ?? {}
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, { ...fetchInit, signal: controller.signal })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    return await response.text()
  } finally {
    clearTimeout(timer)
  }
}

function ds(name: string, status: DataSourceInfo['status'], latencyMs: number, err?: string): DataSourceInfo {
  return { name, status, latencyMs, errorMessage: err ?? null }
}

// ---------------------------------------------------------------------------
// Network type inference helpers
// ---------------------------------------------------------------------------

const HOSTING_KEYWORDS = [
  'amazon', 'aws', 'ec2', 'google cloud', 'gcp', 'microsoft azure', 'azure',
  'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'scaleway', 'upcloud',
  'ionos', 'namecheap', 'godaddy', 'bluehost', 'siteground', 'hostgator',
  'dreamhost', 'netlify', 'vercel', 'heroku', 'render', 'fly.io', 'railway',
  'oracle cloud', 'oci', 'ibm cloud', 'softlayer', 'rackspace', 'akamai',
  'cloudflare', 'fastly', 'cloudfront', 'alibaba cloud', 'tencent cloud',
  'vscale', 'timeweb', 'firstvds',
]

const DATACENTER_KEYWORDS = [
  'datacenter', 'data center', 'colo', 'cologix', 'equinix', 'cyrusone',
  'coresite', 'qts',
]

const ISP_KEYWORDS_BUSINESS = [
  'verizon business', 'at&t business', 'comcast business', 'spectrum business',
  'centurylink business', 'cogent', 'level 3', 'lumen', 'zayo', 'ntt',
  'tata communications', 'orange business', 'bt business', 'vodafone business',
]

const ISP_KEYWORDS_MOBILE = [
  't-mobile', 'verizon wireless', 'at&t mobility', 'sprint', 'vodafone',
  'orange mobile', 'telefonica', 'china mobile', 'china unicom', 'china telecom',
  'softbank', 'ntt docomo', 'kddi', 'sk telecom', 'kt', 'lg u+',
]

function inferNetworkTypeFromOrg(org: string | null | undefined): NetworkTypeInfo {
  if (!org) return { type: 'unknown', confidence: 0, source: 'ipapi.co' }
  const lower = org.toLowerCase()
  for (const kw of DATACENTER_KEYWORDS) {
    if (lower.includes(kw)) return { type: 'datacenter', confidence: 80, source: 'keyword' }
  }
  for (const kw of HOSTING_KEYWORDS) {
    if (lower.includes(kw)) return { type: 'hosting', confidence: 80, source: 'keyword' }
  }
  for (const kw of ISP_KEYWORDS_BUSINESS) {
    if (lower.includes(kw)) return { type: 'business', confidence: 50, source: 'keyword' }
  }
  for (const kw of ISP_KEYWORDS_MOBILE) {
    if (lower.includes(kw)) return { type: 'mobile', confidence: 50, source: 'keyword' }
  }
  return { type: 'unknown', confidence: 0, source: 'ipapi.co' }
}

// ---------------------------------------------------------------------------
// Empty / fallback values
// ---------------------------------------------------------------------------

function emptyGeo(): GeoLocation {
  return { country: '', countryCode: '', region: '', city: '', latitude: null, longitude: null, timezone: '' }
}

function emptyAsn(): AsnInfo {
  return { asn: '', asnOrg: '', isp: '', org: null }
}

function emptyProxyDetection(): ProxyDetection {
  return { isVpn: false, isProxy: false, isTor: false, isRelay: false, isHosting: false, isResidentialProxy: false, confidence: 0, source: '', details: '' }
}

// ---------------------------------------------------------------------------
// 1. ipapi.co — free tier, no key required
//    Geo + ASN + ISP + basic security (VPN/Proxy/Tor/Hosting)
//    Register: https://ipapi.co/ (free: 1000 req/day)
// ---------------------------------------------------------------------------

interface IpapiResponse {
  ip?: string; city?: string; region?: string; country_code?: string; country_name?: string
  latitude?: number; longitude?: number; timezone?: string; asn?: string; org?: string
  isp?: string; postal?: string; in_eu?: boolean
  security?: { is_vpn?: boolean; is_proxy?: boolean; is_tor?: boolean; is_hosting?: boolean; is_relay?: boolean; is_crawler?: boolean; threat_score?: number }
  error?: boolean; reason?: string
}

async function callIpapiCo(ip: string): Promise<{
  geo: GeoLocation; asn: AsnInfo; networkType: NetworkTypeInfo
  proxyDetection: ProxyDetection; status: DataSourceInfo
}> {
  const start = Date.now()
  try {
    const data = await fetchWithTimeout<IpapiResponse>(`https://ipapi.co/${ip}/json/`)
    const latency = Date.now() - start
    if (data.error) {
      return {
        geo: emptyGeo(), asn: emptyAsn(),
        networkType: { type: 'unknown', confidence: 0, source: 'ipapi.co' },
        proxyDetection: emptyProxyDetection(),
        status: ds('ipapi.co', 'error', latency, data.reason ?? 'Unknown API error'),
      }
    }
    const geo: GeoLocation = {
      country: data.country_name ?? '', countryCode: data.country_code ?? '',
      region: data.region ?? '', city: data.city ?? '',
      latitude: data.latitude ?? null, longitude: data.longitude ?? null,
      timezone: data.timezone ?? '',
    }
    const asn: AsnInfo = {
      asn: data.asn ?? '', asnOrg: data.org ?? '', isp: data.isp ?? '', org: data.org ?? null,
    }
    const networkType = inferNetworkTypeFromOrg(data.org)
    if (data.security?.is_hosting) {
      networkType.type = 'hosting'; networkType.confidence = 80
    }
    const sec = data.security
    const proxyDetection: ProxyDetection = {
      isVpn: sec?.is_vpn ?? false, isProxy: sec?.is_proxy ?? false,
      isTor: sec?.is_tor ?? false, isRelay: sec?.is_relay ?? false,
      isHosting: sec?.is_hosting ?? false, isResidentialProxy: false,
      confidence: sec ? 70 : 0, source: 'ipapi.co',
      details: sec ? `VPN:${sec.is_vpn} Proxy:${sec.is_proxy} Tor:${sec.is_tor} Hosting:${sec.is_hosting}` : 'No security data',
    }
    return { geo, asn, networkType, proxyDetection, status: ds('ipapi.co', 'success', latency) }
  } catch (err: any) {
    const latency = Date.now() - start
    if (err.name === 'AbortError') {
      return { geo: emptyGeo(), asn: emptyAsn(), networkType: { type: 'unknown', confidence: 0, source: 'ipapi.co' }, proxyDetection: emptyProxyDetection(), status: ds('ipapi.co', 'timeout', latency) }
    }
    return { geo: emptyGeo(), asn: emptyAsn(), networkType: { type: 'unknown', confidence: 0, source: 'ipapi.co' }, proxyDetection: emptyProxyDetection(), status: ds('ipapi.co', 'error', latency, err.message) }
  }
}

// ---------------------------------------------------------------------------
// 2. IPinfo — free tier 50k req/month, needs API key
//    Geo + ASN + privacy (VPN/Proxy/Tor/Hosting/Relay)
//    Register: https://ipinfo.io/signup
// ---------------------------------------------------------------------------

interface IpinfoResponse {
  ip?: string; city?: string; region?: string; country?: string; loc?: string
  org?: string; postal?: string; timezone?: string; asn?: { asn?: string; name?: string; type?: string }
  company?: { name?: string; type?: string }
  privacy?: { vpn?: boolean; proxy?: boolean; tor?: boolean; relay?: boolean; hosting?: boolean; service?: string }
  error?: { title?: string; message?: string }
}

async function callIpinfo(ip: string): Promise<{
  geo: GeoLocation; asn: AsnInfo; networkType: NetworkTypeInfo
  proxyDetection: ProxyDetection; status: DataSourceInfo
} | null> {
  const apiKey = process.env.IPINFO_API_KEY
  if (!apiKey) return null

  const start = Date.now()
  try {
    const data = await fetchWithTimeout<IpinfoResponse>(
      `https://ipinfo.io/${ip}?token=${apiKey}`,
    )
    const latency = Date.now() - start
    if ((data as any).error) {
      return {
        geo: emptyGeo(), asn: emptyAsn(),
        networkType: { type: 'unknown', confidence: 0, source: 'ipinfo' },
        proxyDetection: emptyProxyDetection(),
        status: ds('IPinfo', 'error', latency, (data as any).error?.message ?? 'Unknown error'),
      }
    }
    const [lat, lon] = (data.loc ?? '').split(',').map(Number)
    const geo: GeoLocation = {
      country: data.country ?? '', countryCode: data.country ?? '',
      region: data.region ?? '', city: data.city ?? '',
      latitude: lat && !isNaN(lat) ? lat : null,
      longitude: lon && !isNaN(lon) ? lon : null,
      timezone: data.timezone ?? '',
    }
    // IPinfo free tier returns org as "AS15169 Google LLC"
    const asnMatch = data.org?.match(/^(AS\d+)\s+(.+)/)
    const asnNumber = data.asn?.asn ?? asnMatch?.[1] ?? ''
    const asnOrg = data.asn?.name ?? asnMatch?.[2] ?? data.org ?? ''
    const asn: AsnInfo = { asn: asnNumber, asnOrg, isp: data.org ?? '', org: data.org ?? null }
    const networkType = inferNetworkTypeFromOrg(data.org)

    // IPinfo free tier doesn't include privacy object; use empty detection
    const proxyDetection: ProxyDetection = {
      isVpn: false, isProxy: false, isTor: false, isRelay: false,
      isHosting: false, isResidentialProxy: false,
      confidence: 0, source: 'IPinfo',
      details: 'Free tier: privacy data not available. Set up ipapi.co for proxy detection.',
    }
    return { geo, asn, networkType, proxyDetection, status: ds('IPinfo', 'success', latency) }
  } catch (err: any) {
    const latency = Date.now() - start
    if (err.name === 'AbortError') return { geo: emptyGeo(), asn: emptyAsn(), networkType: { type: 'unknown', confidence: 0, source: 'ipinfo' }, proxyDetection: emptyProxyDetection(), status: ds('IPinfo', 'timeout', latency) }
    return { geo: emptyGeo(), asn: emptyAsn(), networkType: { type: 'unknown', confidence: 0, source: 'ipinfo' }, proxyDetection: emptyProxyDetection(), status: ds('IPinfo', 'error', latency, err.message) }
  }
}


// ---------------------------------------------------------------------------
// 4. MaxMind GeoIP2 + Anonymous IP — needs Account ID + License Key
//    Register: https://www.maxmind.com/en/geolite2/signup
//    Anonymous IP DB requires separate license
// ---------------------------------------------------------------------------

interface MaxMindResponse {
  country?: { iso_code?: string; names?: { en?: string } }
  city?: { names?: { en?: string } }
  subdivisions?: Array<{ names?: { en?: string } }>
  location?: { latitude?: number; longitude?: number; time_zone?: string }
  traits?: {
    autonomous_system_number?: number; autonomous_system_organization?: string; isp?: string
    organization?: string; is_anonymous?: boolean; is_anonymous_vpn?: boolean
    is_hosting_provider?: boolean; is_tor_exit_node?: boolean; is_public_proxy?: boolean
    is_residential_proxy?: boolean; user_type?: string
  }
  error?: string; code?: string
}

async function callMaxMind(ip: string): Promise<{
  geo: GeoLocation; asn: AsnInfo; networkType: NetworkTypeInfo
  proxyDetection: ProxyDetection; status: DataSourceInfo
} | null> {
  const accountId = process.env.MAXMIND_ACCOUNT_ID
  const licenseKey = process.env.MAXMIND_LICENSE_KEY
  if (!accountId || !licenseKey) return null

  const start = Date.now()
  try {
    const data = await fetchWithTimeout<MaxMindResponse>(
      `https://geoip.maxmind.com/geoip/v2.1/city/${ip}`,
      { headers: { Authorization: 'Basic ' + Buffer.from(`${accountId}:${licenseKey}`).toString('base64') } },
    )
    const latency = Date.now() - start
    if (data.error) {
      return {
        geo: emptyGeo(), asn: emptyAsn(),
        networkType: { type: 'unknown', confidence: 0, source: 'MaxMind' },
        proxyDetection: emptyProxyDetection(),
        status: ds('MaxMind', 'error', latency, data.error),
      }
    }
    const geo: GeoLocation = {
      country: data.country?.names?.en ?? '', countryCode: data.country?.iso_code ?? '',
      region: data.subdivisions?.[0]?.names?.en ?? '', city: data.city?.names?.en ?? '',
      latitude: data.location?.latitude ?? null, longitude: data.location?.longitude ?? null,
      timezone: data.location?.time_zone ?? '',
    }
    const asnNumber = data.traits?.autonomous_system_number ? `AS${data.traits.autonomous_system_number}` : ''
    const asn: AsnInfo = {
      asn: asnNumber, asnOrg: data.traits?.autonomous_system_organization ?? '',
      isp: data.traits?.isp ?? '', org: data.traits?.organization ?? null,
    }
    const t = data.traits
    let nwType: NetworkTypeInfo['type'] = 'unknown'
    if (t?.is_hosting_provider) nwType = 'hosting'
    else if (t?.user_type === 'business') nwType = 'business'
    else if (t?.user_type === 'residential') nwType = 'residential'
    const networkType: NetworkTypeInfo = { type: nwType, confidence: 85, source: 'MaxMind' }

    const proxyDetection: ProxyDetection = {
      isVpn: t?.is_anonymous_vpn ?? false, isProxy: t?.is_public_proxy ?? false,
      isTor: t?.is_tor_exit_node ?? false, isRelay: false,
      isHosting: t?.is_hosting_provider ?? false,
      isResidentialProxy: t?.is_residential_proxy ?? false,
      confidence: 90, source: 'MaxMind',
      details: `VPN:${t?.is_anonymous_vpn} Proxy:${t?.is_public_proxy} Tor:${t?.is_tor_exit_node} Hosting:${t?.is_hosting_provider} ResProxy:${t?.is_residential_proxy}`,
    }
    return { geo, asn, networkType, proxyDetection, status: ds('MaxMind', 'success', latency) }
  } catch (err: any) {
    const latency = Date.now() - start
    if (err.name === 'AbortError') return { geo: emptyGeo(), asn: emptyAsn(), networkType: { type: 'unknown', confidence: 0, source: 'MaxMind' }, proxyDetection: emptyProxyDetection(), status: ds('MaxMind', 'timeout', latency) }
    return { geo: emptyGeo(), asn: emptyAsn(), networkType: { type: 'unknown', confidence: 0, source: 'MaxMind' }, proxyDetection: emptyProxyDetection(), status: ds('MaxMind', 'error', latency, err.message) }
  }
}

// ---------------------------------------------------------------------------
// 5. AbuseIPDB — abuse reports, confidence score
//    Register: https://www.abuseipdb.com/register (free: 1000 checks/day)
// ---------------------------------------------------------------------------

async function callAbuseIPDB(ip: string): Promise<{
  abuseRecord: AbuseRecord | null; blacklistRecords: BlacklistRecord[]; status: DataSourceInfo
} | null> {
  const apiKey = process.env.ABUSEIPDB_API_KEY
  if (!apiKey) return null

  const start = Date.now()
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
    let response: Response; let json: any
    try {
      response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
        { headers: { Key: apiKey, Accept: 'application/json' }, signal: controller.signal },
      )
      json = await response.json()
    } finally { clearTimeout(timer) }

    const latency = Date.now() - start
    if (!response.ok) {
      return { abuseRecord: null, blacklistRecords: [], status: ds('AbuseIPDB', 'error', latency, json?.errors?.[0]?.detail ?? `HTTP ${response.status}`) }
    }
    const record = json?.data
    if (!record) {
      return { abuseRecord: null, blacklistRecords: [], status: ds('AbuseIPDB', 'error', latency, 'Empty response') }
    }
    const abuseRecord: AbuseRecord = {
      confidenceScore: record.abuseConfidenceScore ?? 0,
      totalReports: record.totalReports ?? 0,
      lastReportedAt: record.lastReportedAt ?? null,
      categories: Object.entries(record.categoryDetails ?? {}).map(([id, info]: [string, any]) => `${id}:${info.displayName ?? ''}`),
      source: 'AbuseIPDB',
    }
    const blacklistRecords: BlacklistRecord[] = [{
      listed: record.totalReports > 0, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB',
    }]
    return { abuseRecord, blacklistRecords, status: ds('AbuseIPDB', 'success', latency) }
  } catch (err: any) {
    const latency = Date.now() - start
    if (err.name === 'AbortError') return { abuseRecord: null, blacklistRecords: [], status: ds('AbuseIPDB', 'timeout', latency) }
    return { abuseRecord: null, blacklistRecords: [], status: ds('AbuseIPDB', 'error', latency, err.message) }
  }
}

// ---------------------------------------------------------------------------
// 6. DNSBL lookups — free, no API key needed
//    Checks IP against Spamhaus, Barracuda, SpamCop, Sorbs, etc.
//    Uses reverse DNS lookup: reversed.ip.dnsbl.example.com
// ---------------------------------------------------------------------------

const DNSBL_PROVIDERS: Array<{ name: string; zone: string; type: string }> = [
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', type: 'spam' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org', type: 'spam' },
  { name: 'SpamCop', zone: 'bl.spamcop.net', type: 'spam' },
  { name: 'Sorbs', zone: 'dnsbl.sorbs.net', type: 'spam' },
  { name: 'SURBL (multi)', zone: 'multi.surbl.org', type: 'phishing' },
  { name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net', type: 'spam' },
  { name: 'UCEPROTECT L2', zone: 'dnsbl-2.uceprotect.net', type: 'spam' },
  { name: 'UCEPROTECT L3', zone: 'dnsbl-3.uceprotect.net', type: 'spam' },
]

function reverseIpForDnsbl(ip: string): string {
  if (ip.includes(':')) {
    // IPv6 reverse: expand and reverse nibbles
    // Simplified: only handle IPv4 for DNSBL
    return ''
  }
  return ip.split('.').reverse().join('.')
}

async function callDnsbl(ip: string): Promise<{
  blacklistRecords: BlacklistRecord[]; status: DataSourceInfo
}> {
  if (ip.includes(':')) {
    // DNSBL over IPv6 is uncommon; skip for now
    return { blacklistRecords: [], status: ds('DNSBL', 'not_configured', 0, 'IPv6 DNSBL lookup not supported') }
  }

  const reversed = reverseIpForDnsbl(ip)
  if (!reversed) {
    return { blacklistRecords: [], status: ds('DNSBL', 'error', 0, 'Invalid IP for reverse lookup') }
  }

  const start = Date.now()
  const results: BlacklistRecord[] = []
  let successCount = 0
  let failCount = 0

  const lookups = DNSBL_PROVIDERS.map(async (provider) => {
    const queryName = `${reversed}.${provider.zone}`
    try {
      const result = await dns.resolve4(queryName)
      // RFC 5782: a response of 127.0.0.0/8 means "listed"
      const listed = result.length > 0 && result[0]?.startsWith('127.')
      results.push({ listed, listName: provider.name, listType: provider.type, source: 'DNSBL' })
      if (listed) successCount++
      else failCount++
    } catch (err: any) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
        // NXDOMAIN means NOT listed — this is the expected "clean" response
        results.push({ listed: false, listName: provider.name, listType: provider.type, source: 'DNSBL' })
        successCount++
      } else {
        results.push({ listed: false, listName: provider.name, listType: provider.type, source: 'DNSBL' })
        failCount++
      }
    }
  })

  await Promise.allSettled(lookups)
  const latency = Date.now() - start

  const status: DataSourceInfo = failCount > DNSBL_PROVIDERS.length / 2
    ? ds('DNSBL', 'error', latency, `${failCount}/${DNSBL_PROVIDERS.length} lookups failed`)
    : ds('DNSBL', 'success', latency)

  return { blacklistRecords: results, status }
}

// ---------------------------------------------------------------------------
// 7. Cloudflare Trace — free, no key needed, simple IP detection
//    URL: https://cloudflare.com/cdn-cgi/trace
// ---------------------------------------------------------------------------

async function callCloudflareTrace(): Promise<{
  ip: string | null; status: DataSourceInfo
}> {
  const start = Date.now()
  try {
    const text = await fetchTextWithTimeout('https://cloudflare.com/cdn-cgi/trace')
    const latency = Date.now() - start
    const match = text.match(/^ip=(.+)$/m)
    const ip = match ? match[1] : null
    if (!ip) {
      return { ip: null, status: ds('Cloudflare Trace', 'error', latency, 'Could not extract IP from trace') }
    }
    return { ip, status: ds('Cloudflare Trace', 'success', latency) }
  } catch (err: any) {
    const latency = Date.now() - start
    if (err.name === 'AbortError') return { ip: null, status: ds('Cloudflare Trace', 'timeout', latency) }
    return { ip: null, status: ds('Cloudflare Trace', 'error', latency, err.message) }
  }
}


// ---------------------------------------------------------------------------
// Aggregated data fetchers (public API used by server routes)
// ---------------------------------------------------------------------------

export async function fetchIpGeoData(ip: string): Promise<{
  geo: GeoLocation; asn: AsnInfo; networkType: NetworkTypeInfo; status: DataSourceInfo
}> {
  const [ipapi, ipinfo, maxmind] = await Promise.all([
    callIpapiCo(ip),
    callIpinfo(ip),
    callMaxMind(ip),
  ])

  const sources = [maxmind, ipinfo, ipapi].filter(Boolean) as NonNullable<typeof ipapi>[]

  let geo = emptyGeo()
  let asn = emptyAsn()
  let networkType: NetworkTypeInfo = { type: 'unknown', confidence: 0, source: '' }
  const statuses: DataSourceInfo[] = []

  for (const src of sources) {
    statuses.push(src.status)
    if (src.status.status === 'success') {
      if (!geo.country && src.geo.country) geo = src.geo
      else if (!geo.city && src.geo.city) geo = { ...geo, city: src.geo.city, region: src.geo.region || geo.region }
      if (!asn.asn && src.asn.asn) asn = src.asn
      else if (!asn.asnOrg && src.asn.asnOrg) asn = { ...asn, asnOrg: src.asn.asnOrg }
      if (networkType.type === 'unknown' && src.networkType.type !== 'unknown') {
        networkType = src.networkType
      }
    }
  }

  const overallStatus: DataSourceInfo = {
    name: 'Geo (multi-source)',
    status: statuses.some(s => s.status === 'success') ? 'success' : 'error',
    latencyMs: Math.max(...statuses.map(s => s.latencyMs)),
    errorMessage: statuses.every(s => s.status !== 'success') ? 'All geo data sources failed' : null,
  }

  return { geo, asn, networkType, status: overallStatus }
}

export async function fetchProxyDetection(ip: string): Promise<{
  proxyDetection: ProxyDetection; status: DataSourceInfo
}> {
  const [ipapi, ipinfo, maxmind] = await Promise.all([
    callIpapiCo(ip),
    callIpinfo(ip),
    callMaxMind(ip),
  ])

  const allResults = [ipapi.proxyDetection, ...(
    [ipinfo, maxmind].filter(Boolean) as NonNullable<typeof ipinfo>[]
  ).map(r => r.proxyDetection)]

  const aggregated: ProxyDetection = {
    isVpn: allResults.some(r => r.isVpn),
    isProxy: allResults.some(r => r.isProxy),
    isTor: allResults.some(r => r.isTor),
    isRelay: allResults.some(r => r.isRelay),
    isHosting: allResults.some(r => r.isHosting),
    isResidentialProxy: allResults.some(r => r.isResidentialProxy),
    confidence: Math.max(...allResults.map(r => r.confidence)),
    source: allResults.filter(r => r.source).map(r => r.source).join(', '),
    details: allResults.filter(r => r.details).map(r => `[${r.source}]: ${r.details}`).join(' | '),
  }

  const allStatuses = [ipapi.status, ipinfo?.status, maxmind?.status].filter(Boolean) as DataSourceInfo[]
  const overallStatus: DataSourceInfo = {
    name: 'Proxy Detection (multi-source)',
    status: allStatuses.some(s => s?.status === 'success') ? 'success' : 'error',
    latencyMs: Math.max(...allStatuses.map(s => s?.latencyMs ?? 0)),
    errorMessage: allStatuses.every(s => s?.status !== 'success') ? 'All proxy detection sources failed' : null,
  }

  return { proxyDetection: aggregated, status: overallStatus }
}

export async function fetchAbuseData(ip: string): Promise<{
  abuseRecord: AbuseRecord | null; blacklistRecords: BlacklistRecord[]; status: DataSourceInfo[]
}> {
  const [abuseipdb, dnsbl] = await Promise.all([
    callAbuseIPDB(ip),
    callDnsbl(ip),
  ])

  const statuses: DataSourceInfo[] = []
  let abuseRecord: AbuseRecord | null = null
  const allBlacklistRecords: BlacklistRecord[] = []

  if (abuseipdb) {
    statuses.push(abuseipdb.status)
    if (abuseipdb.abuseRecord) abuseRecord = abuseipdb.abuseRecord
    allBlacklistRecords.push(...abuseipdb.blacklistRecords)
  } else {
    statuses.push(ds('AbuseIPDB', 'not_configured', 0, 'Set ABUSEIPDB_API_KEY'))
  }

  statuses.push(dnsbl.status)
  allBlacklistRecords.push(...dnsbl.blacklistRecords)

  return { abuseRecord, blacklistRecords: allBlacklistRecords, status: statuses }
}

export async function fetchNetworkQuality(_ip: string): Promise<{
  networkQuality: NetworkQuality; status: DataSourceInfo
}> {
  const start = Date.now()

  // Use multiple endpoints to measure connectivity
  const targets = [
    { url: 'https://httpbin.org/ip', name: 'httpbin.org' },
    { url: 'https://api.ipify.org?format=json', name: 'ipify.org' },
    { url: 'https://cloudflare.com/cdn-cgi/trace', name: 'Cloudflare' },
  ]

  const results = await Promise.allSettled(
    targets.map(async (target) => {
      const t0 = Date.now()
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
      try {
        const response = await fetch(target.url, { signal: controller.signal })
        return { name: target.name, latency: Date.now() - t0, ok: response.ok }
      } finally {
        clearTimeout(timer)
      }
    }),
  )

  const latencies: number[] = []
  let failures = 0
  let ipv4Ok = false
  let ipv6Ok = false

  for (const result of results) {
    if (result.status === 'fulfilled') {
      latencies.push(result.value.latency)
      if (result.value.ok) {
        // All these targets are IPv4
        ipv4Ok = true
      }
    } else {
      failures++
    }
  }

  const avgLatency = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : null
  const totalLatency = Date.now() - start

  // Try IPv6 test
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 3000)
    await fetch('https://ipv6.google.com/generate_204', { signal: controller.signal, mode: 'no-cors' })
    ipv6Ok = true
    clearTimeout(timer)
  } catch {
    ipv6Ok = false
  }

  const networkQuality: NetworkQuality = {
    latencyMs: avgLatency,
    packetLoss: results.length > 0 ? Math.round((failures / results.length) * 100) : null,
    ipv4Supported: ipv4Ok,
    ipv6Supported: ipv6Ok,
    connectivityScore: !ipv4Ok ? 0 : avgLatency && avgLatency < 100 ? 10 : avgLatency && avgLatency < 300 ? 8 : avgLatency && avgLatency < 600 ? 5 : 3,
  }

  const status: DataSourceInfo = failures === results.length
    ? ds('Network Quality', 'error', totalLatency, 'All connectivity checks failed')
    : failures > 0
      ? ds('Network Quality', 'success', totalLatency, `${failures}/${results.length} checks failed`)
      : ds('Network Quality', 'success', totalLatency)

  return { networkQuality, status }
}

// ---------------------------------------------------------------------------
// Legacy aliases for backward compatibility with existing server routes
// ---------------------------------------------------------------------------

export { callCloudflareTrace }
