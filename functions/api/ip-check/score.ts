import { callIpapiCo, callIpinfo, callAbuseIPDB, callDnsbl, fetchNetworkQuality } from '../../_shared/dataSources'
import { calculateScore } from '../../_shared/scoreEngine'
import type { DataSourceInfo } from '../../_shared/types'

export const onRequestPost: PagesFunction = async (ctx) => {
  let ip: string
  try {
    const body: any = await ctx.request.json()
    ip = body?.ip?.trim() || ctx.request.headers.get('CF-Connecting-IP') || '127.0.0.1'
  } catch {
    ip = ctx.request.headers.get('CF-Connecting-IP') || '127.0.0.1'
  }

  // Validate IP (basic check)
  if (ip === '127.0.0.1' || ip === '::1') {
    return new Response(JSON.stringify({ error: 'Cannot check localhost', code: 'PRIVATE_IP', details: null }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }

  const [ipapi, ipinfo, abuse, dnsbl, network] = await Promise.all([
    callIpapiCo(ip), callIpinfo(ip), callAbuseIPDB(ip), callDnsbl(ip), fetchNetworkQuality(),
  ])

  const dataSources: DataSourceInfo[] = [ipapi.status, network.status, dnsbl.status]
  if (ipinfo) dataSources.unshift(ipinfo.status)
  if (abuse) dataSources.unshift(abuse.status)

  const geo = ipinfo?.geo?.country ? ipinfo.geo : ipapi.geo
  const asn = ipinfo?.asn?.asn || ipinfo?.asn?.asnOrg ? ipinfo.asn : ipapi.asn
  const networkType = ipapi.networkType.type !== 'unknown' ? ipapi.networkType : (ipinfo?.networkType ?? { type: 'unknown', confidence: 0, source: '' })

  const checkResult = {
    ip, geo, asn, networkType,
    proxyDetection: ipapi.proxyDetection,
    abuseRecord: abuse?.abuseRecord ?? null,
    blacklistRecords: dnsbl.blacklistRecords,
    consistency: null,
    networkQuality: network.networkQuality,
    dataSources,
    checkedAt: new Date().toISOString(),
  }

  const score = calculateScore(checkResult)

  return new Response(JSON.stringify({ ...checkResult, score }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=30' },
  })
}
