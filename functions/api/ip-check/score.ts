import { callIpapiCo, callIpinfo, callAbuseIPDB, callDnsbl, fetchNetworkQuality } from '../../_shared/dataSources'
import { calculateScore } from '../../_shared/scoreEngine'
import { isValidIp, isPublicIp } from '../../_shared/ipValidator'
import type { DataSourceInfo } from '../../_shared/types'

export const onRequestPost: PagesFunction = async (ctx) => {
  let ip: string
  let clientConsistency: any = null
  try {
    const body: any = await ctx.request.json()
    ip = body?.ip?.trim() || ctx.request.headers.get('CF-Connecting-IP') || '127.0.0.1'
    clientConsistency = body?.consistency ?? null
  } catch {
    ip = ctx.request.headers.get('CF-Connecting-IP') || '127.0.0.1'
  }

  if (!isValidIp(ip)) {
    return new Response(JSON.stringify({ error: 'Invalid IP address provided.', code: 'INVALID_IP', details: `"${ip}" is not a valid IPv4 or IPv6 address.` }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }
  if (!isPublicIp(ip)) {
    return new Response(JSON.stringify({ error: 'Only public IP addresses can be checked.', code: 'PRIVATE_IP', details: `"${ip}" is a private, reserved, or non-routable address.` }), { status: 400, headers: { 'Content-Type': 'application/json' } })
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
    consistency: clientConsistency,
    networkQuality: network.networkQuality,
    dataSources,
    checkedAt: new Date().toISOString(),
  }

  const score = calculateScore(checkResult)

  return new Response(JSON.stringify({ ...checkResult, score }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=30' },
  })
}
