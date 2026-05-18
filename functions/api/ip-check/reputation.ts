import { callIpapiCo, callAbuseIPDB, callDnsbl } from '../../_shared/dataSources'
import { isValidIp, isPublicIp } from '../../_shared/ipValidator'
import type { DataSourceInfo } from '../../_shared/types'

export const onRequestGet: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url)
  const ip = url.searchParams.get('ip')?.trim() || ctx.request.headers.get('CF-Connecting-IP') || ''

  if (!ip) {
    return new Response(JSON.stringify({ error: 'Missing ip parameter', code: 'MISSING_IP', details: null }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }
  if (!isValidIp(ip)) {
    return new Response(JSON.stringify({ error: 'Invalid IP address provided.', code: 'INVALID_IP', details: `"${ip}" is not a valid IPv4 or IPv6 address.` }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }
  if (!isPublicIp(ip)) {
    return new Response(JSON.stringify({ error: 'Only public IP addresses can be checked.', code: 'PRIVATE_IP', details: `"${ip}" is a private, reserved, or non-routable address.` }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }

  const [ipapi, abuse, dnsbl] = await Promise.all([callIpapiCo(ip), callAbuseIPDB(ip), callDnsbl(ip)])

  const dataSources: DataSourceInfo[] = [ipapi.status, dnsbl.status]
  if (abuse) dataSources.unshift(abuse.status)

  return new Response(JSON.stringify({
    ip,
    abuseRecord: abuse?.abuseRecord ?? null,
    blacklistRecords: dnsbl.blacklistRecords,
    proxyDetection: ipapi.proxyDetection,
    dataSources,
    checkedAt: new Date().toISOString(),
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' } })
}
