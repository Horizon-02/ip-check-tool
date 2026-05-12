import { callIpapiCo, callAbuseIPDB, callDnsbl } from '../../_shared/dataSources'
import type { DataSourceInfo } from '../../_shared/types'

export const onRequestGet: PagesFunction = async (ctx) => {
  const url = new URL(ctx.request.url)
  const ip = url.searchParams.get('ip')?.trim() || ctx.request.headers.get('CF-Connecting-IP') || ''

  if (!ip) {
    return new Response(JSON.stringify({ error: 'Missing ip parameter', code: 'MISSING_IP', details: null }), { status: 400, headers: { 'Content-Type': 'application/json' } })
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
