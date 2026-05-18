import { callIpapiCo, callIpinfo } from '../../_shared/dataSources'
import { isValidIp, isPublicIp } from '../../_shared/ipValidator'
import type { DataSourceInfo } from '../../_shared/types'

export const onRequestGet: PagesFunction = async (ctx) => {
  const ip = ctx.request.headers.get('CF-Connecting-IP') || '127.0.0.1'

  if (!isValidIp(ip) || !isPublicIp(ip)) {
    return new Response(JSON.stringify({ error: 'Unable to determine a valid public client IP address.', code: 'INVALID_IP', details: null }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }

  const [ipapi, ipinfo] = await Promise.all([callIpapiCo(ip), callIpinfo(ip)])

  const sources: DataSourceInfo[] = [ipapi.status]
  if (ipinfo) sources.push(ipinfo.status)

  const geo = ipinfo?.geo?.country ? ipinfo.geo : ipapi.geo
  const asn = ipinfo?.asn?.asn || ipinfo?.asn?.asnOrg ? ipinfo.asn : ipapi.asn
  const networkType = ipapi.networkType.type !== 'unknown' ? ipapi.networkType : (ipinfo?.networkType ?? { type: 'unknown', confidence: 0, source: '' })

  return new Response(JSON.stringify({
    ip,
    geo, asn, networkType,
    proxyDetection: ipapi.proxyDetection,
    dataSources: sources,
    checkedAt: new Date().toISOString(),
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' } })
}
