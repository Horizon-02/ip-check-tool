// Simplified scoring engine for Cloudflare Functions
import type { NetworkTypeInfo, ProxyDetection, AbuseRecord, BlacklistRecord, DataSourceInfo, RiskLevel } from './types'

export function calculateScore(check: any): any {
  const deductions: any[] = []
  // Geo trust (0-15)
  const geoScore = check.geo?.country ? 15 : 0
  if (!check.geo?.country) deductions.push({ amount: 15, reason: 'Missing geo data', reasonZh: '缺少地理位置数据', source: 'geo', field: 'geo' })

  // Network type (0-15)
  const ntMap: Record<string, number> = { residential: 15, business: 13, mobile: 12, education: 10, unknown: 7, hosting: 3, datacenter: 0 }
  const ntScore = ntMap[check.networkType?.type ?? 'unknown'] ?? 7

  // Proxy risk (0-25)
  let proxyScore = 25
  const pd = check.proxyDetection
  if (pd?.isTor) { proxyScore -= 15; deductions.push({ amount: 15, reason: 'Tor detected', reasonZh: '检测到Tor', source: pd.source, field: 'isTor' }) }
  if (pd?.isVpn) { proxyScore -= 10; deductions.push({ amount: 10, reason: 'VPN detected', reasonZh: '检测到VPN', source: pd.source, field: 'isVpn' }) }
  if (pd?.isProxy) { proxyScore -= 10; deductions.push({ amount: 10, reason: 'Proxy detected', reasonZh: '检测到代理', source: pd.source, field: 'isProxy' }) }
  if (pd?.isHosting) { proxyScore -= 8; deductions.push({ amount: 8, reason: 'Hosting provider', reasonZh: '托管服务商', source: pd.source, field: 'isHosting' }) }
  if (pd?.isRelay) { proxyScore -= 8; deductions.push({ amount: 8, reason: 'Relay detected', reasonZh: '检测到中继', source: pd.source, field: 'isRelay' }) }
  if (pd?.isResidentialProxy) { proxyScore -= 12; deductions.push({ amount: 12, reason: 'Residential proxy', reasonZh: '住宅代理', source: pd.source, field: 'isResidentialProxy' }) }
  proxyScore = Math.max(0, proxyScore)

  // Abuse risk (0-25)
  let abuseScore = 25
  if (check.abuseRecord?.confidenceScore > 80) { abuseScore -= 15; deductions.push({ amount: 15, reason: 'High abuse score', reasonZh: '高滥用评分', source: check.abuseRecord.source, field: 'confidenceScore' }) }
  else if (check.abuseRecord?.confidenceScore > 50) { abuseScore -= 10; deductions.push({ amount: 10, reason: 'Medium abuse score', reasonZh: '中等滥用评分', source: check.abuseRecord.source, field: 'confidenceScore' }) }
  else if (check.abuseRecord?.confidenceScore > 25) { abuseScore -= 5; deductions.push({ amount: 5, reason: 'Low abuse score', reasonZh: '低滥用评分', source: check.abuseRecord.source, field: 'confidenceScore' }) }
  else if (check.abuseRecord?.confidenceScore > 0) { abuseScore -= 3; deductions.push({ amount: 3, reason: 'Minimal abuse flags', reasonZh: '少量滥用标记', source: check.abuseRecord.source, field: 'confidenceScore' }) }
  for (const bl of (check.blacklistRecords ?? [])) {
    if (bl.listed) { abuseScore -= 5; deductions.push({ amount: 5, reason: `Listed on ${bl.listName}`, reasonZh: `黑名单: ${bl.listName}`, source: bl.source, field: bl.listName }) }
  }
  abuseScore = Math.max(0, abuseScore)

  // Environment consistency is informational only.
  // Browser-level checks (timezone, WebRTC, DNS) reflect HOW the user connects,
  // not the IP's intrinsic quality. Shown separately, not scored.
  const envScore = 10

  // Network quality (0-10)
  let nqScore = 10
  if (check.networkQuality?.latencyMs) {
    if (check.networkQuality.latencyMs > 300) { nqScore -= 3 } else if (check.networkQuality.latencyMs > 150) { nqScore -= 1 }
  }
  nqScore = Math.max(0, nqScore)

  const total = geoScore + ntScore + proxyScore + abuseScore + envScore + nqScore

  // Uncertainty check
  const failedCount = (check.dataSources ?? []).filter((d: DataSourceInfo) => d.status === 'error' || d.status === 'timeout').length
  const totalSources = (check.dataSources ?? []).length
  const isUncertain = totalSources > 0 && failedCount / totalSources > 0.5

  let riskLevel: RiskLevel = 'not_recommended'
  if (isUncertain) riskLevel = 'uncertain'
  else if (total >= 85) riskLevel = 'excellent'
  else if (total >= 70) riskLevel = 'good'
  else if (total >= 50) riskLevel = 'caution'
  else if (total >= 30) riskLevel = 'high_risk'

  const recMap: Record<RiskLevel, string> = {
    excellent: '此IP地址干净。建议进行标准验证。',
    good: '此IP地址风险较低。建议进行标准验证。',
    caution: '此IP地址显示可疑特征。建议额外验证。',
    high_risk: '此IP地址有显著风险。不建议直接信任。',
    not_recommended: '此IP地址极不推荐。强烈建议阻止。',
    uncertain: '数据不足无法确定。请重试或检查数据源。',
  }

  return {
    totalScore: Math.max(0, Math.min(100, total)),
    riskLevel,
    breakdown: [
      { category: 'Geo Trust', categoryZh: '地理位置可信度', maxScore: 15, score: geoScore, deductions: deductions.filter(d => ['geo'].includes(d.source)) },
      { category: 'Network Type', categoryZh: '网络类型', maxScore: 15, score: ntScore, deductions: [] },
      { category: 'Proxy Risk', categoryZh: '代理风险', maxScore: 25, score: proxyScore, deductions: deductions.filter(d => ['isVpn', 'isProxy', 'isTor', 'isHosting', 'isRelay', 'isResidentialProxy'].includes(d.field)) },
      { category: 'Abuse Risk', categoryZh: '滥用风险', maxScore: 25, score: abuseScore, deductions: deductions.filter(d => d.field === 'confidenceScore' || (d.source === 'DNSBL' || d.source === 'AbuseIPDB')) },
      { category: 'Environment Consistency', categoryZh: '环境一致性（信息参考）', maxScore: 10, score: 10, deductions: [] },
      { category: 'Network Quality', categoryZh: '网络质量', maxScore: 10, score: nqScore, deductions: [] },
    ],
    keyFindings: [`Score: ${total}/100`, riskLevel],
    keyFindingsZh: [`评分: ${total}/100`, riskLevel],
    recommendation: recMap[riskLevel],
    recommendationZh: recMap[riskLevel],
    isUncertain,
    uncertaintyReason: isUncertain ? `${failedCount}/${totalSources} data sources failed` : null,
  }
}
