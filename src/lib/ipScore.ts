import type {
  IpCheckResponse,
  GeoLocation,
  AsnInfo,
  NetworkTypeInfo,
  ProxyDetection,
  AbuseRecord,
  BlacklistRecord,
  ConsistencyCheck,
  NetworkQuality,
  DataSourceInfo,
  IpScoreResult,
  RiskLevel,
  ScoreBreakdown,
  ScoreDeduction,
} from '../types/ipCheck'

export type CheckResult = Omit<IpCheckResponse, 'score'>

// ---------------------------------------------------------------------------
// Scoring dimension: geoTrust (0-15)
// ---------------------------------------------------------------------------

function calculateGeoTrust(
  geo: GeoLocation | null | undefined,
  asn: AsnInfo | null | undefined,
  consistency: ConsistencyCheck | null | undefined,
  deductions: ScoreDeduction[],
): number {
  let score = 15

  if (!geo) {
    deductions.push({
      amount: 15,
      reason: 'No geolocation data available',
      reasonZh: '没有地理位置数据',
      source: 'geo',
      field: 'geo',
    })
    return 0
  }

  if (!asn) {
    deductions.push({
      amount: 3,
      reason: 'No ASN data available',
      reasonZh: '没有ASN数据',
      source: 'asn',
      field: 'asn',
    })
    score -= 3
  }

  if (!geo.country || !geo.city) {
    deductions.push({
      amount: 3,
      reason: 'Incomplete geographic data (missing country or city)',
      reasonZh: '地理数据不完整（缺少国家或城市）',
      source: 'geo',
      field: 'country/city',
    })
    score -= 3
  }

  if (geo.latitude === null || geo.longitude === null) {
    deductions.push({
      amount: 2,
      reason: 'Missing geographic coordinates',
      reasonZh: '缺少地理坐标',
      source: 'geo',
      field: 'latitude/longitude',
    })
    score -= 2
  }

  if (asn && (!asn.asnOrg || /not.?available|unknown|generic/i.test(asn.asnOrg))) {
    deductions.push({
      amount: 2,
      reason: 'Generic or unknown ASN organization',
      reasonZh: '通用或未知的ASN组织',
      source: 'asn',
      field: 'asnOrg',
    })
    score -= 2
  }

  if (consistency && !consistency.timezoneMatch) {
    deductions.push({
      amount: 2,
      reason: `Timezone conflict: geo reports ${geo.timezone}, browser reports ${consistency.timezoneActual}`,
      reasonZh: `时区冲突：地理位置报告${geo.timezone}，浏览器报告${consistency.timezoneActual}`,
      source: 'consistency',
      field: 'timezoneMatch',
    })
    score -= 2
  }

  return Math.max(0, score)
}

// ---------------------------------------------------------------------------
// Scoring dimension: networkType (0-15)
// ---------------------------------------------------------------------------

const NETWORK_TYPE_SCORES: Record<NetworkTypeInfo['type'], number> = {
  residential: 15,
  business: 13,
  mobile: 12,
  education: 10,
  unknown: 7,
  hosting: 3,
  datacenter: 0,
}

function calculateNetworkTypeScore(
  networkType: NetworkTypeInfo | null | undefined,
  deductions: ScoreDeduction[],
): number {
  if (!networkType) {
    deductions.push({
      amount: 15,
      reason: 'No network type data available',
      reasonZh: '没有网络类型数据',
      source: 'networkType',
      field: 'type',
    })
    return 0
  }

  const score = NETWORK_TYPE_SCORES[networkType.type] ?? NETWORK_TYPE_SCORES.unknown
  if (score === 0) {
    deductions.push({
      amount: 15,
      reason: `Datacenter network detected`,
      reasonZh: '检测到数据中心网络',
      source: networkType.source,
      field: 'type',
    })
  } else if (networkType.type === 'hosting') {
    deductions.push({
      amount: 12,
      reason: `Hosting network detected`,
      reasonZh: '检测到托管网络',
      source: networkType.source,
      field: 'type',
    })
  }

  return score
}

// ---------------------------------------------------------------------------
// Scoring dimension: proxyRisk (0-25)
// ---------------------------------------------------------------------------

const PROXY_FLAG_MAP: Array<{
  key: keyof ProxyDetection
  label: string
  labelZh: string
  deduct: number
}> = [
  { key: 'isVpn', label: 'VPN', labelZh: 'VPN', deduct: 10 },
  { key: 'isProxy', label: 'Proxy', labelZh: '代理', deduct: 10 },
  { key: 'isTor', label: 'Tor', labelZh: 'Tor', deduct: 15 },
  { key: 'isHosting', label: 'Hosting', labelZh: '托管', deduct: 8 },
  { key: 'isResidentialProxy', label: 'Residential Proxy', labelZh: '住宅代理', deduct: 12 },
  { key: 'isRelay', label: 'Relay', labelZh: '中继', deduct: 8 },
]

function calculateProxyRisk(
  proxyDetection: ProxyDetection | null | undefined,
  networkType: NetworkTypeInfo | null | undefined,
  deductions: ScoreDeduction[],
): number {
  let score = 25

  if (!proxyDetection) {
    deductions.push({
      amount: 25,
      reason: 'No proxy detection data available',
      reasonZh: '没有代理检测数据',
      source: 'proxyDetection',
      field: 'proxyDetection',
    })
    return 0
  }

  const activeFlags = PROXY_FLAG_MAP.filter(f => proxyDetection[f.key])

  for (const flag of activeFlags) {
    deductions.push({
      amount: flag.deduct,
      reason: `${flag.label} detected`,
      reasonZh: `检测到${flag.labelZh}`,
      source: proxyDetection.source,
      field: flag.key,
    })
    score -= flag.deduct
  }

  // Multiple distinct proxy flags compound the suspicion
  if (activeFlags.length >= 2) {
    deductions.push({
      amount: 3,
      reason: 'Multiple proxy indicators confirmed across different detection methods',
      reasonZh: '多种代理指标在不同检测方法中得到确认',
      source: proxyDetection.source,
      field: 'multiSource',
    })
    score -= 3
  }

  // Conflicting signals: VPN flagged but network type says residential
  if (proxyDetection.isVpn && networkType?.type === 'residential') {
    deductions.push({
      amount: 2,
      reason: 'Conflicting signals: VPN detected but network type indicates residential connection',
      reasonZh: '信号冲突：检测到VPN但网络类型显示为住宅连接',
      source: proxyDetection.source,
      field: 'isVpn/networkType',
    })
    score -= 2
  }

  return Math.max(0, score)
}

// ---------------------------------------------------------------------------
// Scoring dimension: abuseRisk (0-25)
// ---------------------------------------------------------------------------

function calculateAbuseRisk(
  abuseRecord: AbuseRecord | null | undefined,
  blacklistRecords: BlacklistRecord[] | null | undefined,
  deductions: ScoreDeduction[],
): number {
  let score = 25

  if (abuseRecord) {
    const confidence = abuseRecord.confidenceScore ?? 0
    let abuseDeduction = 0

    if (confidence > 80) {
      abuseDeduction = 15
    } else if (confidence > 50) {
      abuseDeduction = 10
    } else if (confidence > 25) {
      abuseDeduction = 5
    } else if (confidence > 0) {
      abuseDeduction = 3
    }

    if (abuseDeduction > 0) {
      deductions.push({
        amount: abuseDeduction,
        reason: `Abuse confidence score ${confidence} (${abuseRecord.source})`,
        reasonZh: `滥用置信度分数 ${confidence}（${abuseRecord.source}）`,
        source: abuseRecord.source,
        field: 'confidenceScore',
      })
      score -= abuseDeduction
    }
  }

  const listedRecords = (blacklistRecords ?? []).filter(r => r.listed)
  for (const record of listedRecords) {
    deductions.push({
      amount: 5,
      reason: `Listed on ${record.listName}`,
      reasonZh: `出现在 ${record.listName} 黑名单中`,
      source: record.source,
      field: record.listName,
    })
    score -= 5
  }

  return Math.max(0, score)
}

// ---------------------------------------------------------------------------
// Scoring dimension: envConsistency (0-10)
// ---------------------------------------------------------------------------

/**
 * Environment consistency is informational only — it detects browser-level
 * configuration (timezone, language, WebRTC, DNS) which reflects HOW the user
 * connects, not the IP's intrinsic quality.
 *
 * Timezone/WebRTC mismatches are EXPECTED when using a proxy and should NOT
 * penalize the IP score. These are shown as a separate informational panel.
 */
function calculateEnvConsistency(
  _consistency: ConsistencyCheck | null | undefined,
  _deductions: ScoreDeduction[],
): number {
  // Always return full marks — environment checks are informational only.
  // The IP score focuses on IP-intrinsic qualities: geo, network type,
  // proxy detection, abuse history, and network quality.
  return 10
}

// ---------------------------------------------------------------------------
// Scoring dimension: networkQuality (0-10)
// ---------------------------------------------------------------------------

function calculateNetworkQualityScore(
  networkQuality: NetworkQuality | null | undefined,
  deductions: ScoreDeduction[],
): number {
  if (!networkQuality) {
    deductions.push({
      amount: 10,
      reason: 'No network quality data available',
      reasonZh: '没有网络质量数据',
      source: 'networkQuality',
      field: 'networkQuality',
    })
    return 0
  }

  let score = 10

  const latency = networkQuality.latencyMs
  if (latency !== null && latency !== undefined) {
    if (latency > 300) {
      deductions.push({
        amount: 3,
        reason: `High latency: ${latency}ms`,
        reasonZh: `高延迟：${latency}毫秒`,
        source: 'networkQuality',
        field: 'latencyMs',
      })
      score -= 3
    } else if (latency > 150) {
      deductions.push({
        amount: 1,
        reason: `Elevated latency: ${latency}ms`,
        reasonZh: `延迟较高：${latency}毫秒`,
        source: 'networkQuality',
        field: 'latencyMs',
      })
      score -= 1
    }
  }

  const packetLoss = networkQuality.packetLoss
  if (packetLoss !== null && packetLoss !== undefined) {
    if (packetLoss > 5) {
      deductions.push({
        amount: 3,
        reason: `High packet loss: ${packetLoss}%`,
        reasonZh: `高丢包率：${packetLoss}%`,
        source: 'networkQuality',
        field: 'packetLoss',
      })
      score -= 3
    } else if (packetLoss > 1) {
      deductions.push({
        amount: 1,
        reason: `Elevated packet loss: ${packetLoss}%`,
        reasonZh: `丢包率较高：${packetLoss}%`,
        source: 'networkQuality',
        field: 'packetLoss',
      })
      score -= 1
    }
  }

  if (!networkQuality.ipv4Supported) {
    deductions.push({
      amount: 2,
      reason: 'IPv4 not supported',
      reasonZh: '不支持IPv4',
      source: 'networkQuality',
      field: 'ipv4Supported',
    })
    score -= 2
  }

  if (networkQuality.ipv6Supported && !networkQuality.ipv4Supported) {
    deductions.push({
      amount: 1,
      reason: 'IPv6-only connection',
      reasonZh: '仅IPv6连接',
      source: 'networkQuality',
      field: 'ipv6Supported',
    })
    score -= 1
  }

  return Math.max(0, score)
}

// ---------------------------------------------------------------------------
// Risk level determination
// ---------------------------------------------------------------------------

function determineRiskLevel(totalScore: number, isUncertain: boolean): RiskLevel {
  if (isUncertain) return 'uncertain'
  if (totalScore >= 85) return 'excellent'
  if (totalScore >= 70) return 'good'
  if (totalScore >= 50) return 'caution'
  if (totalScore >= 30) return 'high_risk'
  return 'not_recommended'
}

function countFailedSources(dataSources: DataSourceInfo[] | null | undefined): number {
  if (!dataSources || dataSources.length === 0) return 0
  return dataSources.filter(ds => ds.status === 'error' || ds.status === 'timeout').length
}

// ---------------------------------------------------------------------------
// Key findings and recommendations
// ---------------------------------------------------------------------------

const RISK_LEVEL_ZH: Record<RiskLevel, string> = {
  excellent: '优秀',
  good: '良好',
  caution: '谨慎',
  high_risk: '高风险',
  not_recommended: '不推荐',
  uncertain: '不确定',
}

function buildKeyFindings(
  geo: GeoLocation | null | undefined,
  asn: AsnInfo | null | undefined,
  proxyDetection: ProxyDetection | null | undefined,
  abuseRecord: AbuseRecord | null | undefined,
  blacklistRecords: BlacklistRecord[] | null | undefined,
  consistency: ConsistencyCheck | null | undefined,
  networkType: NetworkTypeInfo | null | undefined,
  networkQuality: NetworkQuality | null | undefined,
  totalScore: number,
  riskLevel: RiskLevel,
  isUncertain: boolean,
  uncertaintyReason: string | null,
): { en: string[]; zh: string[] } {
  const en: string[] = []
  const zh: string[] = []

  if (isUncertain && uncertaintyReason) {
    en.push(`Uncertain result: ${uncertaintyReason}`)
    zh.push(`结果不确定：${uncertaintyReason}`)
  }

  if (geo?.country) {
    const location = [geo.city, geo.country].filter(Boolean).join(', ')
    en.push(`IP located in ${location}`)
    zh.push(`IP位于 ${location}`)
  }

  if (asn?.asnOrg) {
    en.push(`ISP/ASN: ${asn.asnOrg} (${asn.asn})`)
    zh.push(`ISP/ASN：${asn.asnOrg}（${asn.asn}）`)
  }

  if (networkType?.type) {
    en.push(`Network type: ${networkType.type}`)
    zh.push(`网络类型：${networkType.type}`)
  }

  if (proxyDetection) {
    const flags: string[] = []
    const flagsZh: string[] = []
    if (proxyDetection.isVpn) { flags.push('VPN'); flagsZh.push('VPN') }
    if (proxyDetection.isProxy) { flags.push('Proxy'); flagsZh.push('代理') }
    if (proxyDetection.isTor) { flags.push('Tor'); flagsZh.push('Tor') }
    if (proxyDetection.isResidentialProxy) { flags.push('Residential Proxy'); flagsZh.push('住宅代理') }
    if (proxyDetection.isRelay) { flags.push('Relay'); flagsZh.push('中继') }
    if (proxyDetection.isHosting) { flags.push('Hosting'); flagsZh.push('托管') }

    if (flags.length > 0) {
      en.push(`Proxy/VPN flags detected: ${flags.join(', ')}`)
      zh.push(`检测到代理/VPN标志：${flagsZh.join('、')}`)

      // Conflict note: VPN flagged but network type is residential
      if (proxyDetection.isVpn && networkType?.type === 'residential') {
        en.push('VPN and residential network type conflict — possible misclassification')
        zh.push('VPN与住宅网络类型冲突 — 可能分类错误')
      }
    } else {
      en.push('No proxy or VPN detected')
      zh.push('未检测到代理或VPN')
    }
  }

  if (abuseRecord && abuseRecord.confidenceScore > 0) {
    en.push(`Abuse confidence score: ${abuseRecord.confidenceScore}`)
    zh.push(`滥用置信度分数：${abuseRecord.confidenceScore}`)
  }

  const listedCount = (blacklistRecords ?? []).filter(r => r.listed).length
  if (listedCount > 0) {
    en.push(`Listed on ${listedCount} blacklist(s)`)
    zh.push(`出现在 ${listedCount} 个黑名单中`)
  } else {
    en.push('Not found on any blacklist')
    zh.push('未出现在任何黑名单中')
  }

  if (consistency) {
    if (consistency.timezoneMatch) {
      en.push('Browser timezone matches IP location')
      zh.push('浏览器时区与IP位置匹配')
    } else {
      en.push('Browser timezone does not match IP location')
      zh.push('浏览器时区与IP位置不匹配')
    }
  } else {
    en.push('Browser environment consistency not checked')
    zh.push('未检查浏览器环境一致性')
  }

  if (networkQuality?.latencyMs !== null && networkQuality?.latencyMs !== undefined) {
    en.push(`Network latency: ${networkQuality.latencyMs}ms`)
    zh.push(`网络延迟：${networkQuality.latencyMs}毫秒`)
  }

  en.push(`Overall score: ${totalScore}/100 (${riskLevel})`)
  zh.push(`综合评分：${totalScore}/100（${RISK_LEVEL_ZH[riskLevel]}）`)

  return { en, zh }
}

function buildRecommendation(totalScore: number, riskLevel: RiskLevel): { en: string; zh: string } {
  if (riskLevel === 'uncertain') {
    return {
      en: 'Unable to determine risk level due to insufficient data. Retry the check or review individual data sources.',
      zh: '由于数据不足，无法确定风险级别。请重试检查或查看各个数据源。',
    }
  }
  if (totalScore >= 85) {
    return {
      en: 'This IP address appears legitimate and safe to proceed with standard verification.',
      zh: '此IP地址看起来是合法的，可以进行标准验证。',
    }
  }
  if (totalScore >= 70) {
    return {
      en: 'This IP address has a low risk profile. Standard verification is recommended.',
      zh: '此IP地址风险较低。建议进行标准验证。',
    }
  }
  if (totalScore >= 50) {
    return {
      en: 'This IP address shows some suspicious characteristics. Additional verification is recommended before proceeding.',
      zh: '此IP地址显示出一些可疑特征。建议在进行操作前进行额外验证。',
    }
  }
  if (totalScore >= 30) {
    return {
      en: 'This IP address shows significant risk indicators. Consider blocking or requiring additional identity verification.',
      zh: '此IP地址显示出显著风险指标。考虑阻止或要求额外的身份验证。',
    }
  }
  return {
    en: 'This IP address is not recommended for use. Strongly consider blocking this IP address.',
    zh: '不建议使用此IP地址。强烈建议阻止此IP地址。',
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function calculateIpScore(data: CheckResult): IpScoreResult {
  if (!data) {
    return {
      totalScore: 0,
      riskLevel: 'not_recommended',
      breakdown: [],
      keyFindings: ['No data provided'],
      keyFindingsZh: ['未提供数据'],
      recommendation: 'No data available to calculate score.',
      recommendationZh: '没有可用于计算评分的数据。',
      isUncertain: true,
      uncertaintyReason: 'No input data provided',
    }
  }

  // --- Calculate each dimension ---

  const geoDeductions: ScoreDeduction[] = []
  const geoTrustScore = calculateGeoTrust(data.geo, data.asn, data.consistency, geoDeductions)

  const networkDeductions: ScoreDeduction[] = []
  const networkTypeScore = calculateNetworkTypeScore(data.networkType, networkDeductions)

  const proxyDeductions: ScoreDeduction[] = []
  const proxyRiskScore = calculateProxyRisk(data.proxyDetection, data.networkType, proxyDeductions)

  const abuseDeductions: ScoreDeduction[] = []
  const abuseRiskScore = calculateAbuseRisk(data.abuseRecord, data.blacklistRecords, abuseDeductions)

  const consistencyDeductions: ScoreDeduction[] = []
  const envConsistencyScore = calculateEnvConsistency(data.consistency, consistencyDeductions)

  const qualityDeductions: ScoreDeduction[] = []
  const networkQualityScore = calculateNetworkQualityScore(data.networkQuality, qualityDeductions)

  // --- Uncertainty check ---

  const totalSources = data.dataSources?.length ?? 0
  const failedCount = countFailedSources(data.dataSources)
  const isUncertain = totalSources > 0 && failedCount / totalSources > 0.5

  let uncertaintyReason: string | null = null
  if (isUncertain) {
    const failedNames = (data.dataSources ?? [])
      .filter(ds => ds.status === 'error' || ds.status === 'timeout')
      .map(ds => ds.name)
    uncertaintyReason = `More than 50% of data sources failed: ${failedNames.join(', ')}`
  }

  // --- Total and risk level ---

  const totalScore =
    geoTrustScore +
    networkTypeScore +
    proxyRiskScore +
    abuseRiskScore +
    envConsistencyScore +
    networkQualityScore

  const riskLevel = determineRiskLevel(totalScore, isUncertain)

  // --- Build breakdown ---

  const categoryDefs: Array<{
    label: string
    labelZh: string
    maxScore: number
    score: number
    deductions: ScoreDeduction[]
  }> = [
    { label: 'Geo Trust', labelZh: '地理位置可信度', maxScore: 15, score: geoTrustScore, deductions: geoDeductions },
    { label: 'Network Type', labelZh: '网络类型', maxScore: 15, score: networkTypeScore, deductions: networkDeductions },
    { label: 'Proxy Risk', labelZh: '代理风险', maxScore: 25, score: proxyRiskScore, deductions: proxyDeductions },
    { label: 'Abuse Risk', labelZh: '滥用风险', maxScore: 25, score: abuseRiskScore, deductions: abuseDeductions },
    { label: 'Environment Consistency', labelZh: '环境一致性', maxScore: 10, score: envConsistencyScore, deductions: consistencyDeductions },
    { label: 'Network Quality', labelZh: '网络质量', maxScore: 10, score: networkQualityScore, deductions: qualityDeductions },
  ]

  const breakdown: ScoreBreakdown[] = categoryDefs.map(cat => ({
    category: cat.label,
    categoryZh: cat.labelZh,
    maxScore: cat.maxScore,
    score: cat.score,
    deductions: cat.deductions,
  }))

  // --- Key findings ---

  const findings = buildKeyFindings(
    data.geo,
    data.asn,
    data.proxyDetection,
    data.abuseRecord,
    data.blacklistRecords,
    data.consistency,
    data.networkType,
    data.networkQuality,
    totalScore,
    riskLevel,
    isUncertain,
    uncertaintyReason,
  )

  const recommendation = buildRecommendation(totalScore, riskLevel)

  return {
    totalScore,
    riskLevel,
    breakdown,
    keyFindings: findings.en,
    keyFindingsZh: findings.zh,
    recommendation: recommendation.en,
    recommendationZh: recommendation.zh,
    isUncertain,
    uncertaintyReason,
  }
}

export function getRiskLevelLabel(level: RiskLevel): { en: string; zh: string; color: string } {
  switch (level) {
    case 'excellent':
      return { en: 'Excellent', zh: '优秀', color: 'green' }
    case 'good':
      return { en: 'Good', zh: '良好', color: 'blue' }
    case 'caution':
      return { en: 'Caution', zh: '谨慎', color: 'yellow' }
    case 'high_risk':
      return { en: 'High Risk', zh: '高风险', color: 'orange' }
    case 'not_recommended':
      return { en: 'Not Recommended', zh: '不推荐', color: 'red' }
    case 'uncertain':
      return { en: 'Uncertain', zh: '不确定', color: 'gray' }
  }
}

export function getScoreColor(score: number): string {
  if (score >= 85) return 'text-green-600'
  if (score >= 70) return 'text-blue-600'
  if (score >= 50) return 'text-yellow-600'
  if (score >= 30) return 'text-orange-600'
  return 'text-red-600'
}
