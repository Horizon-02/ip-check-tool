import { describe, it, expect } from 'vitest'
import { calculateIpScore, getRiskLevelLabel, getScoreColor } from '../../src/lib/ipScore'
import type { CheckResult } from '../../src/lib/ipScore'
import type {
  GeoLocation,
  AsnInfo,
  NetworkTypeInfo,
  ProxyDetection,
  NetworkQuality,
  DataSourceInfo,
} from '../../src/types/ipCheck'

// ---------------------------------------------------------------------------
// Helper: build a minimal CheckResult with defaults for optional fields
// ---------------------------------------------------------------------------

function buildCheckResult(overrides: Partial<CheckResult> = {}): CheckResult {
  const defaultGeo: GeoLocation = {
    country: 'US',
    countryCode: 'US',
    region: 'California',
    city: 'Mountain View',
    latitude: 37.4056,
    longitude: -122.0775,
    timezone: 'America/Los_Angeles',
  }

  const defaultAsn: AsnInfo = {
    asn: 'AS15169',
    asnOrg: 'Google LLC',
    isp: 'Google',
    org: 'Google LLC',
  }

  const defaultNetworkType: NetworkTypeInfo = {
    type: 'residential',
    confidence: 80,
    source: 'ipapi.co',
  }

  const defaultProxyDetection: ProxyDetection = {
    isVpn: false,
    isProxy: false,
    isTor: false,
    isRelay: false,
    isHosting: false,
    isResidentialProxy: false,
    confidence: 70,
    source: 'ipapi.co',
    details: 'No proxy detected',
  }

  const defaultNetworkQuality: NetworkQuality = {
    latencyMs: 50,
    packetLoss: null,
    ipv4Supported: true,
    ipv6Supported: true,
    connectivityScore: 10,
  }

  const defaultDataSources: DataSourceInfo[] = [
    { name: 'ipapi.co (geo)', status: 'success', latencyMs: 100, errorMessage: null },
    { name: 'ipapi.co (security)', status: 'success', latencyMs: 100, errorMessage: null },
    { name: 'httpbin.org', status: 'success', latencyMs: 200, errorMessage: null },
  ]

  return {
    ip: '8.8.8.8',
    geo: defaultGeo,
    asn: defaultAsn,
    networkType: defaultNetworkType,
    proxyDetection: defaultProxyDetection,
    abuseRecord: null,
    blacklistRecords: [
      { listed: false, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
    ],
    consistency: null,
    networkQuality: defaultNetworkQuality,
    dataSources: defaultDataSources,
    checkedAt: '2024-06-01T00:00:00.000Z',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('calculateIpScore', () => {
  // --- Clean residential US IP ---
  it('scores clean residential US IP >= 85 (excellent)', () => {
    const result = calculateIpScore(buildCheckResult())
    expect(result.totalScore).toBeGreaterThanOrEqual(85)
    expect(result.riskLevel).toBe('excellent')
    expect(result.isUncertain).toBe(false)
  })

  // --- Datacenter IP (AWS/GCP) ---
  it('scores datacenter IP < 50 (caution or worse)', () => {
    const result = calculateIpScore(
      buildCheckResult({
        ip: '3.4.5.6',
        asn: { asn: 'AS16509', asnOrg: 'Amazon AWS', isp: 'Amazon', org: 'Amazon Web Services' },
        networkType: { type: 'datacenter', confidence: 80, source: 'ipapi.co' },
        proxyDetection: {
          isVpn: false,
          isProxy: false,
          isTor: false,
          isRelay: false,
          isHosting: true,
          isResidentialProxy: false,
          confidence: 70,
          source: 'ipapi.co',
          details: 'Hosting detected',
        },
        abuseRecord: {
          confidenceScore: 85,
          totalReports: 12,
          lastReportedAt: '2024-01-01T00:00:00.000Z',
          categories: ['spam'],
          source: 'AbuseIPDB',
        },
        blacklistRecords: [
          { listed: true, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
          { listed: true, listName: 'Spamhaus', listType: 'spam', source: 'Spamhaus' },
        ],
        dataSources: [
          { name: 'ipapi.co (geo)', status: 'success', latencyMs: 50, errorMessage: null },
          { name: 'ipapi.co (security)', status: 'success', latencyMs: 50, errorMessage: null },
          { name: 'AbuseIPDB', status: 'success', latencyMs: 100, errorMessage: null },
          { name: 'httpbin.org', status: 'success', latencyMs: 200, errorMessage: null },
        ],
      }),
    )
    expect(result.totalScore).toBeLessThan(50)
    // Should be some level of risk
    expect(['caution', 'high_risk', 'not_recommended']).toContain(result.riskLevel)
  })

  // --- VPN-detected IP ---
  it('scores VPN-detected IP lower than clean residential IP', () => {
    const cleanResult = calculateIpScore(buildCheckResult())

    const vpnResult = calculateIpScore(
      buildCheckResult({
        proxyDetection: {
          isVpn: true,
          isProxy: false,
          isTor: false,
          isRelay: false,
          isHosting: false,
          isResidentialProxy: false,
          confidence: 70,
          source: 'ipapi.co',
          details: 'VPN detected',
        },
      }),
    )

    expect(vpnResult.totalScore).toBeLessThan(cleanResult.totalScore)
    // VPN should have a proxy deduction
    const proxyCategory = vpnResult.breakdown.find(c => c.category === 'Proxy Risk')
    expect(proxyCategory).toBeDefined()
    expect(proxyCategory!.deductions.length).toBeGreaterThan(0)
    expect(proxyCategory!.deductions.some(d => d.field === 'isVpn')).toBe(true)
  })

  // --- Tor-detected IP ---
  it('scores Tor-detected IP < 30 (high risk)', () => {
    const result = calculateIpScore(
      buildCheckResult({
        ip: '185.220.101.1',
        geo: {
          country: 'DE',
          countryCode: 'DE',
          region: '',
          city: '',
          latitude: null,
          longitude: null,
          timezone: 'Europe/Berlin',
        },
        asn: { asn: '', asnOrg: '', isp: '', org: null },
        networkType: { type: 'unknown', confidence: 30, source: 'ipapi.co' },
        proxyDetection: {
          isVpn: true,
          isProxy: true,
          isTor: true,
          isRelay: false,
          isHosting: false,
          isResidentialProxy: false,
          confidence: 70,
          source: 'ipapi.co',
          details: 'Tor exit node',
        },
        abuseRecord: {
          confidenceScore: 95,
          totalReports: 100,
          lastReportedAt: '2024-01-01T00:00:00.000Z',
          categories: ['abuse'],
          source: 'AbuseIPDB',
        },
        blacklistRecords: [
          { listed: true, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
          { listed: true, listName: 'Spamhaus', listType: 'spam', source: 'Spamhaus' },
        ],
        networkQuality: {
          latencyMs: 350,
          packetLoss: null,
          ipv4Supported: true,
          ipv6Supported: false,
          connectivityScore: 4,
        },
      }),
    )
    expect(result.totalScore).toBeLessThan(30)
    expect(result.riskLevel).toBe('not_recommended')
    // Tor should be in deductions
    const proxyBreaks = result.breakdown.find(c => c.category === 'Proxy Risk')
    expect(proxyBreaks?.deductions.some(d => d.field === 'isTor')).toBe(true)
  })

  // --- High abuse score IP ---
  it('scores high-abuse IP < 30', () => {
    const result = calculateIpScore(
      buildCheckResult({
        // No geo data — max penalty to push score down
        geo: {
          country: '',
          countryCode: '',
          region: '',
          city: '',
          latitude: null,
          longitude: null,
          timezone: '',
        },
        proxyDetection: {
          isVpn: true,
          isProxy: false,
          isTor: false,
          isRelay: false,
          isHosting: true,
          isResidentialProxy: false,
          confidence: 70,
          source: 'ipapi.co',
          details: 'VPN + hosting detected',
        },
        networkType: { type: 'hosting', confidence: 80, source: 'ipapi.co' },
        abuseRecord: {
          confidenceScore: 90,
          totalReports: 50,
          lastReportedAt: '2024-01-01T00:00:00.000Z',
          categories: ['spam', 'scan'],
          source: 'AbuseIPDB',
        },
        blacklistRecords: [
          { listed: true, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
          { listed: true, listName: 'Spamhaus', listType: 'spam', source: 'Spamhaus' },
        ],
        networkQuality: null as unknown as NetworkQuality,
      }),
    )
    expect(result.totalScore).toBeLessThan(30)
    expect(['high_risk', 'not_recommended']).toContain(result.riskLevel)
    // Abuse deduction should be present
    const abuseBreaks = result.breakdown.find(c => c.category === 'Abuse Risk')
    expect(abuseBreaks?.deductions.some(d => d.field === 'confidenceScore')).toBe(true)
  })

  // --- Multi-source conflict: VPN detected + residential network ---
  it('surfaces conflict deduction when VPN detected on residential network', () => {
    const result = calculateIpScore(
      buildCheckResult({
        proxyDetection: {
          isVpn: true,
          isProxy: false,
          isTor: false,
          isRelay: false,
          isHosting: false,
          isResidentialProxy: false,
          confidence: 70,
          source: 'ipapi.co',
          details: 'VPN detected',
        },
        networkType: { type: 'residential', confidence: 80, source: 'ipapi.co' },
      }),
    )

    const proxyBreaks = result.breakdown.find(c => c.category === 'Proxy Risk')
    expect(proxyBreaks?.deductions.some(d => d.reason.includes('Conflicting signals'))).toBe(true)
    expect(proxyBreaks?.deductions.some(d => d.field === 'isVpn/networkType')).toBe(true)
  })

  // --- All API failure ---
  it('returns isUncertain=true when all data sources have error status', () => {
    const result = calculateIpScore(
      buildCheckResult({
        dataSources: [
          { name: 'ipapi.co (geo)', status: 'error', latencyMs: 5000, errorMessage: 'Timeout' },
          { name: 'ipapi.co (security)', status: 'error', latencyMs: 5000, errorMessage: 'Timeout' },
          { name: 'AbuseIPDB', status: 'error', latencyMs: 5000, errorMessage: 'API error' },
          { name: 'httpbin.org', status: 'error', latencyMs: 5000, errorMessage: 'Timeout' },
        ],
      }),
    )
    expect(result.isUncertain).toBe(true)
    expect(result.uncertaintyReason).toContain('50% of data sources failed')
    expect(result.riskLevel).toBe('uncertain')
  })

  // --- Partial data (missing geo) ---
  it('still produces a score when geo data is incomplete (missing country/city)', () => {
    const result = calculateIpScore(
      buildCheckResult({
        geo: {
          country: '',
          countryCode: '',
          region: '',
          city: '',
          latitude: null,
          longitude: null,
          timezone: '',
        },
      }),
    )
    // Should not crash; should produce some score
    expect(result.totalScore).toBeGreaterThanOrEqual(0)
    expect(result.isUncertain).toBe(false)
    // Geo trust should be reduced
    const geoBreaks = result.breakdown.find(c => c.category === 'Geo Trust')
    expect(geoBreaks!.deductions.length).toBeGreaterThan(0)
  })

  // --- Null input ---
  it('returns isUncertain=true and does not throw for null input', () => {
    const result = calculateIpScore(null as unknown as CheckResult)
    expect(result.isUncertain).toBe(true)
    expect(result.totalScore).toBe(0)
    expect(result.riskLevel).toBe('not_recommended')
  })

  it('returns isUncertain=true and does not throw for undefined input', () => {
    const result = calculateIpScore(undefined as unknown as CheckResult)
    expect(result.isUncertain).toBe(true)
    expect(result.totalScore).toBe(0)
  })

  // --- Blacklist hits ---
  it('deducts 5 points per blacklist hit', () => {
    const noBlacklistResult = calculateIpScore(
      buildCheckResult({
        blacklistRecords: [
          { listed: false, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
        ],
      }),
    )

    const twoBlacklistResult = calculateIpScore(
      buildCheckResult({
        blacklistRecords: [
          { listed: true, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
          { listed: true, listName: 'Spamhaus', listType: 'spam', source: 'Spamhaus' },
        ],
      }),
    )

    // 2 blacklists * 5 points each = 10 point difference in abuse risk
    const noAbuseBreaks = noBlacklistResult.breakdown.find(c => c.category === 'Abuse Risk')
    const twoAbuseBreaks = twoBlacklistResult.breakdown.find(c => c.category === 'Abuse Risk')

    expect(twoAbuseBreaks!.score).toBe(noAbuseBreaks!.score - 10)
    // Each blacklist hit should have a separate deduction
    const blacklistDeductions = twoAbuseBreaks!.deductions.filter(d => d.field !== 'confidenceScore')
    expect(blacklistDeductions.length).toBe(2)
    expect(blacklistDeductions.every(d => d.amount === 5)).toBe(true)
  })

  // --- Single blacklist hit ---
  it('deducts 5 points for a single blacklist hit', () => {
    const result = calculateIpScore(
      buildCheckResult({
        blacklistRecords: [
          { listed: true, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
        ],
      }),
    )

    const abuseBreaks = result.breakdown.find(c => c.category === 'Abuse Risk')
    const listedDeductions = abuseBreaks!.deductions.filter(d => d.field !== 'confidenceScore')
    expect(listedDeductions.length).toBe(1)
    expect(listedDeductions[0].amount).toBe(5)
    expect(listedDeductions[0].reason).toContain('AbuseIPDB')
  })

  // --- Edge cases ---
  it('handles missing networkType gracefully', () => {
    const result = calculateIpScore(
      buildCheckResult({ networkType: undefined as unknown as NetworkTypeInfo }),
    )
    expect(result.totalScore).toBeGreaterThanOrEqual(0)
    expect(result.isUncertain).toBe(false)
  })

  it('handles missing proxyDetection gracefully', () => {
    const result = calculateIpScore(
      buildCheckResult({ proxyDetection: undefined as unknown as ProxyDetection }),
    )
    expect(result.totalScore).toBeGreaterThanOrEqual(0)
    expect(result.isUncertain).toBe(false)
    // proxy risk should be 0 (max deduction)
    const proxyBreaks = result.breakdown.find(c => c.category === 'Proxy Risk')
    expect(proxyBreaks!.score).toBe(0)
  })

  it('handles missing networkQuality gracefully', () => {
    const result = calculateIpScore(
      buildCheckResult({ networkQuality: undefined as unknown as NetworkQuality }),
    )
    expect(result.totalScore).toBeGreaterThanOrEqual(0)
    expect(result.isUncertain).toBe(false)
  })

  it('handles empty dataSources array', () => {
    const result = calculateIpScore(buildCheckResult({ dataSources: [] }))
    expect(result.isUncertain).toBe(false) // 0 total / 0 failed = not triggered
    expect(result.totalScore).toBeGreaterThan(0)
  })

  it('keyFindings includes "not found on any blacklist" when clean', () => {
    const result = calculateIpScore(buildCheckResult())
    expect(result.keyFindings.some(k => k.includes('Not found on any blacklist'))).toBe(true)
  })

  it('keyFindings includes blacklist count when listed', () => {
    const result = calculateIpScore(
      buildCheckResult({
        blacklistRecords: [
          { listed: true, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
        ],
      }),
    )
    expect(result.keyFindings.some(k => k.includes('Listed on'))).toBe(true)
  })

  it('keyFindings includes IP location when geo is present', () => {
    const result = calculateIpScore(buildCheckResult())
    expect(result.keyFindings.some(k => k.includes('IP located in'))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// getRiskLevelLabel
// ---------------------------------------------------------------------------

describe('getRiskLevelLabel', () => {
  it('returns correct labels for each risk level', () => {
    expect(getRiskLevelLabel('excellent')).toEqual({ en: 'Excellent', zh: '优秀', color: 'green' })
    expect(getRiskLevelLabel('good')).toEqual({ en: 'Good', zh: '良好', color: 'blue' })
    expect(getRiskLevelLabel('caution')).toEqual({ en: 'Caution', zh: '谨慎', color: 'yellow' })
    expect(getRiskLevelLabel('high_risk')).toEqual({ en: 'High Risk', zh: '高风险', color: 'orange' })
    expect(getRiskLevelLabel('not_recommended')).toEqual({ en: 'Not Recommended', zh: '不推荐', color: 'red' })
    expect(getRiskLevelLabel('uncertain')).toEqual({ en: 'Uncertain', zh: '不确定', color: 'gray' })
  })
})

// ---------------------------------------------------------------------------
// getScoreColor
// ---------------------------------------------------------------------------

describe('getScoreColor', () => {
  it('returns green for score >= 85', () => {
    expect(getScoreColor(85)).toBe('text-green-600')
    expect(getScoreColor(100)).toBe('text-green-600')
  })

  it('returns blue for score 70-84', () => {
    expect(getScoreColor(70)).toBe('text-blue-600')
    expect(getScoreColor(84)).toBe('text-blue-600')
  })

  it('returns yellow for score 50-69', () => {
    expect(getScoreColor(50)).toBe('text-yellow-600')
    expect(getScoreColor(69)).toBe('text-yellow-600')
  })

  it('returns orange for score 30-49', () => {
    expect(getScoreColor(30)).toBe('text-orange-600')
    expect(getScoreColor(49)).toBe('text-orange-600')
  })

  it('returns red for score < 30', () => {
    expect(getScoreColor(0)).toBe('text-red-600')
    expect(getScoreColor(29)).toBe('text-red-600')
  })
})
