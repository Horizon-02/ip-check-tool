export interface GeoLocation {
  country: string
  countryCode: string
  region: string
  city: string
  latitude: number | null
  longitude: number | null
  timezone: string
}

export interface AsnInfo {
  asn: string
  asnOrg: string
  isp: string
  org: string | null
}

export type NetworkType =
  | 'residential'
  | 'business'
  | 'mobile'
  | 'datacenter'
  | 'hosting'
  | 'education'
  | 'unknown'

export interface NetworkTypeInfo {
  type: NetworkType
  confidence: number
  source: string
}

export interface ProxyDetection {
  isVpn: boolean
  isProxy: boolean
  isTor: boolean
  isRelay: boolean
  isHosting: boolean
  isResidentialProxy: boolean
  confidence: number
  source: string
  details: string
}

export interface AbuseRecord {
  confidenceScore: number
  totalReports: number
  lastReportedAt: string | null
  categories: string[]
  source: string
}

export interface BlacklistRecord {
  listed: boolean
  listName: string
  listType: string
  source: string
}

export interface ConsistencyCheck {
  timezoneMatch: boolean
  timezoneExpected: string
  timezoneActual: string
  languageMatch: boolean
  languageExpected: string[]
  languageActual: string[]
  dnsMatch: boolean
  dnsNote: string
  webrtcMatch: boolean
  webrtcNote: string
}

export interface NetworkQuality {
  latencyMs: number | null
  packetLoss: number | null
  ipv4Supported: boolean
  ipv6Supported: boolean
  connectivityScore: number
}

export type RiskLevel =
  | 'excellent'
  | 'good'
  | 'caution'
  | 'high_risk'
  | 'not_recommended'
  | 'uncertain'

export interface ScoreBreakdown {
  category: string
  categoryZh: string
  maxScore: number
  score: number
  deductions: ScoreDeduction[]
}

export interface ScoreDeduction {
  amount: number
  reason: string
  reasonZh: string
  source: string
  field: string
}

export interface IpScoreResult {
  totalScore: number
  riskLevel: RiskLevel
  breakdown: ScoreBreakdown[]
  keyFindings: string[]
  keyFindingsZh: string[]
  recommendation: string
  recommendationZh: string
  isUncertain: boolean
  uncertaintyReason: string | null
}

export type DataSourceStatus = 'success' | 'error' | 'timeout' | 'not_configured' | 'rate_limited'

export interface DataSourceInfo {
  name: string
  status: DataSourceStatus
  latencyMs: number
  errorMessage: string | null
}

export interface IpCheckResponse {
  ip: string
  geo: GeoLocation
  asn: AsnInfo
  networkType: NetworkTypeInfo
  proxyDetection: ProxyDetection
  abuseRecord: AbuseRecord | null
  blacklistRecords: BlacklistRecord[]
  consistency: ConsistencyCheck | null
  networkQuality: NetworkQuality
  score: IpScoreResult
  dataSources: DataSourceInfo[]
  checkedAt: string
}

export interface IpCheckError {
  error: string
  code: string
  details: string | null
}
