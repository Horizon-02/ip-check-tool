// Subset of types needed for Cloudflare Functions backend
export interface GeoLocation { country: string; countryCode: string; region: string; city: string; latitude: number | null; longitude: number | null; timezone: string }
export interface AsnInfo { asn: string; asnOrg: string; isp: string; org: string | null }
export interface NetworkTypeInfo { type: string; confidence: number; source: string }
export interface ProxyDetection { isVpn: boolean; isProxy: boolean; isTor: boolean; isRelay: boolean; isHosting: boolean; isResidentialProxy: boolean; confidence: number; source: string; details: string }
export interface AbuseRecord { confidenceScore: number; totalReports: number; lastReportedAt: string | null; categories: string[]; source: string }
export interface BlacklistRecord { listed: boolean; listName: string; listType: string; source: string }
export interface DataSourceInfo { name: string; status: string; latencyMs: number; errorMessage: string | null }
export type RiskLevel = 'excellent' | 'good' | 'caution' | 'high_risk' | 'not_recommended' | 'uncertain'
