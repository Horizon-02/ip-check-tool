import {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef,
  type ReactNode,
} from 'react'

import {
  Shield,
  Globe,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  ChevronDown,
  ChevronUp,
  History,
  RefreshCw,
  Search,
  MapPin,
  Building2,
  Activity,
  Ban,
  ListChecks,
  Monitor,
  Network,
  Lightbulb,
  ArrowRight,
  ChevronRight,
  Eye,
} from 'lucide-react'

import type {
  IpCheckResponse,
  RiskLevel,
  DataSourceStatus,
  NetworkType,
  GeoLocation,
  AsnInfo,
  ProxyDetection,
  AbuseRecord,
  BlacklistRecord,
  ConsistencyCheck,
  NetworkQuality,
  DataSourceInfo,
} from '../types/ipCheck'
import { checkIpScore, ApiError } from '../lib/api'
import {
  collectBrowserSignals,
  detectWebRtcIp,
} from '../lib/envConsistency'

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

interface HistoryEntry {
  ip: string
  totalScore: number
  riskLevel: RiskLevel
  location: string
  checkedAt: string
}

const HISTORY_KEY = 'ip-check-history'
const MAX_HISTORY = 10

function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY)
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : []
  } catch {
    return []
  }
}

function saveHistoryEntry(data: IpCheckResponse): void {
  const history = loadHistory()
  const entry: HistoryEntry = {
    ip: data.ip,
    totalScore: data.score.totalScore,
    riskLevel: data.score.riskLevel,
    location: [data.geo.city, data.geo.country].filter(Boolean).join(', '),
    checkedAt: data.checkedAt,
  }
  const updated = [entry, ...history.filter((h) => h.ip !== data.ip)].slice(
    0,
    MAX_HISTORY,
  )
  localStorage.setItem(HISTORY_KEY, JSON.stringify(updated))
}

function clearHistory(): void {
  localStorage.removeItem(HISTORY_KEY)
}

// ---------------------------------------------------------------------------
// Risk-level helpers
// ---------------------------------------------------------------------------

interface RiskLevelConfig {
  label: string
  labelZh: string
  dotClass: string
  badgeClass: string
  ringColor: string
  barColor: string
  textClass: string
}

const RISK_CONFIG: Record<RiskLevel, RiskLevelConfig> = {
  excellent: {
    label: 'Excellent',
    labelZh: '优秀',
    dotClass: 'bg-accent-teal',
    badgeClass:
      'bg-accent-teal/15 text-accent-teal border-accent-teal/30',
    ringColor: '#2dd4bf',
    barColor: '#2dd4bf',
    textClass: 'text-accent-teal',
  },
  good: {
    label: 'Good',
    labelZh: '良好',
    dotClass: 'bg-accent-blue',
    badgeClass: 'bg-accent-blue/15 text-accent-blue border-accent-blue/30',
    ringColor: '#60a5fa',
    barColor: '#60a5fa',
    textClass: 'text-accent-blue',
  },
  caution: {
    label: 'Caution',
    labelZh: '谨慎',
    dotClass: 'bg-accent-amber',
    badgeClass:
      'bg-accent-amber/15 text-accent-amber border-accent-amber/30',
    ringColor: '#fbbf24',
    barColor: '#fbbf24',
    textClass: 'text-accent-amber',
  },
  high_risk: {
    label: 'High Risk',
    labelZh: '高风险',
    dotClass: 'bg-orange-400',
    badgeClass: 'bg-orange-400/15 text-orange-400 border-orange-400/30',
    ringColor: '#fb923c',
    barColor: '#fb923c',
    textClass: 'text-orange-400',
  },
  not_recommended: {
    label: 'Not Recommended',
    labelZh: '不推荐',
    dotClass: 'bg-accent-rose',
    badgeClass: 'bg-accent-rose/15 text-accent-rose border-accent-rose/30',
    ringColor: '#f43f5e',
    barColor: '#f43f5e',
    textClass: 'text-accent-rose',
  },
  uncertain: {
    label: 'Uncertain',
    labelZh: '不确定',
    dotClass: 'bg-ash-400',
    badgeClass: 'bg-ash-500/20 text-ash-300 border-ash-500/30',
    ringColor: '#7d7d8f',
    barColor: '#7d7d8f',
    textClass: 'text-ash-400',
  },
}

function getRiskConfig(level: RiskLevel): RiskLevelConfig {
  return RISK_CONFIG[level] ?? RISK_CONFIG.uncertain
}

function getScoreRiskLevel(score: number): RiskLevel {
  if (score >= 85) return 'excellent'
  if (score >= 70) return 'good'
  if (score >= 50) return 'caution'
  if (score >= 30) return 'high_risk'
  return 'not_recommended'
}

const NETWORK_TYPE_LABELS: Record<NetworkType, { en: string; zh: string }> = {
  residential: { en: 'Residential', zh: '住宅' },
  business: { en: 'Business', zh: '商业' },
  mobile: { en: 'Mobile', zh: '移动' },
  datacenter: { en: 'Datacenter', zh: '数据中心' },
  hosting: { en: 'Hosting', zh: '托管' },
  education: { en: 'Education', zh: '教育' },
  unknown: { en: 'Unknown', zh: '未知' },
}

const DS_STATUS_LABELS: Record<
  DataSourceStatus,
  { en: string; zh: string }
> = {
  success: { en: 'Success', zh: '成功' },
  error: { en: 'Error', zh: '错误' },
  timeout: { en: 'Timeout', zh: '超时' },
  not_configured: { en: 'Not Configured', zh: '未配置' },
  rate_limited: { en: 'Rate Limited', zh: '限流' },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDateTime(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return iso
  }
}

function formatRelativeTime(iso: string): string {
  try {
    const now = Date.now()
    const then = new Date(iso).getTime()
    const diffSec = Math.floor((now - then) / 1000)
    if (diffSec < 60) return `${diffSec} 秒前`
    const diffMin = Math.floor(diffSec / 60)
    if (diffMin < 60) return `${diffMin} 分钟前`
    const diffHr = Math.floor(diffMin / 60)
    if (diffHr < 24) return `${diffHr} 小时前`
    const diffDay = Math.floor(diffHr / 24)
    return `${diffDay} 天前`
  } catch {
    return ''
  }
}

function formatLatency(ms: number | null): string {
  if (ms === null || ms === undefined) return '--'
  return `${ms}ms`
}

function getPartialWarnings(dataSources: DataSourceInfo[]): string[] {
  const failed = dataSources.filter(
    (ds) => ds.status === 'error' || ds.status === 'timeout',
  )
  return failed.map(
    (ds) =>
      `${ds.name}: ${DS_STATUS_LABELS[ds.status].zh} (${DS_STATUS_LABELS[ds.status].en})${
        ds.errorMessage ? ` — ${ds.errorMessage}` : ''
      }`,
  )
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** SVG score ring donut chart */
function ScoreRing({
  score,
  riskLevel,
  size = 160,
  strokeWidth = 10,
}: {
  score: number
  riskLevel: RiskLevel
  size?: number
  strokeWidth?: number
}) {
  const cfg = getRiskConfig(riskLevel)
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - Math.min(score, 100) / 100)

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg
        width={size}
        height={size}
        className="-rotate-90"
        aria-label={`Score: ${score} out of 100`}
      >
        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#2a2a33"
          strokeWidth={strokeWidth}
        />
        {/* Foreground arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={cfg.ringColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="score-ring"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold tracking-tight" style={{ color: cfg.ringColor }}>
          {score}
        </span>
        <span className="text-xs text-ash-400 mt-0.5">/ 100</span>
      </div>
    </div>
  )
}

/** Colored risk badge */
function RiskBadge({ riskLevel }: { riskLevel: RiskLevel }) {
  const cfg = getRiskConfig(riskLevel)
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${cfg.badgeClass}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dotClass}`} />
      {cfg.labelZh} · {cfg.label}
    </span>
  )
}

/** Dimension score bar */
function ScoreBar({
  label,
  labelZh,
  score,
  maxScore,
  riskLevel,
}: {
  label: string
  labelZh: string
  score: number
  maxScore: number
  riskLevel: RiskLevel
}) {
  const pct = Math.min((score / maxScore) * 100, 100)
  const cfg = getRiskConfig(riskLevel)
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-sm">
        <span className="text-ash-200">
          {labelZh}
          <span className="text-ash-500 ml-1.5 hidden sm:inline">· {label}</span>
        </span>
        <span className="font-mono text-xs tabular-nums text-ash-300">
          {score}/{maxScore}
        </span>
      </div>
      <div className="w-full h-2 bg-ash-800 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${pct}%`, backgroundColor: cfg.barColor }}
        />
      </div>
    </div>
  )
}

/** Collapsible detail section */
function ExpandableSection({
  icon,
  title,
  titleZh,
  defaultOpen = false,
  children,
  badge,
}: {
  icon: ReactNode
  title: string
  titleZh: string
  defaultOpen?: boolean
  children: ReactNode
  badge?: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  const id = useRef(`section-${Math.random().toString(36).slice(2, 8)}`).current

  return (
    <div className="glass-card overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-5 py-4 text-left transition-colors hover:bg-white/[0.02]"
        aria-expanded={open}
        aria-controls={id}
      >
        <div className="flex items-center gap-3">
          <span className="text-ash-400 shrink-0">{icon}</span>
          <span className="text-sm font-medium text-ash-100">
            {titleZh}
            <span className="text-ash-500 ml-2 hidden sm:inline">· {title}</span>
          </span>
          {badge && <span className="ml-2">{badge}</span>}
        </div>
        {open ? (
          <ChevronUp className="w-4 h-4 text-ash-400 shrink-0" />
        ) : (
          <ChevronDown className="w-4 h-4 text-ash-400 shrink-0" />
        )}
      </button>
      <div
        id={id}
        className={`transition-all duration-300 ease-out ${
          open ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0 overflow-hidden'
        }`}
      >
        <div className="px-5 pb-5 pt-1 border-t border-ash-800/50">{children}</div>
      </div>
    </div>
  )
}

/** Key-value row for detail tables */
function DetailRow({
  label,
  labelZh,
  value,
  mono = false,
}: {
  label: string
  labelZh: string
  value: ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-ash-800/30 last:border-b-0">
      <span className="text-xs text-ash-400 shrink-0 min-w-[6rem]">
        {labelZh}
        <span className="hidden sm:inline"> · {label}</span>
      </span>
      <span
        className={`text-sm text-ash-200 text-right ${
          mono ? 'font-mono' : ''
        }`}
      >
        {value ?? <span className="text-ash-500">--</span>}
      </span>
    </div>
  )
}

/** Boolean indicator with icon */
function BoolIndicator({ ok }: { ok: boolean }) {
  return ok ? (
    <span className="inline-flex items-center gap-1 text-accent-teal">
      <CheckCircle className="w-3.5 h-3.5" />
      <span className="text-xs">Yes</span>
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-accent-rose">
      <XCircle className="w-3.5 h-3.5" />
      <span className="text-xs">No</span>
    </span>
  )
}

/** Status dot for data sources */
function StatusDot({ status }: { status: DataSourceStatus }) {
  return <span className={`status-dot ${status}`} />
}

/** Skeleton loader for loading state */
function SkeletonBlock({ className = '' }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded-xl bg-ash-800/50 ${className}`}
    />
  )
}

function LoadingSkeleton() {
  return (
    <div className="space-y-5 mt-6">
      {/* Top row skeleton */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="glass-card p-8 flex flex-col items-center gap-4">
          <SkeletonBlock className="w-40 h-40 rounded-full" />
          <SkeletonBlock className="w-28 h-6 rounded-full" />
        </div>
        <div className="glass-card p-6 space-y-4">
          <SkeletonBlock className="h-6 w-48" />
          <SkeletonBlock className="h-4 w-64" />
          <SkeletonBlock className="h-4 w-40" />
          <SkeletonBlock className="h-4 w-56" />
          <SkeletonBlock className="h-5 w-24 rounded-full" />
        </div>
      </div>
      {/* Score bars skeleton */}
      <div className="glass-card p-6 space-y-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="space-y-1.5">
            <SkeletonBlock className="h-4 w-32" />
            <SkeletonBlock className="h-2 w-full rounded-full" />
          </div>
        ))}
      </div>
      {/* Sections skeleton */}
      {Array.from({ length: 4 }).map((_, i) => (
        <SkeletonBlock key={i} className="h-14 w-full" />
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Network type badge
// ---------------------------------------------------------------------------

function NetworkTypeBadge({ type }: { type: NetworkType }) {
  const label = NETWORK_TYPE_LABELS[type] ?? NETWORK_TYPE_LABELS.unknown
  const colorMap: Record<NetworkType, string> = {
    residential: 'bg-accent-teal/15 text-accent-teal border-accent-teal/30',
    business: 'bg-accent-blue/15 text-accent-blue border-accent-blue/30',
    mobile: 'bg-accent-purple/15 text-accent-purple border-accent-purple/30',
    datacenter: 'bg-accent-rose/15 text-accent-rose border-accent-rose/30',
    hosting: 'bg-orange-400/15 text-orange-400 border-orange-400/30',
    education: 'bg-accent-amber/15 text-accent-amber border-accent-amber/30',
    unknown: 'bg-ash-500/20 text-ash-300 border-ash-500/30',
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-medium border ${
        colorMap[type] ?? colorMap.unknown
      }`}
    >
      {label.zh}
      <span className="ml-1 hidden sm:inline">· {label.en}</span>
    </span>
  )
}

// ---------------------------------------------------------------------------
// Detail section content components
// ---------------------------------------------------------------------------

function GeoSection({ geo }: { geo: GeoLocation }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
      <DetailRow
        label="Country"
        labelZh="国家"
        value={geo.country || <span className="text-ash-500">--</span>}
      />
      <DetailRow
        label="Country Code"
        labelZh="国家代码"
        value={geo.countryCode || '--'}
        mono
      />
      <DetailRow
        label="Region"
        labelZh="地区"
        value={geo.region || '--'}
      />
      <DetailRow
        label="City"
        labelZh="城市"
        value={geo.city || '--'}
      />
      <DetailRow
        label="Coordinates"
        labelZh="坐标"
        value={
          geo.latitude != null && geo.longitude != null
            ? `${geo.latitude.toFixed(4)}, ${geo.longitude.toFixed(4)}`
            : '--'
        }
        mono
      />
      <DetailRow
        label="Timezone"
        labelZh="时区"
        value={geo.timezone || '--'}
        mono
      />
    </div>
  )
}

function AsnSection({ asn }: { asn: AsnInfo }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
      <DetailRow label="ASN" labelZh="ASN" value={asn.asn || '--'} mono />
      <DetailRow
        label="Organization"
        labelZh="组织"
        value={asn.asnOrg || '--'}
      />
      <DetailRow label="ISP" labelZh="ISP" value={asn.isp || '--'} />
      <DetailRow
        label="Organization (Raw)"
        labelZh="原始组织"
        value={asn.org ?? '--'}
      />
    </div>
  )
}

function ProxySection({
  proxy,
}: {
  proxy: ProxyDetection
}) {
  const flags: Array<{ key: keyof ProxyDetection; label: string; labelZh: string }> = [
    { key: 'isVpn', label: 'VPN', labelZh: 'VPN' },
    { key: 'isProxy', label: 'Proxy', labelZh: '代理' },
    { key: 'isTor', label: 'Tor', labelZh: 'Tor' },
    { key: 'isHosting', label: 'Hosting', labelZh: '托管' },
    { key: 'isResidentialProxy', label: 'Residential Proxy', labelZh: '住宅代理' },
    { key: 'isRelay', label: 'Relay', labelZh: '中继' },
  ]

  const flagged = flags.filter((f) => proxy[f.key])

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {flags.map((f) => (
          <div
            key={f.key}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${
              proxy[f.key]
                ? 'bg-accent-rose/10 border-accent-rose/20 text-accent-rose'
                : 'bg-ash-800/30 border-ash-800/40 text-ash-500'
            }`}
          >
            {proxy[f.key] ? (
              <AlertTriangle className="w-3.5 h-3.5" />
            ) : (
              <CheckCircle className="w-3.5 h-3.5" />
            )}
            <span>{f.labelZh}</span>
            <span className="hidden sm:inline text-[10px] opacity-60">· {f.label}</span>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 pt-2">
        <DetailRow
          label="Confidence"
          labelZh="置信度"
          value={
            <span className="font-mono">{proxy.confidence}%</span>
          }
        />
        <DetailRow
          label="Source"
          labelZh="来源"
          value={proxy.source || '--'}
        />
        {flagged.length > 0 && (
          <div className="col-span-1 sm:col-span-2">
            <DetailRow
              label="Details"
              labelZh="详情"
              value={proxy.details || '--'}
            />
          </div>
        )}
      </div>
    </div>
  )
}

function AbuseSection({
  abuse,
  blacklistRecords,
}: {
  abuse: AbuseRecord | null
  blacklistRecords: BlacklistRecord[]
}) {
  const listedRecords = blacklistRecords.filter((r) => r.listed)
  const listedCount = listedRecords.length
  const abuseScore = abuse?.confidenceScore ?? 0

  return (
    <div className="space-y-4">
      {/* Abuse record */}
      <div>
        <h4 className="text-xs font-semibold text-ash-400 uppercase tracking-wider mb-3">
          滥用记录 · Abuse Record
        </h4>
        {abuse ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
            <DetailRow
              label="Confidence Score"
              labelZh="置信度分数"
              value={
                <span
                  className={`font-mono ${
                    abuseScore > 50 ? 'text-accent-rose' : abuseScore > 0 ? 'text-accent-amber' : 'text-accent-teal'
                  }`}
                >
                  {abuseScore}
                </span>
              }
            />
            <DetailRow
              label="Total Reports"
              labelZh="报告总数"
              value={
                <span className="font-mono">{abuse.totalReports}</span>
              }
            />
            <DetailRow
              label="Categories"
              labelZh="类别"
              value={
                abuse.categories.length > 0
                  ? abuse.categories.join(', ')
                  : '--'
              }
            />
            <DetailRow
              label="Last Reported"
              labelZh="最后报告"
              value={
                abuse.lastReportedAt
                  ? formatRelativeTime(abuse.lastReportedAt)
                  : 'Never'
              }
            />
            <DetailRow
              label="Source"
              labelZh="来源"
              value={abuse.source || '--'}
            />
          </div>
        ) : (
          <p className="text-xs text-ash-500">无滥用记录数据 · No abuse record data</p>
        )}
      </div>

      {/* Blacklist */}
      <div>
        <h4 className="text-xs font-semibold text-ash-400 uppercase tracking-wider mb-3">
          黑名单 · Blacklist
        </h4>
        {blacklistRecords.length > 0 ? (
          <div className="space-y-1.5">
            {blacklistRecords.map((r, i) => (
              <div
                key={i}
                className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs ${
                  r.listed
                    ? 'bg-accent-rose/8 border border-accent-rose/15'
                    : 'bg-ash-800/20 border border-ash-800/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <StatusDot
                    status={r.listed ? 'error' : 'success'}
                  />
                  <span className="text-ash-200">{r.listName}</span>
                  <span className="text-ash-500 hidden sm:inline">
                    · {r.listType}
                  </span>
                </div>
                <span className="text-ash-500">{r.source}</span>
              </div>
            ))}
            {listedCount > 0 && (
              <p className="text-xs text-accent-rose mt-2">
                在 {listedCount} 个黑名单中找到匹配 · Listed on {listedCount} blacklist(s)
              </p>
            )}
          </div>
        ) : (
          <p className="text-xs text-ash-500">无黑名单数据 · No blacklist data</p>
        )}
      </div>
    </div>
  )
}

function ConsistencySection({
  consistency,
}: {
  consistency: ConsistencyCheck | null
}) {
  if (!consistency) {
    return (
      <p className="text-xs text-ash-500">
        未收集浏览器环境一致性数据
        <br />
        <span className="text-ash-600">Browser environment consistency data not collected</span>
      </p>
    )
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
      <DetailRow
        label="Timezone Match"
        labelZh="时区匹配"
        value={
          <div className="flex items-center gap-2">
            <BoolIndicator ok={consistency.timezoneMatch} />
            <span className="font-mono text-[11px] text-ash-500">
              {consistency.timezoneActual}
            </span>
          </div>
        }
      />
      <DetailRow
        label="Expected Timezone"
        labelZh="期望时区"
        value={
          <span className="font-mono text-xs text-ash-400">
            {consistency.timezoneExpected}
          </span>
        }
        mono
      />
      <DetailRow
        label="Language Match"
        labelZh="语言匹配"
        value={<BoolIndicator ok={consistency.languageMatch} />}
      />
      <DetailRow
        label="Browser Languages"
        labelZh="浏览器语言"
        value={
          <span className="text-xs text-ash-300">
            {consistency.languageActual.join(', ')}
          </span>
        }
      />
      <DetailRow
        label="DNS Match"
        labelZh="DNS 匹配"
        value={<BoolIndicator ok={consistency.dnsMatch} />}
      />
      <DetailRow
        label="DNS Note"
        labelZh="DNS 说明"
        value={
          <span className="text-xs text-ash-400">
            {consistency.dnsNote || '--'}
          </span>
        }
      />
      <div className="col-span-1 sm:col-span-2">
        <DetailRow
          label="WebRTC Match"
          labelZh="WebRTC 匹配"
          value={<BoolIndicator ok={consistency.webrtcMatch} />}
        />
      </div>
      {consistency.webrtcNote && (
        <div className="col-span-1 sm:col-span-2">
          <DetailRow
            label="WebRTC Note"
            labelZh="WebRTC 说明"
            value={
              <span className="text-xs text-ash-400">
                {consistency.webrtcNote}
              </span>
            }
          />
        </div>
      )}
    </div>
  )
}

function NetworkQualitySection({
  quality,
}: {
  quality: NetworkQuality
}) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
      <DetailRow
        label="Latency"
        labelZh="延迟"
        value={
          <span className="font-mono">{formatLatency(quality.latencyMs)}</span>
        }
      />
      <DetailRow
        label="Packet Loss"
        labelZh="丢包率"
        value={
          <span className="font-mono">
            {quality.packetLoss != null ? `${quality.packetLoss}%` : '--'}
          </span>
        }
      />
      <DetailRow
        label="IPv4"
        labelZh="IPv4"
        value={<BoolIndicator ok={quality.ipv4Supported} />}
      />
      <DetailRow
        label="IPv6"
        labelZh="IPv6"
        value={<BoolIndicator ok={quality.ipv6Supported} />}
      />
      <DetailRow
        label="Connectivity Score"
        labelZh="连接质量评分"
        value={
          <span className="font-mono">{quality.connectivityScore}/100</span>
        }
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export function IpCheckPage() {
  // --- State ---
  const [data, setData] = useState<IpCheckResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [partialWarnings, setPartialWarnings] = useState<string[]>([])
  const [inputIp, setInputIp] = useState('')
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory)
  const [showHistory, setShowHistory] = useState(false)

  const abortRef = useRef<AbortController | null>(null)

  // --- Data fetching ---

  const handleResult = useCallback((result: IpCheckResponse) => {
    setData(result)
    setError(null)

    // Collect browser signals and reconcile with geo data
    const browserSignals = collectBrowserSignals(
      result.geo.timezone,
      result.consistency?.languageExpected ?? undefined,
    )

    // Attempt WebRTC detection in the background
    detectWebRtcIp().then((webrtcIp) => {
      const webrtcMatch = webrtcIp === result.ip
      // Update consistency with WebRTC info if available
      // We store this in a local update — for now it's informative
      if (webrtcIp) {
        setData((prev) => {
          if (!prev) return prev
          return {
            ...prev,
            consistency: prev.consistency
              ? {
                  ...prev.consistency,
                  webrtcMatch,
                  webrtcNote: webrtcMatch
                    ? `WebRTC IP (${webrtcIp}) matches checked IP address`
                    : `WebRTC IP (${webrtcIp}) differs from checked IP (${prev.ip})`,
                }
              : {
                  ...browserSignals,
                  webrtcMatch,
                  webrtcNote: `WebRTC local IP: ${webrtcIp}`,
                },
          }
        })
      }
    })

    // Update consistency with browser signals
    setData((prev) => {
      if (!prev) return prev
      return {
        ...prev,
        consistency: {
          ...browserSignals,
          dnsMatch: prev.consistency?.dnsMatch ?? false,
          dnsNote: prev.consistency?.dnsNote ?? 'DNS comparison requires server-side resolver data',
          webrtcMatch: prev.consistency?.webrtcMatch ?? false,
          webrtcNote: prev.consistency?.webrtcNote ?? 'WebRTC check pending',
        },
      }
    })

    // Check for partial failures
    if (result.dataSources && result.dataSources.length > 0) {
      const warnings = getPartialWarnings(result.dataSources)
      setPartialWarnings(warnings)
    } else {
      setPartialWarnings([])
    }

    // Save to history
    saveHistoryEntry(result)
    setHistory(loadHistory())
  }, [])

  const handleError = useCallback((err: unknown) => {
    if (err instanceof ApiError) {
      setError(err.message)
    } else if (err instanceof Error) {
      setError(err.message)
    } else {
      setError('未知错误 · Unknown error')
    }
    setData(null)
  }, [])

  const fetchData = useCallback(
    async (ip?: string) => {
      // Abort any in-flight request
      if (abortRef.current) {
        abortRef.current.abort()
      }
      abortRef.current = new AbortController()

      setLoading(true)
      setError(null)
      setPartialWarnings([])

      const signal = abortRef.current?.signal
      try {
        const result = await checkIpScore(ip, signal)
        // Only process if this request wasn't superseded
        if (abortRef.current?.signal === signal) {
          handleResult(result)
        }
      } catch (err) {
        // Ignore aborted requests (component unmount or superseded by new search)
        if (err instanceof DOMException && err.name === 'AbortError') return
        if (err instanceof ApiError && err.code === 'TIMEOUT') {
          handleError(err)
          return
        }
        // Only set error if this request is still the current one
        if (abortRef.current?.signal === signal) {
          handleError(err)
        }
      } finally {
        setLoading(false)
        if (abortRef.current?.signal === signal) {
          abortRef.current = null
        }
      }
    },
    [handleResult, handleError],
  )

  // Auto-detect on mount
  useEffect(() => {
    fetchData()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortRef.current) {
        abortRef.current.abort()
      }
    }
  }, [])

  // --- Handlers ---

  const handleSearch = useCallback(() => {
    const trimmed = inputIp.trim()
    if (!trimmed) return
    fetchData(trimmed)
  }, [inputIp, fetchData])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') handleSearch()
    },
    [handleSearch],
  )

  const handleRetry = useCallback(() => {
    fetchData(data?.ip)
  }, [data?.ip, fetchData])

  const handleHistoryClick = useCallback(
    (ip: string) => {
      setInputIp(ip)
      fetchData(ip)
      setShowHistory(false)
    },
    [fetchData],
  )

  const handleClearHistory = useCallback(() => {
    clearHistory()
    setHistory([])
  }, [])

  // --- Derived ---

  const scoreConfig = useMemo(
    () => (data ? getRiskConfig(data.score.riskLevel) : null),
    [data],
  )

  const totalFailedSources = useMemo(
    () =>
      data?.dataSources?.filter(
        (ds) => ds.status === 'error' || ds.status === 'timeout',
      ).length ?? 0,
    [data],
  )

  const totalDataSources = useMemo(
    () => data?.dataSources?.length ?? 0,
    [data],
  )

  // --- Render ---

  return (
    <div className="min-h-screen bg-surface">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-10">
        {/* ===== Header ===== */}
        <header className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Shield className="w-7 h-7 sm:w-8 sm:h-8 text-accent-teal" />
            <h1 className="text-2xl sm:text-3xl font-bold text-ash-50 tracking-tight">
              IP 检测工具
            </h1>
          </div>
          <p className="text-sm text-ash-400">
            IP Reputation Checker
            <span className="mx-2 text-ash-600">·</span>
            评估 IP 地址的信任度、匿名代理和网络质量
          </p>
        </header>

        {/* ===== Search ===== */}
        <section className="glass-card p-4 sm:p-5 mb-6">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ash-500" />
              <input
                type="text"
                value={inputIp}
                onChange={(e) => setInputIp(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="输入 IP 地址 · Enter IP address (e.g. 8.8.8.8)"
                className="w-full h-10 pl-10 pr-3 bg-ash-800/50 border border-ash-700/50 rounded-xl text-sm text-ash-100 placeholder:text-ash-500 focus:outline-none focus:ring-2 focus:ring-accent-teal/40 focus:border-accent-teal/40 transition-all font-mono"
                aria-label="IP address input"
                disabled={loading}
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleSearch}
                disabled={loading || !inputIp.trim()}
                className="flex items-center justify-center gap-2 h-10 px-5 rounded-xl bg-accent-teal/15 text-accent-teal border border-accent-teal/25 text-sm font-medium hover:bg-accent-teal/25 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                aria-label="Search IP"
              >
                <Search className="w-4 h-4" />
                <span className="hidden sm:inline">查询 · Search</span>
              </button>
              <button
                onClick={() => fetchData()}
                disabled={loading}
                className="flex items-center justify-center gap-2 h-10 px-4 rounded-xl bg-ash-800/50 text-ash-300 border border-ash-700/50 text-sm hover:bg-ash-700/50 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                aria-label="Auto detect current IP"
              >
                <RefreshCw
                  className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`}
                />
                <span className="hidden sm:inline">自动检测 · Auto</span>
              </button>
            </div>
          </div>
        </section>

        {/* ===== Error State ===== */}
        {error && !loading && !data && (
          <section className="glass-card p-8 text-center">
            <XCircle className="w-12 h-12 text-accent-rose mx-auto mb-4" />
            <h2 className="text-lg font-semibold text-ash-200 mb-2">
              检测失败 · Check Failed
            </h2>
            <p className="text-sm text-ash-400 mb-6 max-w-md mx-auto">{error}</p>
            <button
              onClick={handleRetry}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-accent-rose/15 text-accent-rose border border-accent-rose/25 text-sm font-medium hover:bg-accent-rose/25 transition-all"
            >
              <RefreshCw className="w-4 h-4" />
              重试 · Retry
            </button>
          </section>
        )}

        {/* ===== Empty State ===== */}
        {!data && !loading && !error && (
          <section className="glass-card p-12 text-center">
            <div className="w-20 h-20 mx-auto mb-5 rounded-full bg-ash-800/50 flex items-center justify-center">
              <Eye className="w-10 h-10 text-ash-500" />
            </div>
            <h2 className="text-lg font-semibold text-ash-300 mb-2">
              准备就绪 · Ready
            </h2>
            <p className="text-sm text-ash-500 max-w-sm mx-auto leading-relaxed">
              输入 IP 地址或点击自动检测开始评估
              <br />
              <span className="text-ash-600">
                Enter an IP address or click Auto Detect to begin evaluation
              </span>
            </p>
          </section>
        )}

        {/* ===== Loading State ===== */}
        {loading && !data && <LoadingSkeleton />}

        {/* ===== Results ===== */}
        {data && (
          <div className="space-y-5">
            {/* Partial warning banner */}
            {partialWarnings.length > 0 && (
              <div className="flex items-start gap-3 p-4 rounded-xl bg-accent-amber/10 border border-accent-amber/20">
                <AlertTriangle className="w-5 h-5 text-accent-amber shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-accent-amber mb-1">
                    部分数据源不可用 · Some data sources unavailable
                  </p>
                  <ul className="text-xs text-ash-400 space-y-0.5">
                    {partialWarnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Top row: Score ring + IP Overview */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Score ring card */}
              <div className="glass-card p-6 sm:p-8 flex flex-col items-center justify-center">
                <ScoreRing
                  score={data.score.totalScore}
                  riskLevel={data.score.riskLevel}
                />
                <div className="mt-4">
                  <RiskBadge riskLevel={data.score.riskLevel} />
                </div>
                {data.score.isUncertain && data.score.uncertaintyReason && (
                  <p className="text-xs text-ash-400 mt-3 text-center max-w-xs">
                    {data.score.uncertaintyReason}
                  </p>
                )}
              </div>

              {/* IP Overview */}
              <div className="glass-card p-6">
                <h3 className="text-sm font-semibold text-ash-300 mb-4 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-accent-teal" />
                  IP 概览 · Overview
                </h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-ash-400">IP Address</span>
                    <span className="font-mono text-sm text-ash-100 font-medium">
                      {data.ip}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-ash-400">位置 · Location</span>
                    <span className="text-sm text-ash-200">
                      {[data.geo.city, data.geo.country].filter(Boolean).join(', ') || '--'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-ash-400">ASN</span>
                    <span className="font-mono text-sm text-ash-200">
                      {data.asn.asn || '--'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-ash-400">ISP</span>
                    <span className="text-sm text-ash-200">
                      {data.asn.isp || data.asn.asnOrg || '--'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-ash-400">网络类型 · Network</span>
                    <NetworkTypeBadge type={data.networkType.type} />
                  </div>
                  <div className="flex items-center justify-between pt-1 border-t border-ash-800/40">
                    <span className="text-xs text-ash-400">IPv4 / IPv6</span>
                    <span className="flex items-center gap-3">
                      <span className="flex items-center gap-1.5 text-xs">
                        <BoolIndicator ok={data.networkQuality.ipv4Supported} />
                        <span className="text-ash-500">IPv4</span>
                      </span>
                      <span className="flex items-center gap-1.5 text-xs">
                        <BoolIndicator ok={data.networkQuality.ipv6Supported} />
                        <span className="text-ash-500">IPv6</span>
                      </span>
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Score Dimensions */}
            <div className="glass-card p-5 sm:p-6">
              <h3 className="text-sm font-semibold text-ash-300 mb-5 flex items-center gap-2">
                <Activity className="w-4 h-4 text-accent-teal" />
                评分维度 · Score Dimensions
              </h3>
              <div className="space-y-4">
                {data.score.breakdown.map((b, i) => (
                  <ScoreBar
                    key={i}
                    label={b.category}
                    labelZh={b.categoryZh}
                    score={b.score}
                    maxScore={b.maxScore}
                    riskLevel={getScoreRiskLevel(
                      b.maxScore > 0 ? (b.score / b.maxScore) * 100 : 0,
                    )}
                  />
                ))}
              </div>

              {/* Deductions list */}
              {data.score.breakdown.some((b) => b.deductions.length > 0) && (
                <div className="mt-5 pt-4 border-t border-ash-800/40">
                  <h4 className="text-xs font-semibold text-ash-400 uppercase tracking-wider mb-3">
                    扣分项 · Deductions
                  </h4>
                  <div className="space-y-2">
                    {data.score.breakdown.map(
                      (b) =>
                        b.deductions.length > 0 && (
                          <div key={b.category}>
                            <p className="text-xs text-ash-500 mb-1.5">
                              {b.categoryZh} · {b.category}
                            </p>
                            <div className="space-y-1 ml-2">
                              {b.deductions.map((d, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-start gap-2 text-xs"
                                >
                                  <span className="text-accent-rose shrink-0 mt-0.5">-{d.amount}</span>
                                  <span className="text-ash-400">
                                    {d.reasonZh}
                                    <span className="text-ash-500 hidden sm:inline">
                                      {' · '}
                                      {d.reason}
                                    </span>
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        ),
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Expandable detail sections */}
            <div className="space-y-3">
              <ExpandableSection
                icon={<MapPin className="w-4 h-4" />}
                title="Geolocation"
                titleZh="地理位置"
              >
                <GeoSection geo={data.geo} />
              </ExpandableSection>

              <ExpandableSection
                icon={<Building2 className="w-4 h-4" />}
                title="ASN / ISP"
                titleZh="ASN / ISP 信息"
              >
                <AsnSection asn={data.asn} />
              </ExpandableSection>

              <ExpandableSection
                icon={<Ban className="w-4 h-4" />}
                title="VPN / Proxy / Tor Detection"
                titleZh="VPN / 代理 / Tor 检测"
                badge={
                  <span className="text-xs text-ash-500">
                    {data.proxyDetection.isVpn ||
                    data.proxyDetection.isProxy ||
                    data.proxyDetection.isTor
                      ? 'Flagged'
                      : 'Clear'}
                  </span>
                }
              >
                <ProxySection proxy={data.proxyDetection} />
              </ExpandableSection>

              <ExpandableSection
                icon={<ListChecks className="w-4 h-4" />}
                title="Abuse & Blacklist Records"
                titleZh="滥用记录"
                badge={
                  data.abuseRecord || data.blacklistRecords.length > 0 ? (
                    <span className="text-xs text-ash-500">
                      {data.blacklistRecords.filter((r) => r.listed).length > 0
                        ? 'Listed'
                        : 'Clear'}
                    </span>
                  ) : undefined
                }
              >
                <AbuseSection
                  abuse={data.abuseRecord}
                  blacklistRecords={data.blacklistRecords}
                />
              </ExpandableSection>

              <ExpandableSection
                icon={<Monitor className="w-4 h-4" />}
                title="Environment Consistency"
                titleZh="环境一致性"
                badge={
                  data.consistency ? (
                    <span className="text-xs">
                      {data.consistency.timezoneMatch ? '一致' : '不一致'}
                    </span>
                  ) : undefined
                }
              >
                <ConsistencySection consistency={data.consistency} />
              </ExpandableSection>

              <ExpandableSection
                icon={<Network className="w-4 h-4" />}
                title="Network Quality"
                titleZh="网络质量"
              >
                <NetworkQualitySection quality={data.networkQuality} />
              </ExpandableSection>
            </div>

            {/* Key Findings */}
            <div className="glass-card p-5 sm:p-6">
              <h3 className="text-sm font-semibold text-ash-300 mb-4 flex items-center gap-2">
                <Lightbulb className="w-4 h-4 text-accent-amber" />
                关键发现 · Key Findings
              </h3>
              <ul className="space-y-2">
                {data.score.keyFindings.map((finding, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2 text-sm text-ash-400"
                  >
                    <ChevronRight className="w-3.5 h-3.5 text-ash-600 shrink-0 mt-0.5" />
                    <span>
                      {data.score.keyFindingsZh[i] ?? finding}
                      <span className="text-ash-500 hidden sm:inline">
                        {' · '}
                        {finding}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Recommendations */}
            <div className="glass-card p-5 sm:p-6 border-l-4"
              style={{
                borderLeftColor: scoreConfig?.ringColor ?? '#7d7d8f',
              }}
            >
              <h3 className="text-sm font-semibold text-ash-300 mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4" style={{ color: scoreConfig?.ringColor ?? '#7d7d8f' }} />
                建议 · Recommendation
              </h3>
              <p className="text-sm text-ash-200 leading-relaxed">
                {data.score.recommendationZh}
              </p>
              <p className="text-xs text-ash-500 mt-1.5">
                {data.score.recommendation}
              </p>
            </div>

            {/* Data Sources */}
            <div className="glass-card p-5 sm:p-6">
              <h3 className="text-sm font-semibold text-ash-300 mb-4 flex items-center gap-2">
                <Server className="w-4 h-4 text-accent-blue" />
                数据源状态 · Data Sources
                <span className="text-xs font-normal text-ash-500 ml-auto">
                  {totalFailedSources > 0
                    ? `${totalFailedSources}/${totalDataSources} 失败`
                    : `${totalDataSources} 个数据源`}
                </span>
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {data.dataSources.map((ds, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between px-3 py-2.5 rounded-lg bg-ash-800/20 border border-ash-800/40"
                  >
                    <div className="flex items-center gap-2.5">
                      <StatusDot status={ds.status} />
                      <div>
                        <span className="text-xs text-ash-200">{ds.name}</span>
                        <span className="text-[10px] text-ash-500 ml-2">
                          {DS_STATUS_LABELS[ds.status].zh}
                        </span>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono text-ash-500">
                      {ds.latencyMs > 0 ? `${ds.latencyMs}ms` : '--'}
                    </span>
                  </div>
                ))}
              </div>
              <div className="mt-4 pt-3 border-t border-ash-800/30 text-xs text-ash-500">
                <span className="flex items-center gap-2">
                  <Clock className="w-3.5 h-3.5" />
                  检测时间 · Checked at: {formatDateTime(data.checkedAt)}
                </span>
              </div>
            </div>

            {/* Retry button */}
            <div className="flex justify-center pt-2">
              <button
                onClick={handleRetry}
                disabled={loading}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-ash-800/50 text-ash-300 border border-ash-700/50 text-sm hover:bg-ash-700/50 disabled:opacity-40 transition-all"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                {loading ? '检测中 · Checking...' : '重新检测 · Re-check'}
              </button>
            </div>
          </div>
        )}

        {/* ===== Loading overlay for refresh ===== */}
        {loading && data && (
          <div className="fixed inset-0 bg-surface/60 backdrop-blur-[2px] flex items-start justify-center pt-20 z-50">
            <div className="glass-card px-8 py-5 flex items-center gap-4">
              <RefreshCw className="w-6 h-6 text-accent-teal animate-spin" />
              <span className="text-sm text-ash-200">检测中 · Checking...</span>
            </div>
          </div>
        )}

        {/* ===== History ===== */}
        {history.length > 0 && (
          <section className="mt-8">
            <button
              onClick={() => setShowHistory((s) => !s)}
              className="flex items-center gap-2 text-sm text-ash-400 hover:text-ash-200 transition-colors mb-3"
              aria-expanded={showHistory}
            >
              <History className="w-4 h-4" />
              历史记录 · History ({history.length})
              {showHistory ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>

            {showHistory && (
              <div className="glass-card overflow-hidden">
                <div className="flex items-center justify-between px-5 py-3 border-b border-ash-800/40">
                  <span className="text-xs text-ash-400">
                    最近 {history.length} 条记录 · Last {history.length} checks
                  </span>
                  <button
                    onClick={handleClearHistory}
                    className="text-xs text-accent-rose/70 hover:text-accent-rose transition-colors"
                  >
                    清除 · Clear
                  </button>
                </div>
                <div className="divide-y divide-ash-800/30">
                  {history.map((entry) => {
                    const cfg = getRiskConfig(entry.riskLevel)
                    return (
                      <button
                        key={`${entry.ip}-${entry.checkedAt}`}
                        onClick={() => handleHistoryClick(entry.ip)}
                        className="w-full flex items-center justify-between px-5 py-3 text-left hover:bg-white/[0.02] transition-colors"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <span className="font-mono text-sm text-ash-200 truncate">
                            {entry.ip}
                          </span>
                          <span className="hidden sm:inline text-xs text-ash-500 truncate">
                            {entry.location || '--'}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 shrink-0">
                          <span className="font-mono text-sm font-semibold" style={{ color: cfg.ringColor }}>
                            {entry.totalScore}
                          </span>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full border ${cfg.badgeClass}`}>
                            {cfg.labelZh}
                          </span>
                          <span className="text-[10px] text-ash-500 hidden sm:inline">
                            {formatRelativeTime(entry.checkedAt)}
                          </span>
                          <ArrowRight className="w-3.5 h-3.5 text-ash-600" />
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}
          </section>
        )}

        {/* ===== Footer ===== */}
        <footer className="mt-10 text-center text-[11px] text-ash-600">
          IP 检测工具 · IP Reputation Checker
          <span className="mx-2">|</span>
          数据仅供参考 · Data for reference only
        </footer>
      </div>
    </div>
  )
}
