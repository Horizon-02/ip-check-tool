// Load .env file before any other imports
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
try {
  const __dirname = dirname(fileURLToPath(import.meta.url))
  const envPath = resolve(__dirname, '..', '.env')
  const envContent = readFileSync(envPath, 'utf-8')
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eqIdx = trimmed.indexOf('=')
    if (eqIdx === -1) continue
    const key = trimmed.slice(0, eqIdx).trim()
    const value = trimmed.slice(eqIdx + 1).trim()
    if (!process.env[key]) process.env[key] = value
  }
} catch { /* .env file not found, skip */ }

import express from 'express'
import cors from 'cors'
import { isValidIp, isPublicIp, sanitizeIp } from './ipValidator'
import { createRateLimiter } from './rateLimiter'
import { createCache } from './cache'
import {
  fetchIpGeoData,
  fetchProxyDetection,
  fetchAbuseData,
  fetchNetworkQuality,
} from './dataSources'
import { calculateIpScore } from '../src/lib/ipScore'
import type { IpCheckResponse, ConsistencyCheck, DataSourceInfo } from '../src/types/ipCheck'

const app = express()
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3001

app.use(cors())
app.use(express.json({ limit: '16kb' }))

// Trust proxy to get real client IP
app.set('trust proxy', true)

// ---------------------------------------------------------------------------
// Rate limiters
// ---------------------------------------------------------------------------

const generalLimiter = createRateLimiter(
  parseInt(process.env.RATE_LIMIT_MAX ?? '10'),
  parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '60000'),
)

// ---------------------------------------------------------------------------
// Caches
// ---------------------------------------------------------------------------

const geoCache = createCache<any>(60_000)       // 60s TTL
const abuseCache = createCache<any>(120_000)     // 2min TTL
const scoreCache = createCache<any>(30_000)      // 30s TTL

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getClientIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string') {
    const first = forwarded.split(',')[0].trim()
    if (isValidIp(first)) return first
  }
  if (Array.isArray(forwarded) && forwarded.length > 0) {
    const first = forwarded[0].split(',')[0].trim()
    if (isValidIp(first)) return first
  }
  // Fall back to req.ip (trust proxy must be enabled)
  if (req.ip && isValidIp(req.ip)) return req.ip
  return '127.0.0.1'
}

function rateLimitMiddleware(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const clientIp = getClientIp(req)
  const result = generalLimiter.check(clientIp)

  res.setHeader('X-RateLimit-Limit', String(parseInt(process.env.RATE_LIMIT_MAX ?? '10')))
  res.setHeader('X-RateLimit-Remaining', String(result.remaining))
  res.setHeader('X-RateLimit-Reset', String(Math.ceil(result.resetTime / 1000)))

  if (!result.allowed) {
    res.status(429).json({
      error: 'Too many requests. Please try again later.',
      code: 'RATE_LIMITED',
      details: `Rate limit exceeded. Resets at ${new Date(result.resetTime).toISOString()}`,
    })
    return
  }

  next()
}

function setCacheControl(res: express.Response, maxAge: number = 60): void {
  res.setHeader('Cache-Control', `public, max-age=${maxAge}`)
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// ---------------------------------------------------------------------------
// GET /api/ip-check/current  —  quick current-IP lookup
// ---------------------------------------------------------------------------

app.get('/api/ip-check/current', rateLimitMiddleware, async (req, res) => {
  const ip = getClientIp(req)

  if (!isValidIp(ip)) {
    res.status(400).json({
      error: 'Unable to determine a valid client IP address.',
      code: 'INVALID_IP',
      details: null,
    })
    return
  }

  // Check cache
  const cacheKey = `current:${ip}`
  const cached = geoCache.get(cacheKey)
  if (cached) {
    setCacheControl(res)
    res.json(cached)
    return
  }

  const { geo, asn, networkType, status: geoStatus } = await fetchIpGeoData(ip)
  const { proxyDetection, status: proxyStatus } = await fetchProxyDetection(ip)
  const { networkQuality: _networkQuality, status: qualityStatus } = await fetchNetworkQuality(ip)

  const dataSources: DataSourceInfo[] = [geoStatus, proxyStatus, qualityStatus]

  const result = {
    ip,
    geo,
    asn,
    networkType,
    proxyDetection,
    dataSources,
    checkedAt: new Date().toISOString(),
  }

  // Only cache if geo succeeded
  if (geoStatus.status === 'success') {
    geoCache.set(cacheKey, result)
  }

  setCacheControl(res)
  res.json(result)
})

// ---------------------------------------------------------------------------
// POST /api/ip-check/score  —  full IP reputation scoring
// ---------------------------------------------------------------------------

app.post('/api/ip-check/score', rateLimitMiddleware, async (req, res) => {
  const rawIp = req.body?.ip
  const ip: string = rawIp
    ? sanitizeIp(String(rawIp))
    : getClientIp(req)

  // Validate IP
  if (!isValidIp(ip)) {
    res.status(400).json({
      error: 'Invalid IP address provided.',
      code: 'INVALID_IP',
      details: `"${rawIp ?? ''}" is not a valid IPv4 or IPv6 address.`,
    })
    return
  }

  if (!isPublicIp(ip)) {
    res.status(400).json({
      error: 'Only public IP addresses can be checked.',
      code: 'PRIVATE_IP',
      details: `"${ip}" is a private, reserved, or non-routable address.`,
    })
    return
  }

  // Check score cache
  const cacheKey = `score:${ip}`
  const cached = scoreCache.get(cacheKey)
  if (cached) {
    setCacheControl(res, 30)
    res.json(cached)
    return
  }

  // Run all data sources in parallel
  const [geoResult, proxyResult, abuseResult, qualityResult] = await Promise.all([
    fetchIpGeoData(ip),
    fetchProxyDetection(ip),
    fetchAbuseData(ip),
    fetchNetworkQuality(ip),
  ])

  const dataSources: DataSourceInfo[] = [
    geoResult.status,
    proxyResult.status,
    ...abuseResult.status,
    qualityResult.status,
  ]

  // Accept browser-side consistency data from the frontend
  const consistency: ConsistencyCheck | null = req.body?.consistency ?? null

  // Build the check result for the scoring engine
  const now = new Date().toISOString()
  const checkResult = {
    ip,
    geo: geoResult.geo,
    asn: geoResult.asn,
    networkType: geoResult.networkType,
    proxyDetection: proxyResult.proxyDetection,
    abuseRecord: abuseResult.abuseRecord,
    blacklistRecords: abuseResult.blacklistRecords,
    consistency,
    networkQuality: qualityResult.networkQuality,
    dataSources,
    checkedAt: now,
  }

  const score = calculateIpScore(checkResult)

  const response: IpCheckResponse = {
    ...checkResult,
    score,
    checkedAt: now,
  }

  // Cache the result
  scoreCache.set(cacheKey, response)

  setCacheControl(res, 30)
  res.json(response)
})

// ---------------------------------------------------------------------------
// GET /api/ip-check/reputation  —  abuse / blacklist data
// ---------------------------------------------------------------------------

app.get('/api/ip-check/reputation', rateLimitMiddleware, async (req, res) => {
  const rawIp = (req.query.ip as string) ?? ''
  const ip = sanitizeIp(rawIp)

  if (!ip) {
    res.status(400).json({
      error: 'Query parameter "ip" is required.',
      code: 'MISSING_IP',
      details: 'Usage: GET /api/ip-check/reputation?ip=8.8.8.8',
    })
    return
  }

  if (!isValidIp(ip)) {
    res.status(400).json({
      error: 'Invalid IP address provided.',
      code: 'INVALID_IP',
      details: `"${rawIp}" is not a valid IPv4 or IPv6 address.`,
    })
    return
  }

  if (!isPublicIp(ip)) {
    res.status(400).json({
      error: 'Only public IP addresses can be checked.',
      code: 'PRIVATE_IP',
      details: `"${ip}" is a private, reserved, or non-routable address.`,
    })
    return
  }

  // Check cache
  const cacheKey = `reputation:${ip}`
  const cached = abuseCache.get(cacheKey)
  if (cached) {
    setCacheControl(res)
    res.json(cached)
    return
  }

  const { abuseRecord, blacklistRecords, status } = await fetchAbuseData(ip)
  const { proxyDetection, status: proxyStatus } = await fetchProxyDetection(ip)

  const dataSources: DataSourceInfo[] = [...status, proxyStatus]

  const result = {
    ip,
    abuseRecord,
    blacklistRecords,
    proxyDetection,
    dataSources,
    checkedAt: new Date().toISOString(),
  }

  abuseCache.set(cacheKey, result)

  setCacheControl(res)
  res.json(result)
})

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`IP Check API server running on http://localhost:${PORT}`)
})

export { app }
