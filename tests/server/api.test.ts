import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import type { DataSourceInfo, GeoLocation, AsnInfo, NetworkTypeInfo, ProxyDetection, NetworkQuality } from '../../src/types/ipCheck'

// ---------------------------------------------------------------------------
// Mocks — hoisted before imports
// ---------------------------------------------------------------------------

// Prevent rate limiting in tests
vi.mock('../../server/rateLimiter', () => ({
  createRateLimiter: vi.fn(() => ({
    check: vi.fn(() => ({
      allowed: true,
      remaining: 99,
      resetTime: Date.now() + 60_000,
    })),
  })),
}))

// Prevent real network calls
vi.mock('../../server/dataSources', () => ({
  fetchIpGeoData: vi.fn(),
  fetchProxyDetection: vi.fn(),
  fetchAbuseData: vi.fn(),
  fetchNetworkQuality: vi.fn(),
}))

// Prevent caching so every request hits the handler
vi.mock('../../server/cache', () => ({
  createCache: vi.fn(() => ({
    get: vi.fn(() => null),
    set: vi.fn(),
    has: vi.fn(() => false),
    clear: vi.fn(),
  })),
}))

// ---------------------------------------------------------------------------
// Import app (mocked deps are in place before this runs)
// ---------------------------------------------------------------------------

import { app } from '../../server/index'
import * as dataSources from '../../server/dataSources'

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

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
  confidence: 0,
  source: 'ipapi.co',
  details: 'No security data',
}

const defaultNetworkQuality: NetworkQuality = {
  latencyMs: 50,
  packetLoss: null,
  ipv4Supported: true,
  ipv6Supported: true,
  connectivityScore: 10,
}

const defaultStatus: DataSourceInfo = {
  name: 'ipapi.co (geo)',
  status: 'success',
  latencyMs: 100,
  errorMessage: null,
}

function setupDefaultMocks(): void {
  vi.mocked(dataSources.fetchIpGeoData).mockResolvedValue({
    geo: defaultGeo,
    asn: defaultAsn,
    networkType: defaultNetworkType,
    status: { ...defaultStatus, name: 'ipapi.co (geo)' },
  })

  vi.mocked(dataSources.fetchProxyDetection).mockResolvedValue({
    proxyDetection: defaultProxyDetection,
    status: { ...defaultStatus, name: 'ipapi.co (security)' },
  })

  vi.mocked(dataSources.fetchAbuseData).mockResolvedValue({
    abuseRecord: null,
    blacklistRecords: [{ listed: false, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' }],
    status: [{ name: 'AbuseIPDB', status: 'not_configured' as const, latencyMs: 0, errorMessage: 'No API key' }],
  })

  vi.mocked(dataSources.fetchNetworkQuality).mockResolvedValue({
    networkQuality: defaultNetworkQuality,
    status: { ...defaultStatus, name: 'httpbin.org' },
  })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GET /api/health', () => {
  it('returns 200 with status ok', async () => {
    const res = await request(app).get('/api/health')
    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('status', 'ok')
    expect(res.body).toHaveProperty('timestamp')
    expect(typeof res.body.timestamp).toBe('string')
  })
})

describe('POST /api/ip-check/score', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setupDefaultMocks()
  })

  it('returns 200 with IpCheckResponse structure for valid IP', async () => {
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '8.8.8.8' })
      .expect('Content-Type', /json/)

    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('ip', '8.8.8.8')
    expect(res.body).toHaveProperty('score')
    expect(res.body).toHaveProperty('geo')
    expect(res.body).toHaveProperty('asn')
    expect(res.body).toHaveProperty('networkType')
    expect(res.body).toHaveProperty('proxyDetection')
    expect(res.body).toHaveProperty('abuseRecord')
    expect(res.body).toHaveProperty('blacklistRecords')
    expect(res.body).toHaveProperty('networkQuality')
    expect(res.body).toHaveProperty('dataSources')
    expect(res.body).toHaveProperty('checkedAt')

    // Score shape
    expect(res.body.score).toHaveProperty('totalScore')
    expect(res.body.score).toHaveProperty('riskLevel')
    expect(res.body.score).toHaveProperty('breakdown')
    expect(res.body.score).toHaveProperty('keyFindings')
    expect(res.body.score).toHaveProperty('recommendation')
    expect(res.body.score).toHaveProperty('isUncertain')
    expect(typeof res.body.score.totalScore).toBe('number')
  })

  it('returns 400 with INVALID_IP code for invalid IP', async () => {
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: 'not-an-ip' })

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'INVALID_IP')
    expect(res.body).toHaveProperty('error')
    expect(res.body).toHaveProperty('details')
    expect(res.body.details).toContain('not-an-ip')
  })

  it('falls back to client IP when request IP is empty string', async () => {
    // When body.ip is empty/falsy, the handler falls back to getClientIp(req)
    // which returns the connection IP (or 127.0.0.1). The response should
    // still succeed or return a relevant error, not crash.
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '' })

    // Should not crash; either succeeds or fails with a validation error
    expect([200, 400]).toContain(res.status)
  })

  it('returns 400 with PRIVATE_IP code for private IP (192.168.1.1)', async () => {
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '192.168.1.1' })

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'PRIVATE_IP')
    expect(res.body).toHaveProperty('error', 'Only public IP addresses can be checked.')
    expect(res.body.details).toContain('192.168.1.1')
    // Should not call data sources for private IP
    expect(dataSources.fetchIpGeoData).not.toHaveBeenCalled()
  })

  it('returns 400 with PRIVATE_IP for loopback IP', async () => {
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '127.0.0.1' })

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'PRIVATE_IP')
  })

  it('returns 400 with PRIVATE_IP for link-local IP', async () => {
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '169.254.1.1' })

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'PRIVATE_IP')
  })

  it('sanitizes IP input before validation', async () => {
    // IP with leading whitespace gets sanitized before validation
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '  192.168.1.1  ' })

    // After sanitization it should be '192.168.1.1' which is private
    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'PRIVATE_IP')
    // The sanitized form is used in the details message
    expect(res.body.details).toContain('192.168.1.1')
  })

  it('calls all data sources for a valid public IP', async () => {
    await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '1.1.1.1' })

    expect(dataSources.fetchIpGeoData).toHaveBeenCalledWith('1.1.1.1')
    expect(dataSources.fetchProxyDetection).toHaveBeenCalledWith('1.1.1.1')
    expect(dataSources.fetchAbuseData).toHaveBeenCalledWith('1.1.1.1')
    expect(dataSources.fetchNetworkQuality).toHaveBeenCalledWith('1.1.1.1')
  })
})

describe('GET /api/ip-check/reputation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setupDefaultMocks()
  })

  it('returns 400 when ip parameter is missing', async () => {
    const res = await request(app).get('/api/ip-check/reputation')

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'MISSING_IP')
    expect(res.body).toHaveProperty('error', 'Query parameter "ip" is required.')
  })

  it('returns 400 for empty ip parameter', async () => {
    const res = await request(app)
      .get('/api/ip-check/reputation')
      .query({ ip: '' })

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'MISSING_IP')
  })

  it('returns 400 with INVALID_IP for invalid IP', async () => {
    const res = await request(app)
      .get('/api/ip-check/reputation')
      .query({ ip: 'bad-input' })

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'INVALID_IP')
  })

  it('returns 400 with PRIVATE_IP for private IP', async () => {
    const res = await request(app)
      .get('/api/ip-check/reputation')
      .query({ ip: '10.0.0.1' })

    expect(res.status).toBe(400)
    expect(res.body).toHaveProperty('code', 'PRIVATE_IP')
  })

  it('returns 200 with abuse/blacklist data for valid public IP', async () => {
    // Configure mock to return abuse data
    vi.mocked(dataSources.fetchAbuseData).mockResolvedValue({
      abuseRecord: {
        confidenceScore: 25,
        totalReports: 3,
        lastReportedAt: '2024-01-01T00:00:00.000Z',
        categories: ['spam'],
        source: 'AbuseIPDB',
      },
      blacklistRecords: [
        { listed: true, listName: 'AbuseIPDB', listType: 'abuse', source: 'AbuseIPDB' },
      ],
      status: [{ name: 'AbuseIPDB', status: 'success', latencyMs: 200, errorMessage: null }],
    })

    const res = await request(app)
      .get('/api/ip-check/reputation')
      .query({ ip: '8.8.8.8' })

    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('ip', '8.8.8.8')
    expect(res.body).toHaveProperty('abuseRecord')
    expect(res.body).toHaveProperty('blacklistRecords')
    expect(res.body).toHaveProperty('proxyDetection')
    expect(res.body).toHaveProperty('dataSources')
    expect(res.body.abuseRecord.confidenceScore).toBe(25)
    expect(res.body.blacklistRecords).toHaveLength(1)
    expect(res.body.blacklistRecords[0].listed).toBe(true)
  })
})

describe('Rate limit headers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('rate limit headers are set on score endpoint response', async () => {
    setupDefaultMocks()

    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '9.9.9.9' })

    expect(res.headers['x-ratelimit-limit']).toBeDefined()
    expect(res.headers['x-ratelimit-remaining']).toBeDefined()
    expect(res.headers['x-ratelimit-reset']).toBeDefined()
    expect(res.headers['x-ratelimit-limit']).toBe('10')
    expect(res.headers['x-ratelimit-remaining']).toBe('99')
  })

  it('rate limit headers are set on reputation endpoint response', async () => {
    setupDefaultMocks()

    const res = await request(app)
      .get('/api/ip-check/reputation')
      .query({ ip: '9.9.9.9' })

    expect(res.headers['x-ratelimit-limit']).toBeDefined()
    expect(res.headers['x-ratelimit-remaining']).toBeDefined()
    expect(res.headers['x-ratelimit-limit']).toBe('10')
  })
})

describe('Cache-Control headers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setupDefaultMocks()
  })

  it('sets Cache-Control header on successful score response', async () => {
    const res = await request(app)
      .post('/api/ip-check/score')
      .send({ ip: '1.1.1.1' })

    expect(res.headers['cache-control']).toBeDefined()
    expect(res.headers['cache-control']).toContain('public')
    expect(res.headers['cache-control']).toContain('max-age=30')
  })
})
