import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createRateLimiter } from '../../server/rateLimiter'

describe('createRateLimiter', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('allows requests under the limit', () => {
    const limiter = createRateLimiter(5, 60_000)

    for (let i = 0; i < 5; i++) {
      const result = limiter.check('test-key')
      expect(result.allowed).toBe(true)
    }
  })

  it('blocks requests over the limit', () => {
    const limiter = createRateLimiter(3, 60_000)

    // First 3 are allowed
    expect(limiter.check('test-key').allowed).toBe(true)
    expect(limiter.check('test-key').allowed).toBe(true)
    expect(limiter.check('test-key').allowed).toBe(true)

    // 4th is blocked
    const result = limiter.check('test-key')
    expect(result.allowed).toBe(false)
    expect(result.remaining).toBe(0)
  })

  it('returns correct remaining count', () => {
    const limiter = createRateLimiter(5, 60_000)

    // After 1 request: max - 1 = 4 remaining
    expect(limiter.check('key').remaining).toBe(4)
    // After 2 requests: max - 2 = 3 remaining
    expect(limiter.check('key').remaining).toBe(3)
    // After 3 requests: max - 3 = 2 remaining
    expect(limiter.check('key').remaining).toBe(2)
    // After 4 requests: max - 4 = 1 remaining
    expect(limiter.check('key').remaining).toBe(1)
    // After 5 requests: max - 5 = 0 remaining
    expect(limiter.check('key').remaining).toBe(0)
    // 6th: blocked
    expect(limiter.check('key').remaining).toBe(0)
  })

  it('returns resetTime in the future', () => {
    const limiter = createRateLimiter(3, 60_000)
    const now = Date.now()

    const result = limiter.check('key')
    expect(result.resetTime).toBeGreaterThan(now)
    // resetTime should be exactly now + windowMs
    expect(result.resetTime).toBe(now + 60_000)
  })

  it('tracks different keys independently', () => {
    const limiter = createRateLimiter(3, 60_000)

    // Exhaust key-a
    expect(limiter.check('key-a').allowed).toBe(true)
    expect(limiter.check('key-a').allowed).toBe(true)
    expect(limiter.check('key-a').allowed).toBe(true)
    expect(limiter.check('key-a').allowed).toBe(false)

    // key-b should still be fully available (save result to avoid double-call)
    const result = limiter.check('key-b')
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(2)
  })

  it('resets window after time passes', () => {
    const limiter = createRateLimiter(3, 60_000)

    // Exhaust key
    expect(limiter.check('key').allowed).toBe(true)
    expect(limiter.check('key').allowed).toBe(true)
    expect(limiter.check('key').allowed).toBe(true)
    expect(limiter.check('key').allowed).toBe(false)

    // Advance time past the window
    vi.advanceTimersByTime(60_001)

    // Should be allowed again (new window started)
    const result = limiter.check('key')
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(2)
  })

  it('window resets exactly at window boundary', () => {
    const limiter = createRateLimiter(2, 10_000)

    expect(limiter.check('key').allowed).toBe(true)
    expect(limiter.check('key').allowed).toBe(true)
    expect(limiter.check('key').allowed).toBe(false)

    // Advance 1ms short of window
    vi.advanceTimersByTime(9_999)
    expect(limiter.check('key').allowed).toBe(false)

    // Advance past window
    vi.advanceTimersByTime(2)
    expect(limiter.check('key').allowed).toBe(true)
  })

  it('handles burst traffic gracefully without crashing', () => {
    const limiter = createRateLimiter(100, 60_000)

    // Make many requests rapidly
    for (let i = 0; i < 200; i++) {
      limiter.check('burst-key')
    }

    // Allowed should be false (exceeded by 100)
    expect(limiter.check('burst-key').allowed).toBe(false)
    expect(limiter.check('burst-key').remaining).toBe(0)
  })

  it('nth request (matching maxRequests) is allowed with remaining=0', () => {
    const limiter = createRateLimiter(5, 60_000)

    // Make maxRequests-1 calls, then the nth call is the one we assert on
    for (let i = 0; i < 4; i++) {
      limiter.check('key')
    }

    // The 5th request hits the limit exactly: count becomes 5, 5 > 5 is false
    const result = limiter.check('key')
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(0)
  })
})
