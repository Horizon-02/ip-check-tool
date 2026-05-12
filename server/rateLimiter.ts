interface RateLimitEntry {
  count: number
  windowStart: number
}

interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetTime: number
}

interface RateLimiter {
  check(key: string): RateLimitResult
}

/**
 * Create a simple in-memory rate limiter.
 *
 * @param maxRequests - Maximum number of requests allowed within the window
 * @param windowMs    - Length of the window in milliseconds
 */
export function createRateLimiter(maxRequests: number = 10, windowMs: number = 60_000): RateLimiter {
  const store = new Map<string, RateLimitEntry>()

  // Periodic cleanup of expired entries (every 60 seconds)
  const cleanupInterval = setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of store) {
      if (now - entry.windowStart >= windowMs) {
        store.delete(key)
      }
    }
  }, 60_000)

  // Allow the Node process to exit even if the interval is still active
  if (cleanupInterval.unref) {
    cleanupInterval.unref()
  }

  return {
    check(key: string): RateLimitResult {
      const now = Date.now()
      const entry = store.get(key)

      if (!entry || now - entry.windowStart >= windowMs) {
        // Start a new window
        store.set(key, { count: 1, windowStart: now })
        return {
          allowed: true,
          remaining: maxRequests - 1,
          resetTime: now + windowMs,
        }
      }

      entry.count += 1

      if (entry.count > maxRequests) {
        // Prevent unbounded growth under sustained attack by pruning stale entries
        if (store.size > 10_000) {
          const threshold = now - windowMs
          for (const [k, e] of store) {
            if (now - e.windowStart >= threshold) store.delete(k)
          }
        }

        return {
          allowed: false,
          remaining: 0,
          resetTime: entry.windowStart + windowMs,
        }
      }

      return {
        allowed: true,
        remaining: maxRequests - entry.count,
        resetTime: entry.windowStart + windowMs,
      }
    },
  }
}
