interface CacheEntry<T> {
  value: T
  expiresAt: number
}

interface Cache<T> {
  get(key: string): T | null
  set(key: string, value: T): void
  has(key: string): boolean
  clear(): void
}

/**
 * Create a simple in-memory cache with Time-To-Live (TTL) expiration.
 *
 * @param ttlMs - Time-to-live in milliseconds (default: 60 seconds)
 */
export function createCache<T>(ttlMs: number = 60_000): Cache<T> {
  const store = new Map<string, CacheEntry<T>>()

  // Periodic cleanup of expired entries
  const cleanupInterval = setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of store) {
      if (now >= entry.expiresAt) {
        store.delete(key)
      }
    }
  }, Math.min(ttlMs, 30_000))

  if (cleanupInterval.unref) {
    cleanupInterval.unref()
  }

  return {
    get(key: string): T | null {
      const entry = store.get(key)
      if (!entry) return null
      if (Date.now() >= entry.expiresAt) {
        store.delete(key)
        return null
      }
      return entry.value
    },

    set(key: string, value: T): void {
      store.set(key, { value, expiresAt: Date.now() + ttlMs })
    },

    has(key: string): boolean {
      return this.get(key) !== null
    },

    clear(): void {
      store.clear()
    },
  }
}
