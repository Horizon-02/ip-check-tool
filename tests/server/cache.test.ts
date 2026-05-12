import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createCache } from '../../server/cache'

describe('createCache', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('set stores a value and get retrieves it', () => {
    const cache = createCache<string>(60_000)
    cache.set('key1', 'value1')
    expect(cache.get('key1')).toBe('value1')
  })

  it('get returns null for a missing key', () => {
    const cache = createCache<string>(60_000)
    expect(cache.get('nonexistent')).toBeNull()
  })

  it('has returns true for existing keys', () => {
    const cache = createCache<string>(60_000)
    cache.set('key', 'value')
    expect(cache.has('key')).toBe(true)
  })

  it('has returns false for missing keys', () => {
    const cache = createCache<string>(60_000)
    expect(cache.has('nonexistent')).toBe(false)
  })

  it('has returns false for expired keys', () => {
    const cache = createCache<string>(1000) // 1s TTL
    cache.set('key', 'value')
    expect(cache.has('key')).toBe(true)

    vi.advanceTimersByTime(1001)
    expect(cache.has('key')).toBe(false)
  })

  it('returns null for expired entries', () => {
    const cache = createCache<string>(1000) // 1s TTL
    cache.set('key', 'value')

    vi.advanceTimersByTime(999)
    expect(cache.get('key')).toBe('value')

    vi.advanceTimersByTime(2) // Past TTL
    expect(cache.get('key')).toBeNull()
  })

  it('returns null for expired entries exactly at TTL boundary', () => {
    const cache = createCache<string>(1000)
    cache.set('key', 'value')

    // At exactly TTL, value should still be accessible (expiresAt === now is expired)
    vi.advanceTimersByTime(1000)
    // expiresAt check uses `>=`, so at exactly TTL it is expired
    expect(cache.get('key')).toBeNull()
  })

  it('clear removes all entries', () => {
    const cache = createCache<string>(60_000)
    cache.set('a', '1')
    cache.set('b', '2')
    cache.set('c', '3')

    expect(cache.has('a')).toBe(true)
    expect(cache.has('b')).toBe(true)
    expect(cache.has('c')).toBe(true)

    cache.clear()

    expect(cache.has('a')).toBe(false)
    expect(cache.has('b')).toBe(false)
    expect(cache.has('c')).toBe(false)
    expect(cache.get('a')).toBeNull()
  })

  it('works with complex object types', () => {
    interface User {
      id: number
      name: string
      roles: string[]
      metadata: Record<string, unknown>
    }

    const cache = createCache<User>(60_000)
    const user: User = {
      id: 42,
      name: 'Alice',
      roles: ['admin', 'user'],
      metadata: { department: 'engineering', active: true },
    }

    cache.set('user:42', user)

    const retrieved = cache.get('user:42')
    expect(retrieved).toEqual(user)
    expect(retrieved?.id).toBe(42)
    expect(retrieved?.name).toBe('Alice')
    expect(retrieved?.roles).toContain('admin')
    expect(retrieved?.metadata.department).toBe('engineering')
  })

  it('works with number values', () => {
    const cache = createCache<number>(60_000)
    cache.set('count', 100)
    expect(cache.get('count')).toBe(100)
  })

  it('works with boolean values', () => {
    const cache = createCache<boolean>(60_000)
    cache.set('flag', true)
    expect(cache.get('flag')).toBe(true)
  })

  it('works with null as a stored value', () => {
    const cache = createCache<null>(60_000)
    cache.set('null-key', null)
    // get returns null for both missing and null-stored values
    // This is a limitation of the interface (T | null return type)
    expect(cache.get('null-key')).toBeNull()
  })

  it('handles multiple keys independently', () => {
    const cache = createCache<string>(60_000)
    cache.set('k1', 'v1')
    cache.set('k2', 'v2')

    expect(cache.get('k1')).toBe('v1')
    expect(cache.get('k2')).toBe('v2')

    cache.clear()
    expect(cache.get('k1')).toBeNull()
    expect(cache.get('k2')).toBeNull()
  })

  it('respects custom TTL per cache instance', () => {
    const shortCache = createCache<string>(100)   // 100ms TTL
    const longCache = createCache<string>(10_000) // 10s TTL

    shortCache.set('s', 'short')
    longCache.set('l', 'long')

    vi.advanceTimersByTime(200)
    expect(shortCache.get('s')).toBeNull()
    expect(longCache.get('l')).toBe('long')
  })

  it('overwrites existing keys', () => {
    const cache = createCache<string>(60_000)
    cache.set('key', 'old')
    expect(cache.get('key')).toBe('old')

    cache.set('key', 'new')
    expect(cache.get('key')).toBe('new')
  })
})
