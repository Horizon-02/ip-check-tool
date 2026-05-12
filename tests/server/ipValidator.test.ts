import { describe, it, expect } from 'vitest'
import { isValidIp, isPublicIp, sanitizeIp } from '../../server/ipValidator'

describe('isValidIp', () => {
  // Valid IPv4 addresses
  it('returns true for valid IPv4 addresses', () => {
    expect(isValidIp('8.8.8.8')).toBe(true)
    expect(isValidIp('1.1.1.1')).toBe(true)
    expect(isValidIp('192.168.1.1')).toBe(true)
    expect(isValidIp('10.0.0.1')).toBe(true)
    expect(isValidIp('172.16.0.1')).toBe(true)
    expect(isValidIp('0.0.0.0')).toBe(true)
    expect(isValidIp('255.255.255.255')).toBe(true)
    expect(isValidIp('127.0.0.1')).toBe(true)
    expect(isValidIp('224.0.0.1')).toBe(true)
    expect(isValidIp('240.0.0.1')).toBe(true)
  })

  // Valid IPv6 addresses
  it('returns true for valid IPv6 addresses (compressed)', () => {
    expect(isValidIp('::1')).toBe(true)
    expect(isValidIp('::')).toBe(true)
    expect(isValidIp('2001:db8::1')).toBe(true)
    expect(isValidIp('fe80::1')).toBe(true)
    expect(isValidIp('2001:4860:4860::8888')).toBe(true)
  })

  it('returns true for valid IPv6 addresses (full)', () => {
    expect(isValidIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(true)
    expect(isValidIp('0000:0000:0000:0000:0000:0000:0000:0001')).toBe(true)
    expect(isValidIp('fe80:0000:0000:0000:0000:0000:0000:0001')).toBe(true)
  })

  it('returns true for IPv6 loopback', () => {
    expect(isValidIp('::1')).toBe(true)
    expect(isValidIp('0:0:0:0:0:0:0:1')).toBe(true)
  })

  // Invalid inputs
  it('returns false for empty string', () => {
    expect(isValidIp('')).toBe(false)
  })

  it('returns false for nonsense strings', () => {
    expect(isValidIp('not-an-ip')).toBe(false)
    expect(isValidIp('abc.def.ghi.ijk')).toBe(false)
    expect(isValidIp('hello world')).toBe(false)
    expect(isValidIp('12345')).toBe(false)
  })

  it('returns false for partial/incomplete IPs', () => {
    expect(isValidIp('192.168.1')).toBe(false)
    expect(isValidIp('192.168.1.1.1')).toBe(false)
    expect(isValidIp('192.168.1.1.')).toBe(false)
    expect(isValidIp('.192.168.1.1')).toBe(false)
    expect(isValidIp('192.168.1.300')).toBe(false)
    expect(isValidIp('256.256.256.256')).toBe(false)
  })

  it('returns false for IPs with leading/trailing whitespace', () => {
    expect(isValidIp(' 8.8.8.8')).toBe(false)
    expect(isValidIp('8.8.8.8 ')).toBe(false)
    expect(isValidIp(' 8.8.8.8 ')).toBe(false)
    expect(isValidIp('  ::1')).toBe(false)
  })

  it('returns false for null, undefined, or non-string types', () => {
    expect(isValidIp(null as unknown as string)).toBe(false)
    expect(isValidIp(undefined as unknown as string)).toBe(false)
    expect(isValidIp(123 as unknown as string)).toBe(false)
    expect(isValidIp({} as unknown as string)).toBe(false)
    expect(isValidIp([] as unknown as string)).toBe(false)
  })
})

describe('sanitizeIp', () => {
  it('trims whitespace from input', () => {
    expect(sanitizeIp('  8.8.8.8  ')).toBe('8.8.8.8')
    expect(sanitizeIp('  ::1  ')).toBe('::1')
    expect(sanitizeIp('\t192.168.1.1\n')).toBe('192.168.1.1')
  })

  it('lowercases IPv6 addresses', () => {
    expect(sanitizeIp('2001:DB8::1')).toBe('2001:db8::1')
    expect(sanitizeIp('FE80::1')).toBe('fe80::1')
    expect(sanitizeIp('::FFFF:192.168.1.1')).toBe('::ffff:192.168.1.1')
  })

  it('strips invalid characters', () => {
    // Hex chars (a-f) are valid in IPv6 so they are kept
    expect(sanitizeIp('8.8.8.8<script>')).toBe('8.8.8.8c')
    expect(sanitizeIp('<script>alert(1)</script>')).toBe('cae1c')
    expect(sanitizeIp('1.1.1.1|; rm -rf /')).toBe('1.1.1.1f')
  })

  it('preserves valid IP characters only (hex digits, dots, colons)', () => {
    expect(sanitizeIp('2001:db8::1')).toBe('2001:db8::1')
    expect(sanitizeIp('1.2.3.4')).toBe('1.2.3.4')
    // Dots are valid IP characters, so they are preserved
    expect(sanitizeIp('a.b.c.d')).toBe('a.b.c.d')
  })

  it('returns empty string for null, undefined, or number', () => {
    expect(sanitizeIp(null as unknown as string)).toBe('')
    expect(sanitizeIp(undefined as unknown as string)).toBe('')
    expect(sanitizeIp(123 as unknown as string)).toBe('')
  })

  it('handles empty string gracefully', () => {
    expect(sanitizeIp('')).toBe('')
  })
})

describe('isPublicIp', () => {
  // Private / reserved IPv4 ranges
  it('rejects 10.x.x.x (private class A)', () => {
    expect(isPublicIp('10.0.0.1')).toBe(false)
    expect(isPublicIp('10.255.255.255')).toBe(false)
    expect(isPublicIp('10.1.2.3')).toBe(false)
  })

  it('rejects 172.16.x.x - 172.31.x.x (private class B)', () => {
    expect(isPublicIp('172.16.0.1')).toBe(false)
    expect(isPublicIp('172.31.255.255')).toBe(false)
    expect(isPublicIp('172.20.0.1')).toBe(false)
    // Just outside the range — should be public
    expect(isPublicIp('172.15.255.255')).toBe(true)
    expect(isPublicIp('172.32.0.1')).toBe(true)
  })

  it('rejects 192.168.x.x (private class C)', () => {
    expect(isPublicIp('192.168.0.1')).toBe(false)
    expect(isPublicIp('192.168.255.255')).toBe(false)
    expect(isPublicIp('192.168.1.1')).toBe(false)
  })

  it('rejects 127.x.x.x (loopback)', () => {
    expect(isPublicIp('127.0.0.1')).toBe(false)
    expect(isPublicIp('127.0.0.0')).toBe(false)
    expect(isPublicIp('127.255.255.255')).toBe(false)
  })

  it('rejects 169.254.x.x (link-local)', () => {
    expect(isPublicIp('169.254.0.1')).toBe(false)
    expect(isPublicIp('169.254.255.255')).toBe(false)
    expect(isPublicIp('169.254.1.1')).toBe(false)
  })

  it('rejects 0.0.0.0', () => {
    expect(isPublicIp('0.0.0.0')).toBe(false)
    expect(isPublicIp('0.1.2.3')).toBe(false)
  })

  it('rejects 224.x.x.x - 239.x.x.x (multicast)', () => {
    expect(isPublicIp('224.0.0.1')).toBe(false)
    expect(isPublicIp('239.255.255.255')).toBe(false)
    expect(isPublicIp('225.1.2.3')).toBe(false)
  })

  it('rejects 240.x.x.x+ (reserved)', () => {
    expect(isPublicIp('240.0.0.1')).toBe(false)
    expect(isPublicIp('255.255.255.255')).toBe(false)
    expect(isPublicIp('250.1.2.3')).toBe(false)
  })

  it('rejects 100.64.x.x - 100.127.x.x (carrier-grade NAT)', () => {
    expect(isPublicIp('100.64.0.1')).toBe(false)
    expect(isPublicIp('100.127.255.255')).toBe(false)
    expect(isPublicIp('100.100.0.1')).toBe(false)
    // Outside the CGNAT range
    expect(isPublicIp('100.63.255.255')).toBe(true)
    expect(isPublicIp('100.128.0.1')).toBe(true)
  })

  it('rejects 192.0.0.x (IETF protocol assignments)', () => {
    expect(isPublicIp('192.0.0.1')).toBe(false)
    expect(isPublicIp('192.0.0.255')).toBe(false)
  })

  it('rejects documentation ranges for IPv4', () => {
    expect(isPublicIp('192.0.2.1')).toBe(false)   // TEST-NET-1
    expect(isPublicIp('198.51.100.1')).toBe(false) // TEST-NET-2
    expect(isPublicIp('203.0.113.1')).toBe(false)  // TEST-NET-3
  })

  it('rejects 192.88.99.x (6to4 anycast)', () => {
    expect(isPublicIp('192.88.99.1')).toBe(false)
    expect(isPublicIp('192.88.99.255')).toBe(false)
  })

  it('rejects 198.18.x.x - 198.19.x.x (benchmark testing)', () => {
    expect(isPublicIp('198.18.0.1')).toBe(false)
    expect(isPublicIp('198.19.255.255')).toBe(false)
  })

  // IPv6 private / reserved ranges
  it('rejects ::1 (IPv6 loopback)', () => {
    expect(isPublicIp('::1')).toBe(false)
    expect(isPublicIp('0:0:0:0:0:0:0:1')).toBe(false)
  })

  it('rejects :: (IPv6 unspecified)', () => {
    expect(isPublicIp('::')).toBe(false)
    expect(isPublicIp('::0')).toBe(false)
    expect(isPublicIp('0:0:0:0:0:0:0:0')).toBe(false)
  })

  it('rejects fe80:: (IPv6 link-local)', () => {
    expect(isPublicIp('fe80::1')).toBe(false)
    expect(isPublicIp('fe80::')).toBe(false)
    expect(isPublicIp('fe80:0000:0000:0000:0000:0000:0000:0001')).toBe(false)
  })

  it('rejects fc00:: (IPv6 unique local)', () => {
    expect(isPublicIp('fc00::1')).toBe(false)
    expect(isPublicIp('fd00::1')).toBe(false)
    expect(isPublicIp('fcff::1')).toBe(false)
  })

  it('rejects fec0:: (IPv6 site-local, deprecated)', () => {
    expect(isPublicIp('fec0::1')).toBe(false)
    expect(isPublicIp('fec0::')).toBe(false)
  })

  it('rejects ff00:: (IPv6 multicast)', () => {
    expect(isPublicIp('ff00::1')).toBe(false)
    expect(isPublicIp('ff02::1')).toBe(false)     // all-nodes link-local multicast
    expect(isPublicIp('ff02::2')).toBe(false)     // all-routers link-local multicast
  })

  it('rejects 2001:db8:: (IPv6 documentation)', () => {
    expect(isPublicIp('2001:db8::1')).toBe(false)
    expect(isPublicIp('2001:db8::')).toBe(false)
    expect(isPublicIp('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(false)
  })

  // Public IPs that should be accepted
  it('accepts valid public IPv4 addresses', () => {
    expect(isPublicIp('8.8.8.8')).toBe(true)
    expect(isPublicIp('1.1.1.1')).toBe(true)
    expect(isPublicIp('9.9.9.9')).toBe(true)
    expect(isPublicIp('208.67.222.222')).toBe(true)
    expect(isPublicIp('185.199.108.153')).toBe(true)
  })

  it('accepts valid public IPv6 addresses', () => {
    expect(isPublicIp('2001:4860:4860::8888')).toBe(true)  // Google DNS
    expect(isPublicIp('2001:4860:4860::8844')).toBe(true)
    expect(isPublicIp('2606:4700:4700::1111')).toBe(true)  // Cloudflare DNS
    expect(isPublicIp('2620:fe::fe')).toBe(true)            // Quad9
  })

  it('returns false for invalid IP format', () => {
    expect(isPublicIp('not-an-ip')).toBe(false)
    expect(isPublicIp('')).toBe(false)
    expect(isPublicIp('256.1.2.3')).toBe(false)
  })

  it('is case-insensitive for IPv6 checks', () => {
    expect(isPublicIp('FE80::1')).toBe(false)
    expect(isPublicIp('fe80::1')).toBe(false)
    expect(isPublicIp('2001:DB8::1')).toBe(false)
    expect(isPublicIp('2001:db8::1')).toBe(false)
    expect(isPublicIp('FF02::1')).toBe(false)
    expect(isPublicIp('2001:4860:4860::8888')).toBe(true)
  })
})
