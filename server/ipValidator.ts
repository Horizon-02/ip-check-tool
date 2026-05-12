import { isIPv4, isIPv6 } from 'node:net'

/**
 * Validate whether a string is a properly formatted IPv4 or IPv6 address.
 */
export function isValidIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false
  return isIPv4(ip) || isIPv6(ip)
}

/**
 * Check whether an IP address is a public (routable) address.
 * Returns false for private, loopback, link-local, multicast, reserved,
 * and documentation ranges.
 */
export function isPublicIp(ip: string): boolean {
  if (!isValidIp(ip)) return false

  // --- IPv4 range checks ---
  if (isIPv4(ip)) {
    const parts = ip.split('.').map(Number)

    // 0.x.x.x - "This network" (reserved)
    if (parts[0] === 0) return false
    // 10.x.x.x - Private class A
    if (parts[0] === 10) return false
    // 100.64.x.x - 100.127.x.x - Carrier-grade NAT (RFC 6598)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false
    // 127.x.x.x - Loopback
    if (parts[0] === 127) return false
    // 169.254.x.x - Link-local
    if (parts[0] === 169 && parts[1] === 254) return false
    // 172.16.x.x - 172.31.x.x - Private class B
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
    // 192.0.0.x - IETF protocol assignments
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return false
    // 192.0.2.x - Documentation (TEST-NET-1)
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return false
    // 192.88.99.x - 6to4 anycast relay (deprecated)
    if (parts[0] === 192 && parts[1] === 88 && parts[2] === 99) return false
    // 192.168.x.x - Private class C
    if (parts[0] === 192 && parts[1] === 168) return false
    // 198.18.x.x - 198.19.x.x - Benchmark testing
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return false
    // 198.51.100.x - Documentation (TEST-NET-2)
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return false
    // 203.0.113.x - Documentation (TEST-NET-3)
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return false
    // 224.x.x.x - 239.x.x.x - Multicast
    if (parts[0] >= 224 && parts[0] <= 239) return false
    // 240.x.x.x+ - Reserved / future use
    if (parts[0] >= 240) return false
    // 255.255.255.255 - Limited broadcast
    if (parts[0] === 255 && parts[1] === 255 && parts[2] === 255 && parts[3] === 255) return false

    return true
  }

  // --- IPv6 range checks ---
  if (isIPv6(ip)) {
    const lowerIp = ip.toLowerCase()
    // ::/128 - Unspecified
    if (lowerIp === '::' || lowerIp === '::0' || lowerIp === '0:0:0:0:0:0:0:0') return false
    // ::1/128 - Loopback
    if (lowerIp === '::1' || lowerIp === '0:0:0:0:0:0:0:1') return false
    // fe80::/10 - Link-local unicast
    if (lowerIp.startsWith('fe80')) return false
    // fec0::/10 - Site-local unicast (deprecated)
    if (lowerIp.startsWith('fec0')) return false
    // fc00::/7 - Unique local address (ULA)
    if (lowerIp.startsWith('fc') || lowerIp.startsWith('fd')) return false
    // ff00::/8 - Multicast
    if (lowerIp.startsWith('ff')) return false
    // 2001:db8::/32 - Documentation
    if (lowerIp.startsWith('2001:db8')) return false
    // 2002:e0::/20 - 6to4 relay anycast (deprecated) - not needed for basic check
    // 64:ff9b::/96 - IPv4-IPv6 translation

    return true
  }

  return false
}

/**
 * Sanitize an IP input string: trim whitespace, lowercase, strip dangerous chars.
 */
export function sanitizeIp(input: string): string {
  if (!input || typeof input !== 'string') return ''
  // Trim whitespace
  let sanitized = input.trim()
  // Lowercase (IPv6 is case-insensitive)
  sanitized = sanitized.toLowerCase()
  // Strip any character that is not valid in an IP address
  sanitized = sanitized.replace(/[^a-fa-f0-9.:]/g, '')
  return sanitized
}
