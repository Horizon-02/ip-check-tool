// Cloudflare Workers compatible IP validation (no node:net dependency)

/**
 * Validate whether a string is a properly formatted IPv4 or IPv6 address.
 */
export function isValidIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false
  return isValidIPv4(ip) || isValidIPv6(ip)
}

function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    const num = Number(part)
    return part === String(num) && num >= 0 && num <= 255
  })
}

function isValidIPv6(ip: string): boolean {
  // Handle IPv4-mapped IPv6
  if (ip.startsWith('::ffff:')) {
    const v4 = ip.slice(7)
    return isValidIPv4(v4)
  }
  if (ip === '::' || ip === '::0') return true
  // Count segments — compressed form has :: once or not at all
  if ((ip.match(/::/g) || []).length > 1) return false
  const parts = ip.split(':')
  if (parts.length < 2 || parts.length > 8) return false
  return parts.every((part) => {
    if (part === '') return true // :: compression
    return /^[0-9a-f]{1,4}$/i.test(part)
  })
}

/**
 * Check whether an IP address is a public (routable) address.
 */
export function isPublicIp(ip: string): boolean {
  if (!isValidIp(ip)) return false

  // Unwrap IPv4-mapped IPv6
  if (ip.startsWith('::ffff:')) {
    ip = ip.slice(7)
  }

  if (ip.includes(':')) {
    // IPv6 checks
    const lower = ip.toLowerCase()
    if (lower === '::' || lower === '::0' || lower === '0:0:0:0:0:0:0:0') return false
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return false
    if (lower.startsWith('fe80')) return false
    if (lower.startsWith('fec0')) return false
    if (lower.startsWith('fc') || lower.startsWith('fd')) return false
    if (lower.startsWith('ff')) return false
    if (lower.startsWith('2001:db8')) return false
    return true
  }

  // IPv4 checks
  const parts = ip.split('.').map(Number)
  if (parts[0] === 0) return false
  if (parts[0] === 10) return false
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false
  if (parts[0] === 127) return false
  if (parts[0] === 169 && parts[1] === 254) return false
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
  if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return false
  if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return false
  if (parts[0] === 192 && parts[1] === 88 && parts[2] === 99) return false
  if (parts[0] === 192 && parts[1] === 168) return false
  if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return false
  if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return false
  if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return false
  if (parts[0] >= 224 && parts[0] <= 239) return false
  if (parts[0] >= 240) return false
  if (parts[0] === 255 && parts[1] === 255 && parts[2] === 255 && parts[3] === 255) return false
  return true
}
