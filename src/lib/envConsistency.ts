import type { ConsistencyCheck } from '../types/ipCheck'

// Public STUN servers — needed for WebRTC ICE candidate gathering.
// Reference: jason5ng32/MyIP (10.3k stars) uses 4 servers; we use 2 key ones.
const STUN_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
]

// Match both IPv4 and IPv6 addresses in ICE candidates
// Reference: MyIP's CANDIDATE_IP_RE
const CANDIDATE_IP_RE = /([0-9a-f]{1,4}(:[0-9a-f]{1,4}){7}|[0-9a-f]{0,4}(:[0-9a-f]{1,4}){0,6}::[0-9a-f]{0,4}|::[0-9a-f]{1,4}(:[0-9a-f]{1,4}){0,6}|[0-9]{1,3}(\.[0-9]{1,3}){3})/i

/**
 * Detect the real public IP via WebRTC STUN.
 * Only accepts server-reflexive (srflx) candidates — these prove the STUN
 * server responded with the client's public IP. Host candidates are ignored
 * because they only show local network IPs.
 *
 * Reference: jason5ng32/MyIP checkSTUNServer() — only srflx/prflx candidates
 */
export async function detectWebRtcIp(): Promise<string | null> {
  try {
    const pc = new RTCPeerConnection({ iceServers: STUN_SERVERS })
    pc.createDataChannel('')
    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    return new Promise<string | null>((resolve) => {
      let settled = false
      const finish = (ip: string | null) => {
        if (settled) return
        settled = true
        pc.close()
        resolve(ip)
      }

      const timer = setTimeout(() => finish(null), 5000)

      pc.onicecandidate = (event) => {
        if (!event.candidate || settled) return
        const candidate = event.candidate.candidate
        // Candidate format: "candidate:... typ <type> ..."
        // Only srflx (server-reflexive) proves STUN worked.
        // prflx (peer-reflexive) can also contain the public IP.
        const parts = candidate.split(' ')
        const type = parts[7]
        if (type !== 'srflx' && type !== 'prflx') return

        const match = CANDIDATE_IP_RE.exec(candidate)
        if (match && match[0]) {
          clearTimeout(timer)
          finish(match[0])
        }
      }
    })
  } catch {
    return null
  }
}

/**
 * Check DNS consistency by comparing the IP that Cloudflare sees
 * with the reported public IP. A mismatch suggests DNS-level proxying
 * or a DNS leak.
 */
export async function detectDnsConsistency(reportedIp: string): Promise<{ match: boolean; note: string }> {
  try {
    // Cloudflare's trace endpoint returns the IP of the TCP connection
    const resp = await fetch('https://cloudflare.com/cdn-cgi/trace')
    const text = await resp.text()
    const cfIp = /ip=([^\n]+)/.exec(text)?.[1]
    if (!cfIp) {
      return { match: false, note: 'Could not detect connection IP via Cloudflare trace' }
    }
    const match = cfIp === reportedIp
    return {
      match,
      note: match
        ? `Connection IP (${cfIp}) matches reported IP`
        : `Connection IP (${cfIp}) differs from reported IP (${reportedIp}) — possible DNS/proxy manipulation`,
    }
  } catch (e) {
    return { match: false, note: `DNS consistency check failed: ${e instanceof Error ? e.message : 'network error'}` }
  }
}

/**
 * Collect browser-side signals for environment consistency checks.
 *
 * @param ipTimezone - The timezone reported by the IP geo database (optional).
 * @param ipLanguages - The expected / accept-language hint from IP data (optional).
 *
 * When `ipTimezone` or `ipLanguages` are supplied the returned object includes
 * the comparison result. Otherwise the match fields default to `false` so the
 * caller can reconcile after receiving geo data.
 */
export function collectBrowserSignals(
  ipTimezone?: string,
  ipLanguages?: string[],
): ConsistencyCheck {
  const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone
  const browserLangs: string[] =
    navigator.languages.length > 0
      ? Array.from(navigator.languages)
      : [navigator.language || 'en-US']

  return {
    timezoneMatch: ipTimezone
      ? normalizeTimezone(browserTz) === normalizeTimezone(ipTimezone)
      : true,  // Don't penalize when IP timezone data unavailable
    timezoneExpected: ipTimezone ?? browserTz,
    timezoneActual: browserTz,

    languageMatch: ipLanguages
      ? arraysEqualIgnoringCase(browserLangs, ipLanguages)
      : true,  // Don't penalize when IP language data unavailable
    languageExpected: ipLanguages ?? browserLangs,
    languageActual: browserLangs,

    dnsMatch: false,
    dnsNote: 'DNS check pending; call detectDnsConsistency()',

    webrtcMatch: false,
    webrtcNote: 'WebRTC check pending; call detectWebRtcIp()',
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Normalise timezone strings for comparison (case-insensitive, strip spaces). */
function normalizeTimezone(tz: string): string {
  return tz.replace(/[\s_]/g, '').toLowerCase()
}

/** Compare two string arrays ignoring case (used for language tags). */
function arraysEqualIgnoringCase(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  return a.every((v, i) => v.toLowerCase() === b[i].toLowerCase())
}
