import type { ConsistencyCheck } from '../types/ipCheck'

/**
 * Attempt to detect the local IP address via WebRTC.
 * Creates a minimal RTCPeerConnection, generates an offer, and inspects
 * ICE candidates for the local IP. Never establishes a real connection.
 * Returns null on failure, timeout (3s), or if WebRTC is unavailable.
 */
export async function detectWebRtcIp(): Promise<string | null> {
  try {
    const pc = new RTCPeerConnection({ iceServers: [] })
    pc.createDataChannel('')
    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    return new Promise<string | null>((resolve) => {
      const fallbackTimer = setTimeout(() => {
        pc.close()
        resolve(null)
      }, 3000)

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          const match =
            /([0-9]{1,3}(?:\.[0-9]{1,3}){3})/.exec(event.candidate.candidate)
          if (match) {
            clearTimeout(fallbackTimer)
            pc.close()
            resolve(match[1])
          }
        }
      }

      // If no candidate fires within 2 s, give up
      setTimeout(() => {
        clearTimeout(fallbackTimer)
        pc.close()
        resolve(null)
      }, 2000)
    })
  } catch {
    return null
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
      : false,
    timezoneExpected: ipTimezone ?? browserTz,
    timezoneActual: browserTz,

    languageMatch: ipLanguages
      ? arraysEqualIgnoringCase(browserLangs, ipLanguages)
      : false,
    languageExpected: ipLanguages ?? browserLangs,
    languageActual: browserLangs,

    dnsMatch: false,
    dnsNote: 'DNS comparison requires server-side resolver data',

    webrtcMatch: false,
    webrtcNote: 'WebRTC check pending; call detectWebRtcIp() and compare with IP address',
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
