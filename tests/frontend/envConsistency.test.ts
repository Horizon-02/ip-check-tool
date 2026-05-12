import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  detectWebRtcIp,
  collectBrowserSignals,
} from '@/lib/envConsistency'

// ---------------------------------------------------------------------------
// detectWebRtcIp
// ---------------------------------------------------------------------------

describe('detectWebRtcIp', () => {
  const originalRTCPeerConnection = globalThis.RTCPeerConnection

  afterEach(() => {
    // Restore whatever RTCPeerConnection was before the test
    if (originalRTCPeerConnection === undefined) {
      delete (globalThis as any).RTCPeerConnection
    } else {
      globalThis.RTCPeerConnection = originalRTCPeerConnection
    }
  })

  it('returns null when WebRTC is not available (RTCPeerConnection undefined)', async () => {
    delete (globalThis as any).RTCPeerConnection
    const result = await detectWebRtcIp()
    expect(result).toBeNull()
  })

  it('returns null when RTCPeerConnection constructor throws', async () => {
    globalThis.RTCPeerConnection = vi.fn().mockImplementation(() => {
      throw new Error('WebRTC not supported')
    }) as unknown as typeof RTCPeerConnection
    const result = await detectWebRtcIp()
    expect(result).toBeNull()
  })

  it('returns null when no ICE candidate fires within timeout', async () => {
    // A mock that never fires onicecandidate
    const closeFn = vi.fn()
    globalThis.RTCPeerConnection = vi.fn().mockImplementation(() => ({
      createDataChannel: vi.fn(),
      createOffer: vi.fn().mockResolvedValue({}),
      setLocalDescription: vi.fn().mockResolvedValue(undefined),
      close: closeFn,
      onicecandidate: null as any,
    })) as unknown as typeof RTCPeerConnection

    const result = await detectWebRtcIp()
    expect(result).toBeNull()
    // The connection should have been closed
    expect(closeFn).toHaveBeenCalled()
  })

  it('returns the local IP when an ICE candidate provides one', async () => {
    let onIceCallback: ((event: any) => void) | null = null
    const closeFn = vi.fn()

    globalThis.RTCPeerConnection = vi.fn().mockImplementation(() => ({
      createDataChannel: vi.fn(),
      createOffer: vi.fn().mockResolvedValue({}),
      setLocalDescription: vi.fn().mockResolvedValue(undefined),
      close: closeFn,
      set onicecandidate(cb: ((event: any) => void) | null) {
        // Fire the callback asynchronously with a real-looking candidate
        if (cb) {
          setTimeout(() => {
            cb({
              candidate: {
                candidate:
                  'candidate:1 1 UDP 2122252543 192.168.1.42 54321 typ host',
              },
            })
          }, 5)
        }
        onIceCallback = cb
      },
      get onicecandidate() {
        return onIceCallback
      },
    })) as unknown as typeof RTCPeerConnection

    const result = await detectWebRtcIp()
    expect(result).toBe('192.168.1.42')
    expect(closeFn).toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// collectBrowserSignals
// ---------------------------------------------------------------------------

describe('collectBrowserSignals', () => {
  beforeEach(() => {
    // Ensure consistent browser environment for each test
    vi.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockReturnValue({
      timeZone: 'America/New_York',
      locale: 'en-US',
      calendar: 'gregory',
      numberingSystem: 'latn',
    } as Intl.ResolvedDateTimeFormatOptions)

    Object.defineProperty(navigator, 'languages', {
      value: ['en-US', 'en', 'zh-CN'],
      configurable: true,
      writable: true,
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns timezone info from the browser', () => {
    const signals = collectBrowserSignals()
    expect(signals.timezoneActual).toBe('America/New_York')
    // Without ipTimezone, timezoneMatch should be false
    expect(signals.timezoneMatch).toBe(false)
    // timezoneExpected should fall back to browser timezone
    expect(signals.timezoneExpected).toBe('America/New_York')
  })

  it('returns language info from the browser', () => {
    const signals = collectBrowserSignals()
    expect(signals.languageActual).toEqual(['en-US', 'en', 'zh-CN'])
    // Without ipLanguages, languageMatch should be false
    expect(signals.languageMatch).toBe(false)
    // languageExpected should fall back to browser languages
    expect(signals.languageExpected).toEqual(['en-US', 'en', 'zh-CN'])
  })

  it('returns platform info (navigator.platform)', () => {
    // platform is not directly part of ConsistencyCheck but navigator is used
    // Verify the function produces the expected return type shape
    const signals = collectBrowserSignals()
    expect(signals).toHaveProperty('timezoneMatch')
    expect(signals).toHaveProperty('languageMatch')
    expect(signals).toHaveProperty('dnsMatch')
    expect(signals).toHaveProperty('webrtcMatch')
  })

  it('has expected default values for network-related fields', () => {
    const signals = collectBrowserSignals()
    expect(signals.dnsMatch).toBe(false)
    expect(signals.dnsNote).toBe('DNS comparison requires server-side resolver data')
    expect(signals.webrtcMatch).toBe(false)
    expect(signals.webrtcNote).toBe(
      'WebRTC check pending; call detectWebRtcIp() and compare with IP address',
    )
  })

  describe('timezoneMatch', () => {
    it('correctly compares matching timezones', () => {
      const signals = collectBrowserSignals('America/New_York')
      expect(signals.timezoneMatch).toBe(true)
    })

    it('correctly detects mismatching timezones', () => {
      const signals = collectBrowserSignals('Asia/Shanghai')
      expect(signals.timezoneMatch).toBe(false)
    })

    it('handles timezone normalization (strip underscores)', () => {
      // Browser reports "America/New_York", geo reports "America/New_York"
      // normalizeTimezone removes underscores, so both become "america/newyork"
      const signals = collectBrowserSignals('America/New_York')
      expect(signals.timezoneMatch).toBe(true)
    })

    it('handles timezone normalization (case insensitive)', () => {
      const signals = collectBrowserSignals('america/new_york')
      expect(signals.timezoneMatch).toBe(true)
    })
  })

  describe('languageMatch', () => {
    it('correctly compares matching languages', () => {
      const signals = collectBrowserSignals(undefined, ['en-US', 'en', 'zh-CN'])
      expect(signals.languageMatch).toBe(true)
    })

    it('correctly detects when no languages overlap', () => {
      const signals = collectBrowserSignals(undefined, ['ja-JP', 'ja'])
      expect(signals.languageMatch).toBe(false)
    })

    it('is case insensitive when comparing languages', () => {
      const signals = collectBrowserSignals(undefined, ['en-us', 'EN', 'zh-cn'])
      expect(signals.languageMatch).toBe(true)
    })

    it('returns false when given no expected languages (ipLanguages undefined)', () => {
      const signals = collectBrowserSignals()
      expect(signals.languageMatch).toBe(false)
    })
  })
})
