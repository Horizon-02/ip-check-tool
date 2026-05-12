import type { IpCheckResponse, IpCheckError, ConsistencyCheck } from '../types/ipCheck'

const TIMEOUT_MS = 15000

export class ApiError extends Error {
  code: string
  details: string | null

  constructor(message: string, code: string, details: string | null = null) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.details = details
  }

  toJSON() {
    return { error: this.message, code: this.code, details: this.details }
  }
}

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS)

  // Merge external abort signal (from component cleanup) with timeout
  const externalSignal = options?.signal
  if (externalSignal) {
    if (externalSignal.aborted) {
      clearTimeout(timeoutId)
      throw new DOMException('Aborted', 'AbortError')
    }
    externalSignal.addEventListener('abort', () => {
      clearTimeout(timeoutId)
      controller.abort()
    })
  }

  // Strip signal from options to avoid passing conflicting signals
  const { signal: _, ...restOptions } = options ?? {}

  try {
    const response = await fetch(url, {
      ...restOptions,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...restOptions?.headers,
      },
    })

    if (!response.ok) {
      let errorBody: IpCheckError | null = null
      try {
        errorBody = await response.json() as IpCheckError
      } catch {
        // response body not valid JSON
      }

      throw new ApiError(
        errorBody?.error ?? `HTTP ${response.status} ${response.statusText}`,
        errorBody?.code ?? `HTTP_${response.status}`,
        errorBody?.details ?? null,
      )
    }

    return await response.json() as T
  } catch (err) {
    if (err instanceof ApiError) throw err
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiError('Request timed out', 'TIMEOUT')
    }
    throw new ApiError(
      err instanceof Error ? err.message : 'Unknown network error',
      'NETWORK_ERROR',
    )
  } finally {
    clearTimeout(timeoutId)
  }
}

export async function fetchCurrentIp(signal?: AbortSignal): Promise<IpCheckResponse> {
  return apiFetch<IpCheckResponse>('/api/ip-check/current', { signal })
}

export async function checkIpScore(ip?: string, signal?: AbortSignal, consistency?: ConsistencyCheck): Promise<IpCheckResponse> {
  return apiFetch<IpCheckResponse>('/api/ip-check/score', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...(ip ? { ip: ip.trim() } : {}), consistency: consistency ?? null }),
    signal,
  })
}

export async function fetchReputation(
  ip: string,
  signal?: AbortSignal,
): Promise<Pick<IpCheckResponse, 'abuseRecord' | 'blacklistRecords' | 'dataSources'>> {
  return apiFetch<Pick<IpCheckResponse, 'abuseRecord' | 'blacklistRecords' | 'dataSources'>>(
    `/api/ip-check/reputation?ip=${encodeURIComponent(ip.trim())}`,
    { signal },
  )
}
