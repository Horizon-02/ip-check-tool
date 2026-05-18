# IP Reputation Check Tool (IP 检测工具)

A comprehensive IP address reputation checking tool that evaluates trustworthiness, anonymity, and network quality of any IP address. Built with a React frontend and Express backend.

## Features

- **IP Scoring**: Multi-dimensional scoring across 6 categories (100 points total)
- **Geolocation**: Country, region, city, coordinates, and timezone
- **ASN/ISP Detection**: Organization and ISP information
- **Proxy/VPN/Tor Detection**: Identifies anonymization services
- **Abuse Record Check**: AbuseIPDB integration for reported abuse data
- **Blacklist Monitoring**: Checks multiple blacklist databases
- **Environment Consistency**: Browser timezone, language, DNS, and WebRTC consistency checks
- **Network Quality**: Latency, packet loss, and IPv4/IPv6 support
- **History**: Local storage-based check history
- **Bilingual UI**: Full Chinese and English interface

## Architecture

```
ip-check-tool/
├── src/                      # Frontend (React + Vite + TypeScript + Tailwind)
│   ├── components/
│   │   └── IpCheckPage.tsx   # Main page component
│   ├── lib/
│   │   ├── api.ts            # API client (fetch wrappers)
│   │   ├── ipScore.ts        # Scoring engine
│   │   └── envConsistency.ts # Browser environment checks
│   ├── types/
│   │   └── ipCheck.ts        # TypeScript type definitions
│   └── test-setup.ts         # Test setup imports
├── server/                   # Backend (Express + TypeScript)
│   ├── index.ts              # Express server with API routes
│   ├── dataSources.ts        # External data source fetchers
│   ├── ipValidator.ts        # IP address validation utilities
│   ├── rateLimiter.ts        # In-memory rate limiting
│   └── cache.ts              # In-memory TTL cache
├── tests/                    # Test files
│   ├── frontend/             # Frontend component tests
│   └── server/               # Backend integration tests
├── vite.config.ts            # Vite configuration with API proxy
└── vitest.config.ts          # Test runner configuration
```

### Frontend

- **Framework**: React 19 with TypeScript
- **Build Tool**: Vite 6
- **Styling**: Tailwind CSS 3
- **Icons**: Lucide React
- **Testing**: Vitest + Testing Library + jsdom

### Backend

- **Runtime**: Express 4 with TypeScript (via tsx)
- **API Proxy**: Vite dev server proxies `/api` to the backend on port 3001
- **Caching**: In-memory TTL cache (60s geo, 2min abuse, 30s score)
- **Rate Limiting**: Configurable per-IP rate limiting

## Setup

### Prerequisites

- Node.js >= 18
- npm

### Installation

```bash
# Clone the repository
git clone <repo-url> && cd ip-check-tool

# Install dependencies
npm install
```

### Configuration

Create a `.env` file in the project root:

```env
# Server port (default: 3001)
PORT=3001

# AbuseIPDB API key (optional — without it abuse checks are skipped)
ABUSEIPDB_API_KEY=your_key_here

# Rate limiting: max requests per window
RATE_LIMIT_MAX=10

# Rate limiting: window duration in milliseconds (default: 60000 = 1 minute)
RATE_LIMIT_WINDOW_MS=60000
```

### Running Locally

```bash
# Start both frontend and backend (recommended)
npm run dev:all

# Or start them separately in two terminals:
npm run dev          # Frontend on http://localhost:5173
npm run dev:server   # Backend on http://localhost:3001
```

The Vite dev server proxies `/api/*` requests to the Express backend automatically.

## API Endpoints

### `GET /api/health`

Health check endpoint.

**Response:**
```json
{ "status": "ok", "timestamp": "2026-05-12T10:00:00.000Z" }
```

### `GET /api/ip-check/current`

Quick current-IP lookup. Detects the client's IP from the request and returns geo, ASN, network type, and proxy data.

**Response:** Partial `IpCheckResponse` (no score, abuse, or consistency data).

### `POST /api/ip-check/score`

Full IP reputation scoring. Accepts an IP address in the request body or auto-detects the client IP.

**Request:**
```json
{ "ip": "8.8.8.8" }
```

**Response:** Full `IpCheckResponse` with all data sources and computed score.

**Rate limited:** Yes (configurable).

### `GET /api/ip-check/reputation?ip=8.8.8.8`

Abuse and blacklist data for a specific IP address.

**Query parameters:** `ip` (required) — the IP address to look up.

**Response:** Abuse record, blacklist records, proxy detection.

**Rate limited:** Yes (configurable).

### Error Responses

All endpoints return errors in a consistent format:

```json
{
  "error": "Description of the error",
  "code": "ERROR_CODE",
  "details": "Additional information (may be null)"
}
```

Common error codes: `INVALID_IP`, `PRIVATE_IP`, `MISSING_IP`, `RATE_LIMITED`, `TIMEOUT`, `NETWORK_ERROR`.

## Data Sources

| Source | Type | Required | Description |
|--------|------|----------|-------------|
| ipapi.co | Geo/IP | Yes (free tier) | Geolocation, ASN, network type, proxy detection |
| AbuseIPDB | Abuse | No (optional API key) | Abuse confidence scores and reports |

The free tier of ipapi.co provides sufficient data for basic scoring. AbuseIPDB requires an API key for abuse report data; without it, abuse-related score dimensions are skipped.

## Scoring Model

The IP reputation score is calculated across 6 dimensions, totaling 100 points:

| Dimension | Max Score | Description |
|-----------|-----------|-------------|
| Geo Trust | 15 | Geolocation data completeness and ASN legitimacy |
| Network Type | 15 | Residential/business networks score higher than datacenter/hosting |
| Proxy Risk | 25 | VPN, proxy, Tor (20pt deduction), and relay detection |
| Abuse Risk | 25 | AbuseIPDB confidence score and blacklist presence (5pt per listing) |
| Environment Consistency | 5 | Browser timezone/language/DNS/WebRTC — informational reference only |
| Network Quality | 10 | Latency (>300ms: -5, >150ms: -2), packet loss, IPv4/IPv6 support |

Note: Environment consistency is **not penalized** in the IP score — mismatches are EXPECTED when using proxies and are shown as informational data only.

### Risk Levels

| Score Range | Level | Description |
|-------------|-------|-------------|
| 85-100 | Excellent | IP appears legitimate and safe |
| 70-84 | Good | Low risk, standard verification recommended |
| 50-69 | Caution | Some suspicious characteristics |
| 30-49 | High Risk | Significant risk indicators |
| 0-29 | Not Recommended | Strongly consider blocking |

An "Uncertain" level is used when more than 50% of data sources fail.

## Security Notes

- **API keys are server-side only**: The AbuseIPDB API key is used exclusively in the Express backend and never exposed to the client.
- **Rate limiting**: All scoring and reputation endpoints are rate-limited per client IP to prevent abuse.
- **No client-side secrets**: The Vite dev server proxies API calls, keeping backend configuration hidden from the browser.
- **Input validation**: All IP addresses are validated and sanitized server-side. Only public, routable IP addresses are accepted.
- **CORS**: The backend allows cross-origin requests but should be restricted in production.
- **Cache Control**: Responses include `Cache-Control` headers to allow CDN and browser caching where appropriate.

## Deployment

### Production Build

```bash
# Build the frontend
npm run build

# Output: dist/ directory with static assets
```

### Production Server

For production, serve the Express backend with the built frontend assets. You may want to:

1. Configure a process manager (PM2, systemd)
2. Set up a reverse proxy (Nginx, Caddy)
3. Enable HTTPS
4. Set stricter CORS origins
5. Configure proper caching headers

Example production setup with Nginx:

```nginx
server {
    listen 443 ssl;
    server_name ipcheck.example.com;

    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Frontend static assets
    root /path/to/ip-check-tool/dist;
    index index.html;

    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

### Running Tests

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch
```

## Development

### Project Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite dev server on port 5173 |
| `npm run dev:server` | Start Express backend on port 3001 |
| `npm run dev:all` | Start both frontend and backend concurrently |
| `npm run build` | TypeScript check + Vite production build |
| `npm test` | Run all tests with Vitest |

### Tech Stack

- **Frontend**: React 19, TypeScript 5.6, Vite 6, Tailwind CSS 3, Lucide React icons
- **Backend**: Express 4, TypeScript (via tsx)
- **Testing**: Vitest 2, Testing Library 16, jsdom 25
- **Runtime**: Node.js >= 18
