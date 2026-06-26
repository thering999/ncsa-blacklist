# NCSA Blacklist — Development & Usage Guide

> Last updated: 2026-06-26

---

## Overview

Self-hosted threat intelligence service synced from [NCSA Thailand](https://opendata.ncsa.or.th) MISP-sourced blocklists (TLP:CLEAR).

**Three data feeds:**
| Feed | URL | Update |
|------|-----|--------|
| IP blocklist | `opendata.ncsa.or.th/ip/blocklist.json` | Daily |
| Domain blocklist | `opendata.ncsa.or.th/domain/blocklist.json` | Daily |
| SHA256 hash blocklist | `opendata.ncsa.or.th/hash/sha256.json` | Daily |

**Extra dataset:** ThaICERT cybernews (CKAN, monthly CSV) — fetched on page load, cached 6h.

---

## Quick Start (Docker)

```bash
# Clone
git clone https://github.com/thering999/ncsa-blacklist.git
cd ncsa-blacklist

# Copy env
cp .env.example .env
# Edit .env: set ADMIN_TOKEN, WEBHOOK_SECRET, etc.

# Run
docker-compose up -d

# First fetch (data is empty until this runs)
docker exec ncsa-blacklist-ncsa-blacklist-1 node src/fetch.js

# Open UI
open http://localhost:3939
```

**Scheduler runs automatically** inside `ncsa-blacklist-sync` container every 6 hours (cron: `0 */6 * * *`).

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP port | `3939` |
| `ADMIN_TOKEN` | Single admin bearer token | (none — watch/reload unprotected) |
| `ADMIN_TOKENS` | Named tokens: `name:token,name2:token2` | — |
| `WEBHOOK_SECRET` | HMAC-SHA256 secret for watch notifications | — |
| `DATA_DIR` | Where JSON feeds + history are stored | `/data` (Docker) |

---

## API Reference

### Stats & Info

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /stats` | — | Count, generated_at, TLP, sha256, file_entries, integrity_ok per feed |
| `GET /info` | — | Full provenance: publisher, MISP source URL, query, license, contact |
| `GET /history` | — | Last 30 sync records (jsonl, newest first) |
| `GET /recent?type=ip&limit=15` | — | Latest sync diffs: added/removed values + GeoIP for IPs |

### Lookup

| Endpoint | Method | Body / Params | Description |
|----------|--------|---------------|-------------|
| `GET /check/auto/:value` | — | — | Auto-detect type (IP/domain/hash). Domain: parent-domain check. IP: GeoIP enriched. |
| `GET /check/:type/:value` | — | `type` = ip\|domain\|hash | Exact lookup |
| `POST /check/bulk` | JSON | `{type, values[]}` max 10 000 | Batch lookup; domain uses parent-matching |
| `POST /check/cidr` | JSON | `{cidr: "1.2.3.0/24"}` max /16 | Find blacklisted IPs in subnet |
| `GET /search?type=ip&q=23.129` | — | q ≥ 3 chars | Partial match, max 100 results |

### Scan & Export

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /scan` | text/plain (≤2MB) | Scan log text — returns hit lines with context. Rate limited: 30 req/min. |
| `GET /export/iptables` | — | iptables-restore format (IP feed) |
| `GET /export/dnsmasq` | — | dnsmasq `address=/domain/` format |
| `GET /export/wazuh` | — | Wazuh CDB list format |
| `GET /export/csv/ip` | — | IP list, one per line (CSV) |
| `GET /export/csv/domain` | — | Domain list, one per line (CSV) |
| `GET /export/csv/hash` | — | SHA256 list, one per line (CSV) |
| `GET /export/json` | — | All 3 feeds bundled as JSON `{ip:{feed,generated_at,total,data[]},…}` |

### Network Analysis

| Endpoint | Description |
|----------|-------------|
| `GET /analyze/networks` | Top 25 /24 subnets by blacklisted IP count + country/AS. Rows clickable → CIDR check. |
| `GET /analyze/countries` | Top 25 countries by IP count + percentage. Returns `{total_ips, total_countries, top[{country,count,pct}]}` |

### Admin (requires auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /admin/health` | Auth | uptime, RSS/heap MB, store sizes, file sizes, rate limit key count, Node version |
| `POST /admin/webhook-test` | Auth + JSON `{webhook}` | Send test ping to webhook URL; returns `{ok, status}` |

### Watch List (requires auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /watch` | Auth | List watched entries |
| `POST /watch` | Auth + JSON `{type, value, webhook}` | Add watch entry |
| `DELETE /watch/:id` | Auth | Remove entry |
| `POST /reload` | Auth | Force re-fetch all feeds now |

### News & Recent

| Endpoint | Description |
|----------|-------------|
| `GET /news?limit=25` | ThaICERT cybernews (latest monthly CSV, cached 6h) |
| `GET /recent?limit=15&type=ip` | Recent sync diffs (populated after first change) |

---

## Response Schemas

### `/check/auto/:value`
```json
{
  "type": "ip",
  "value": "23.129.64.100",
  "blacklisted": true,
  "matched": "23.129.64.100",
  "matchType": "exact",
  "geo": { "country": "US", "city": null, "as": null, "org": null }
}
```

For domain with parent match:
```json
{
  "type": "domain",
  "value": "sub.evil.com",
  "blacklisted": true,
  "matched": "evil.com",
  "matchType": "parent"
}
```

### `/check/cidr`
```json
{
  "cidr": "23.129.64.0/24",
  "range_start": "23.129.64.0",
  "range_end": "23.129.64.255",
  "total_in_range": 256,
  "hits_count": 57,
  "hits": [{ "ip": "23.129.64.100", "geo": { "country": "US" } }]
}
```

### `/stats`
```json
{
  "ip": {
    "total": 19453,
    "generated_at": "2026-06-25T...",
    "valid_for_days": 7,
    "expires_at": "2026-07-02",
    "tlp": "clear",
    "sha256": "abc...",
    "file_entries": 19453,
    "integrity_ok": true,
    "feed": "NCSA Thailand Public IP Blocklist"
  }
}
```

---

## Architecture

```
ncsa-blacklist/
├── src/
│   ├── server.js       Express API + all endpoints
│   ├── fetch.js        Feed fetcher + SHA256 change detection + diff writer
│   ├── scheduler.js    node-cron (runs fetch every 6h)
│   ├── store.js        Load feed JSON from disk into memory Sets
│   ├── scan.js         Log scanner (regex IP extraction + blacklist match)
│   ├── watchlist.js    Watch list persistence (JSON file)
│   ├── notify.js       Webhook dispatch (HMAC-signed)
│   ├── auth.js         ADMIN_TOKEN / ADMIN_TOKENS bearer auth
│   ├── geoip.js        geoip-lite wrapper (offline MaxMind GeoLite2)
│   ├── news.js         ThaICERT cybernews CKAN fetch + CSV parser
│   ├── diff.js         Set diff (added/removed)
│   └── paths.js        DATA_DIR resolution
├── public/
│   └── index.html      Single-file SPA (no build step)
├── data/               (Docker volume: ncsa-data)
│   ├── ip.json         Latest IP feed snapshot
│   ├── domain.json     Latest domain feed snapshot
│   ├── hash.json       Latest hash feed snapshot
│   ├── history.jsonl   Sync history (count per run)
│   ├── recent.jsonl    Sync diffs with actual added/removed values
│   └── watchlist.json  Watch entries
├── Dockerfile
├── docker-compose.yml
└── .env                (never commit)
```

**Data flow:**
```
NCSA opendata.ncsa.or.th
  → fetch.js (SHA256 check → skip if unchanged)
  → diff against prev snapshot
  → write ip.json / domain.json / hash.json
  → append history.jsonl + recent.jsonl
  → POST reload → server re-loads store
  → notify watch webhook if hit
```

---

## UI Features

| Section | Feature |
|---------|---------|
| Header | Dark/light mode toggle (🌙/☀️), last-updated timestamp, settings gear |
| Sticky Nav | Jump links to all 13 sections; active section highlighted while scrolling |
| Stats cards | IP / Domain / Hash counts, TLP badge, freshness indicator, integrity check |
| New-since-visit | Green banner when feed counts grew since last page load (localStorage) |
| Recent Activity | Per-sync added/removed entries with GeoIP country |
| Single Lookup | Auto-detect type, parent domain matching, GeoIP |
| CIDR Check | Find all blacklisted IPs in a subnet (max /16) |
| Bulk Check | Paste list → POST /check/bulk (up to 10 000) |
| Search | Partial match across any feed type |
| Log Scan | File upload (.log/.txt) or drag-drop or paste text → hit lines with context |
| Settings: Health | Admin panel shows uptime, memory, store sizes (requires token) |
| Settings: Webhook test | Send test ping to any webhook URL, shows HTTP response |
| Export | iptables / dnsmasq / wazuh / IP CSV / Domain CSV / Hash CSV / JSON bundle |
| Watch List | Monitor values → webhook alert when added to blacklist |
| ThaICERT News | Latest cybersecurity news (monthly CSV, clickable headlines) |
| Network Analysis | Two tabs: (1) Top /24 subnets bar chart — click row → CIDR check; (2) By Country — flag emoji + percentage bar |
| Trend Chart | 30 sync history chart (IP/Domain/Hash tabs) |
| About | MISP provenance, source query, publisher, license, TLP |

## Rate Limits (per IP, per minute)

| Endpoint | Limit |
|----------|-------|
| `POST /check/bulk` | 120 req/min |
| `POST /scan` | 30 req/min |
| `POST /check/cidr` | 60 req/min |
| All others | none (behind reverse proxy / firewall recommended) |

**Dark mode** — toggle persists to localStorage.

---

## Development

### Prerequisites
- Node.js ≥ 18
- Docker + Docker Compose (for production-like setup)

### Local run (no Docker)
```bash
npm install
DATA_DIR=./local-data node src/fetch.js    # fetch data first
DATA_DIR=./local-data node src/server.js   # start server
```

### Run tests
```bash
npm test
```

Tests in `test/` cover: scan.js, diff.js, auth.js.

### Add a new endpoint
1. Add handler in `src/server.js`
2. Route-order rule: specific routes (e.g., `/check/auto/:v`) must come **before** parameterized ones (`/check/:type/:v`)
3. Update this guide's API table

### Modify the feed sync
- Feed URLs in `src/fetch.js` → `FEEDS` object
- SHA256 change detection: `json.file?.sha256` vs `prev.file?.sha256`
- Anomaly guard: skips write if >50% of entries removed in one sync

### Update GeoIP database
```bash
# Inside running container or locally:
node -e "require('geoip-lite').reloadDataSync()"
# Or:
npm run-script updatedb  # if geoip-lite postinstall script available
```

---

## Security Notes

- Admin endpoints (`/watch`, `/reload`) require `Authorization: Bearer <token>`
- Webhook payloads are HMAC-SHA256 signed (`X-Webhook-Signature: sha256=<hex>`)
- No user input is eval'd; all HTML output goes through `esc()` (XSS-safe)
- Feed anomaly guard prevents catastrophic data loss on upstream errors
- Do **not** expose port 3939 publicly without a reverse proxy + TLS

---

## Data Sources

| Source | URL | License |
|--------|-----|---------|
| NCSA IP/domain/hash blocklist | `opendata.ncsa.or.th` | CC0-1.0 |
| CKAN package metadata | `data.go.th` | Open Government Data |
| ThaICERT cybernews | `ncsa.gdcatalog.go.th` | Public |
| GeoIP (offline) | `geoip-lite` npm (MaxMind GeoLite2) | CC BY-SA 4.0 |
