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
| `DATA_DIR` | Where JSON feeds + history are stored | `/data` (Docker) |
| `RATE_LIMIT` | Global per-IP requests per minute | `60` |
| `CORS_ORIGIN` | `Access-Control-Allow-Origin` value | (CORS disabled) |
| **Auth** | | |
| `ADMIN_TOKEN` | Single admin bearer token | (none — admin endpoints unprotected) |
| `ADMIN_TOKENS` | Named tokens: `alice:tok1,bob:tok2` | — |
| `METRICS_TOKEN` | Bearer token for `GET /metrics` (optional — open if unset) | — |
| **Notifications** | | |
| `WEBHOOK_URL` | POST JSON on sync changes + stale alerts | — |
| `WEBHOOK_SECRET` | HMAC-SHA256 sign webhook payloads (`X-Signature`) | — |
| `LINE_NOTIFY_TOKEN` | LINE Notify — sends on sync changes / watch hits / stale | — |
| `SMTP_HOST` | SMTP server for email notifications | — |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_SECURE` | Use TLS (`true`/`false`) | `false` |
| `SMTP_USER` | SMTP auth username | — |
| `SMTP_PASS` | SMTP auth password | — |
| `SMTP_FROM` | Sender address | same as `SMTP_USER` |
| `SMTP_TO` | Recipient address(es) | — |
| **Feeds** | | |
| `EXTRA_FEEDS` | Extra blocklist feeds: `name:url,name2:url2` | — |

---

## API Reference

### Stats & Info

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /healthz` | — | `{ok, sync_last_run, sync_next_run}` — lightweight monitoring probe |
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
| `POST /scan` | text/plain (≤2MB) | Scan log text — returns `{scanned, hits[], lines[{line,text,ips[]}]}`. Rate limited: 30/min. |
| `POST /scan/csv` | text/plain (≤2MB) | Same as `/scan` but returns CSV download with `line_no,ip,log_excerpt` columns. Rate limited: 30/min. |
| `GET /export/iptables` | — | iptables + ipset shell script (IP feed) |
| `GET /export/dnsmasq` | — | dnsmasq `address=/domain/0.0.0.0` format |
| `GET /export/wazuh` | — | Wazuh CDB list `hash:ncsa-blacklist` format |
| `GET /export/csv/:type` | — | Feed as CSV — type: `ip`, `domain`, or `hash` |
| `GET /export/json` | — | All feeds bundled: `{ip:{feed,generated_at,total,data[]},…}` |

### Network Analysis

| Endpoint | Description |
|----------|-------------|
| `GET /analyze/networks` | Top 50 /24 subnets by blacklisted IP count + country/AS. Supports `?country=TH` filter. |
| `GET /analyze/countries` | Top 25 countries by IP count + percentage. Returns `{total_ips, total_countries, top[{country,count,pct}]}` |
| `GET /analyze/asns` | Top 30 ASNs by blacklisted IP count. Returns `{total_ips, total_asns, top[{asn,org,count,country}]}` |

### Monitoring

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /metrics` | `METRICS_TOKEN` (optional) | Prometheus text format. Gauges: `ncsa_store_size`, `ncsa_feed_up`, `ncsa_feed_file_age_seconds`, `ncsa_memory_rss_bytes`, `ncsa_rate_limit_keys`, `ncsa_sync_last_run_timestamp` |
| `GET /healthz` | — | `{ok, sync_last_run, sync_next_run}` — lightweight probe |

### Admin (requires auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /admin/health` | Auth | uptime, RSS/heap MB, store sizes, file sizes, rate limit key count |
| `GET /admin/feed-health` | Auth | Per-feed status: `ok`/`stale`/`missing`, entries, `file_age_seconds`, `last_modified`, `file_size_kb`, feed URL |
| `GET /admin/summary?days=7` | Auth | Sync summary for last N days; add `&send=true` to email it |
| `POST /admin/webhook-test` | Auth + JSON `{webhook}` | Send test ping; returns `{ok, status}` |
| `POST /reload` | Auth | Force re-load store from disk |

### Watch List & Allow List (requires auth for write)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /watch` | — | List all watched entries |
| `POST /watch` | Auth + JSON `{type, value}` | Add entry — alert fires (webhook/email/LINE) when value appears in feed |
| `DELETE /watch` | Auth + JSON `{type, value}` | Remove entry |
| `GET /allowlist` | — | List all allowlisted entries |
| `POST /allowlist` | Auth + JSON `{type, value}` | Add entry — allowlisted values always return `blacklisted: false, allowlisted: true` regardless of feed content |
| `DELETE /allowlist` | Auth + JSON `{type, value}` | Remove entry |

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
  "geo": { "country": "US", "city": null, "as": null, "org": null },
  "rdns": "host.example.com",
  "risk": 65,
  "feeds": ["ip"]
}
```

Allowlisted value (overrides blacklist):
```json
{
  "type": "ip",
  "value": "8.8.8.8",
  "blacklisted": false,
  "allowlisted": true,
  "matched": "8.8.8.8",
  "matchType": "exact"
}
```

Domain with parent match:
```json
{
  "type": "domain",
  "value": "sub.evil.com",
  "blacklisted": true,
  "matched": "evil.com",
  "matchType": "parent"
}
```

### `/admin/feed-health`
```json
{
  "feeds": {
    "ip": {
      "status": "ok",
      "entries": 19453,
      "file_age_seconds": 14400,
      "last_modified": "2026-06-26T01:00:00.000Z",
      "file_size_kb": 312,
      "url": "https://opendata.ncsa.or.th/ip/blocklist.json"
    }
  }
}
```
`status` values: `ok` (age < 25h), `stale` (age ≥ 25h), `missing` (file not found).

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
│   ├── server.js       Express API + all endpoints (exports app for testing)
│   ├── fetch.js        Feed fetcher + ETag/SHA256 change detection + diff writer
│   ├── scheduler.js    node-cron: daily sync at 01:00, hourly stale check
│   ├── store.js        Load feed JSON from disk into memory Sets
│   ├── scan.js         Log scanner (regex IP extraction + blacklist match)
│   ├── watchlist.js    Watch list persistence (data/watchlist.json)
│   ├── allowlist.js    Allow list persistence (data/allowlist.json)
│   ├── notify.js       Webhook/LINE/email dispatch; notifyStale() for feed alerts
│   ├── auth.js         ADMIN_TOKEN / ADMIN_TOKENS bearer auth middleware
│   ├── geoip.js        geoip-lite wrapper (offline MaxMind GeoLite2)
│   ├── news.js         ThaICERT cybernews CKAN fetch + CSV parser
│   ├── diff.js         Set diff (added/removed)
│   └── paths.js        DATA_DIR resolution from env
├── test/
│   ├── allowlist.test.js
│   ├── auth.test.js
│   ├── diff.test.js
│   ├── fetch.test.js
│   ├── notify.test.js
│   ├── scan.test.js
│   ├── scheduler.test.js
│   ├── server.test.js  (integration — starts real HTTP server)
│   └── watchlist.test.js
├── public/
│   └── index.html      Single-file SPA (no build step)
├── data/               (Docker volume: ncsa-data)
│   ├── ip.json / domain.json / hash.json
│   ├── history.jsonl       Sync history (up to 1000 records)
│   ├── recent.jsonl        Sync diffs with added/removed values
│   ├── watchlist.json      Watch entries
│   ├── allowlist.json      Allow entries
│   ├── etag-state.json     ETag/Last-Modified per feed (conditional GET)
│   └── stale-alert-state.json  Last alert timestamp per feed (dedup)
├── .github/workflows/ci.yml   Node 18/20/22 matrix CI
├── Dockerfile
├── docker-compose.yml
└── .env                (never commit — see .env.example)
```

**Data flow:**
```
NCSA opendata.ncsa.or.th
  → fetch.js: send If-None-Match (ETag) → 304 = skip entirely
  → if 200: SHA256 check → skip write if unchanged
  → anomaly guard (>50% removed → abort)
  → write ip.json / domain.json / hash.json
  → save ETag for next request
  → append history.jsonl + recent.jsonl
  → notify: webhook / LINE / email if changes or watch hits

scheduler.js (hourly):
  → check feed file age → if >25h: notifyStale()
  → dedup: only re-alert after 24h cooldown per feed
  → clear state when feed recovers
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
| Network Analysis | Two tabs: (1) Top /24 bar chart, country filter input, click → CIDR check; (2) By Country — flag emoji + percentage bar |
| Single Lookup | Copy button + share link (🔗) on results; permalink via `?q=value` URL param |
| Bulk Check | File upload (.txt/.csv) → auto-populate textarea for batch check |
| Trend Chart | 30 sync history chart (IP/Domain/Hash tabs) |
| About | MISP provenance, source query, publisher, license, TLP |

## Rate Limits (per IP, per minute)

| Endpoint | Limit |
|----------|-------|
| `POST /check/bulk` | 120 req/min |
| `POST /scan`, `POST /scan/csv` | 30 req/min |
| `POST /check/cidr` | 60 req/min |
| All routes (global) | `RATE_LIMIT` env (default: 60 req/min) |

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
# 67 tests across 9 test files
# Covers: auth, allowlist, diff, fetch (ETag via mock HTTP), notify, scan, scheduler, server (integration), watchlist
```

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

- Admin endpoints require `Authorization: Bearer <token>` (set `ADMIN_TOKEN` or `ADMIN_TOKENS`)
- `GET /metrics` is open by default — set `METRICS_TOKEN` to restrict in public deployments
- Webhook payloads are HMAC-SHA256 signed when `WEBHOOK_SECRET` is set (`X-Signature: sha256=<hex>`)
- No user input is eval'd; all HTML output goes through `esc()` (XSS-safe)
- Feed anomaly guard: aborts write if >50% of entries removed in one sync
- SIGTERM/SIGINT: graceful shutdown — waits for in-flight requests, force-exits after 10s
- Do **not** expose port 3939 publicly without a reverse proxy + TLS

---

## Data Sources

| Source | URL | License |
|--------|-----|---------|
| NCSA IP/domain/hash blocklist | `opendata.ncsa.or.th` | CC0-1.0 |
| CKAN package metadata | `data.go.th` | Open Government Data |
| ThaICERT cybernews | `ncsa.gdcatalog.go.th` | Public |
| GeoIP (offline) | `geoip-lite` npm (MaxMind GeoLite2) | CC BY-SA 4.0 |
