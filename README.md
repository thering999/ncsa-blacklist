# 🛡️ NCSA Blacklist — ระบบตรวจสอบ Threat Intelligence ของประเทศไทย

บริการ self-hosted สำหรับซิงค์และค้นหาข้อมูล blocklist สาธารณะจาก [NCSA Thailand](https://opendata.ncsa.or.th) ซึ่งมาจาก MISP feed อัปเดตทุกวัน ใบอนุญาต CC0

**ข้อมูลที่ครอบคลุม:** IP ที่เป็นอันตราย · โดเมนที่เป็นอันตราย · SHA256 hash ของมัลแวร์

---

## ฟีเจอร์หลัก

| ฟีเจอร์ | รายละเอียด |
|---------|-----------|
| 🔍 **ตรวจสอบ** | IP / Domain / Hash — auto-detect ประเภท, รองรับ IPv6, parent-domain matching |
| 🌐 **CIDR Check** | ค้นหา IP ที่อยู่ใน blacklist ทั้งหมดภายใน subnet (สูงสุด /16) |
| 📋 **Bulk Check** | ส่งรายการสูงสุด 10,000 รายการใน request เดียว, รองรับ auto-detect |
| 📂 **Log Scan** | วาง/upload log file → ระบุ IP ที่อันตรายพร้อม context บรรทัด |
| 🔎 **Search** | ค้นหาแบบ partial match + pagination รองรับข้อมูลขนาดใหญ่ |
| 🌍 **GeoIP** | ข้อมูลประเทศ, เมือง, AS org จาก MaxMind GeoLite2 (offline) |
| 🔀 **Reverse DNS** | ค้น PTR record อัตโนมัติเมื่อตรวจสอบ IP |
| ⚡ **Risk Score** | คะแนนความเสี่ยง 0–100 ต่อ IP จาก: blacklist + ประเทศ + ความหนาแน่น CIDR |
| 📊 **Network Analysis** | Top /24 subnets + By Country (flag emoji + bar chart), กรองตามประเทศได้ |
| 👁️ **Watch List** | ติดตาม IP/domain/hash → แจ้งเตือนผ่าน Webhook / LINE Notify / Email |
| 📰 **ThaICERT News** | ข่าวความมั่นคงไซเบอร์ล่าสุด (CKAN CSV, cache 6 ชั่วโมง) |
| ⬇️ **Export** | iptables · dnsmasq · Wazuh CDB · CSV · JSON bundle |
| 🌙 **Dark Mode** | บันทึกค่าไว้ใน localStorage |
| 📱 **Mobile Responsive** | รองรับมือถือ ทุก breakpoint |

---

## เริ่มต้นใช้งาน (Docker — แนะนำ)

```bash
git clone https://github.com/thering999/ncsa-blacklist.git
cd ncsa-blacklist

# คัดลอกไฟล์ตัวอย่าง config
cp .env.example .env
# แก้ไข .env: ตั้ง ADMIN_TOKEN อย่างน้อย 1 ค่า

# เริ่มระบบ
docker compose up -d

# ดึงข้อมูลครั้งแรก (sync container จะทำเองหลังจาก start แต่รอรอบแรก ~6 ชม.)
# หรือรันเดี๋ยวนี้เลย:
docker compose exec ncsa-blacklist node src/fetch.js

# เปิด UI
open http://localhost:3939
```

ระบบประกอบด้วย 2 container บน volume เดียวกัน:
- `ncsa-blacklist` — Web UI + REST API บน port 3939
- `ncsa-blacklist-sync` — cron sync ทุก 6 ชั่วโมง (ตอนเปิดเครื่องก็ sync ทันที)

---

## เริ่มต้นใช้งาน (ไม่ใช้ Docker)

```bash
npm install
npm run fetch        # ดึงข้อมูลครั้งแรก
npm start            # Web UI + API บน port 3939
npm run schedule     # process แยก: sync ทุก 6 ชม.
```

---

## ตัวแปร Environment

| ตัวแปร | ค่าเริ่มต้น | คำอธิบาย |
|--------|-----------|----------|
| `PORT` | `3939` | HTTP port |
| `DATA_DIR` | `./data` | ที่เก็บ snapshot, history, watchlist |
| `ADMIN_TOKEN` | — | Bearer token สำหรับ endpoint ที่ต้องการสิทธิ์ (watch, reload, health) |
| `ADMIN_TOKENS` | — | หลาย token: `alice:token1,bob:token2` |
| `WEBHOOK_URL` | — | URL ที่รับ POST เมื่อ sync เสร็จหรือ watch hit |
| `WEBHOOK_SECRET` | — | เซ็น payload ด้วย HMAC-SHA256 (`X-Signature: sha256=<hex>`) |
| `LINE_NOTIFY_TOKEN` | — | Token LINE Notify — ส่งข้อความเมื่อ sync / watch hit |
| `SMTP_HOST` | — | SMTP server สำหรับส่ง email แจ้งเตือน |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_SECURE` | `false` | ใช้ TLS (`true`/`false`) |
| `SMTP_USER` | — | username SMTP |
| `SMTP_PASS` | — | password SMTP |
| `SMTP_FROM` | — | ที่อยู่ผู้ส่ง |
| `SMTP_TO` | — | ที่อยู่ผู้รับ |
| `EXTRA_FEEDS` | — | เพิ่ม feed เอง: `mylist:https://example.com/feed.json` |
| `CORS_ORIGIN` | — | อนุญาต cross-origin request จาก origin นี้ |

---

## API Reference

### ตรวจสอบ

```bash
# ตรวจสอบแบบ auto-detect (IPv4, IPv6, domain, hash)
GET /check/auto/1.10.214.0
GET /check/auto/evil.com
GET /check/auto/abc123...64chars

# ตรวจสอบแบบระบุประเภท
GET /check/ip/1.10.214.0
GET /check/domain/evil.com
GET /check/hash/<sha256>

# ผลลัพธ์ IP รวม: GeoIP, reverse DNS, risk score (0-100), multi-feed badge
```

```bash
# Bulk check (สูงสุด 10,000 รายการ)
POST /check/bulk
Content-Type: application/json
{"type":"auto","values":["1.2.3.4","evil.com","abc..."]}

# CIDR check (สูงสุด /16)
POST /check/cidr
{"cidr":"1.10.214.0/24"}

# Scan log (text body, สูงสุด 2MB)
POST /scan
Content-Type: text/plain
<log content>
```

### ค้นหา

```bash
# Partial search + pagination
GET /search?type=ip&q=1.10&page=1&limit=100
# → {total, page, pages, results[]}
```

### วิเคราะห์ Network

```bash
GET /analyze/networks          # Top 50 /24 subnets + country/AS
GET /analyze/networks?country=TH   # กรองเฉพาะประเทศ
GET /analyze/countries         # Top 25 ประเทศ + % ของ IP ทั้งหมด
```

### Export

```bash
GET /export/iptables           # ipset shell script
GET /export/dnsmasq            # dnsmasq config
GET /export/wazuh              # Wazuh CDB list
GET /export/csv/ip             # IP list (one per line)
GET /export/csv/domain         # Domain list
GET /export/csv/hash           # SHA256 list
GET /export/json               # JSON bundle (all 3 feeds)
```

### Watch List (ต้องใช้ Admin Token)

```bash
GET    /watch                  # ดูรายการที่ติดตาม
POST   /watch                  # เพิ่ม: {"type":"ip","value":"1.2.3.4","webhook":"https://..."}
DELETE /watch/:id              # ลบ
POST   /reload                 # โหลดข้อมูลใหม่จากดิสก์
```

### Admin

```bash
GET  /admin/health             # uptime, RAM, store sizes, rate limit keys
GET  /admin/summary?days=7     # สรุป 7 วัน (เพิ่ม ?send=true เพื่อส่ง email)
POST /admin/webhook-test       # ส่ง test ping: {"webhook":"https://..."}
```

### Monitoring

```bash
GET /healthz                   # {ok:true, sync_last_run, sync_next_run}
GET /stats                     # จำนวน + sha256 + integrity ต่อ feed
GET /info                      # provenance: publisher, MISP URL, license
GET /history?type=ip           # ประวัติ 30 sync ล่าสุด
GET /recent?limit=15           # diff ล่าสุด: เพิ่ม/ลบ + GeoIP
GET /news                      # ThaICERT cybernews (cache 6h)
```

---

## ตัวอย่าง Response

### ตรวจสอบ IP (blacklisted)
```json
GET /check/auto/1.10.214.0

{
  "type": "ip",
  "value": "1.10.214.0",
  "blacklisted": true,
  "matched": "1.10.214.0",
  "matchType": "exact",
  "geo": { "country": "TH", "city": "Bangkok", "as": "AS9931", "org": "CAT Telecom" },
  "rdns": "1-10-214-0.static.tbcz.net",
  "risk": 65,
  "feeds": ["ip"]
}
```

### ตรวจสอบ Domain (parent match)
```json
GET /check/auto/sub.evil.example.com

{
  "type": "domain",
  "value": "sub.evil.example.com",
  "blacklisted": true,
  "matched": "evil.example.com",
  "matchType": "parent",
  "feeds": ["domain"]
}
```

### Bulk Check (auto-detect)
```json
POST /check/bulk
{"type":"auto","values":["1.2.3.4","evil.com","abc...64hex..."]}

{
  "type": "auto",
  "results": [
    {"value":"1.2.3.4","type":"ip","blacklisted":false},
    {"value":"evil.com","type":"domain","blacklisted":true,"matched":"evil.com","matchType":"exact"},
    {"value":"abc...","type":"hash","blacklisted":false}
  ]
}
```

### CIDR Check
```json
POST /check/cidr
{"cidr":"1.10.214.0/24"}

{
  "cidr": "1.10.214.0/24",
  "range_start": "1.10.214.0",
  "range_end": "1.10.214.255",
  "total_in_range": 256,
  "hits_count": 3,
  "hits": [
    {"ip":"1.10.214.0","geo":{"country":"TH"}},
    {"ip":"1.10.214.1","geo":{"country":"TH"}}
  ]
}
```

### Risk Score ความหมาย

| คะแนน | สี | ความหมาย |
|-------|-----|----------|
| 0–39 | 🟢 เขียว | ความเสี่ยงต่ำ |
| 40–69 | 🟡 เหลือง | ความเสี่ยงปานกลาง |
| 70–100 | 🔴 แดง | ความเสี่ยงสูง |

คะแนนคำนวณจาก:
- อยู่ใน blacklist = **+50**
- ประเทศความเสี่ยงสูง (CN/RU/KP/IR/BY/CU/SY/VE) = **+15**
- CIDR density > 50 IPs ใน /24 เดียวกัน = **+20**
- CIDR density > 10 IPs = **+12**
- CIDR density > 2 IPs = **+5**

---

## Permalink

ทุก URL รองรับ query parameter สำหรับแชร์ผลลัพธ์:

```
http://localhost:3939/?q=1.10.214.0        # เปิดหน้าแล้ว check ทันที
http://localhost:3939/?cidr=1.10.0.0/16   # CIDR check ทันที
```

---

## Rate Limits

| Endpoint | จำกัด |
|---------|-------|
| `POST /check/bulk` | 120 req/min |
| `POST /scan` | 30 req/min |
| `POST /check/cidr` | 60 req/min |
| อื่นๆ | ไม่จำกัด (แนะนำใช้ reverse proxy + firewall) |

Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## HTTPS / Reverse Proxy

ระบบพูด HTTP เท่านั้น ใช้ reverse proxy สำหรับ TLS — ตัวอย่างใน `Caddyfile.example` และ `nginx.conf.example`

```
Caddy:  reverse_proxy localhost:3939
Nginx:  proxy_pass http://localhost:3939;
```

---

## สถาปัตยกรรม

```
ncsa-blacklist/
├── src/
│   ├── server.js      REST API + endpoint ทั้งหมด
│   ├── fetch.js       ดึง feed + SHA256 change detection + diff writer
│   ├── scheduler.js   cron (ทุก 6h)
│   ├── store.js       โหลด JSON เข้า memory Sets
│   ├── scan.js        log scanner (IPv4+IPv6 regex + blacklist match)
│   ├── watchlist.js   watch list persistence
│   ├── notify.js      webhook + LINE Notify + email (HMAC-signed)
│   ├── auth.js        bearer token middleware
│   ├── geoip.js       MaxMind GeoLite2 wrapper (offline)
│   ├── news.js        ThaICERT CKAN CSV fetcher
│   ├── diff.js        set diff (added/removed)
│   └── paths.js       DATA_DIR resolution
├── public/
│   └── index.html     Single-file SPA (ไม่ต้อง build)
├── data/              (Docker volume: ncsa-data)
│   ├── ip.json        IP feed snapshot
│   ├── domain.json    Domain feed snapshot
│   ├── hash.json      Hash feed snapshot
│   ├── history.jsonl  sync history (สูงสุด 1,000 บรรทัด)
│   ├── recent.jsonl   diff ล่าสุด (สูงสุด 120 รายการ)
│   └── watchlist.json watch entries
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── GUIDE.md           คู่มือ API + dev reference ฉบับเต็ม
```

---

## ความปลอดภัย

- Admin endpoint ทุกตัวต้องใช้ `Authorization: Bearer <token>`
- Webhook payload เซ็นด้วย HMAC-SHA256 (`X-Signature: sha256=<hex>`)
- ไม่มีการ eval input ใดๆ — HTML output ผ่าน `esc()` (XSS-safe)
- Feed anomaly guard: ถ้า upstream ลดข้อมูล >50% ในครั้งเดียว → ไม่บันทึก ป้องกัน data loss
- **อย่า expose port 3939 โดยตรง** — ใช้ reverse proxy + TLS เสมอ

---

## แหล่งข้อมูล

| แหล่ง | URL | ใบอนุญาต |
|-------|-----|----------|
| NCSA IP/domain/hash blocklist | `opendata.ncsa.or.th` | CC0-1.0 |
| CKAN package metadata | `data.go.th` | Open Government Data |
| ThaICERT cybernews | `ncsa.gdcatalog.go.th` | สาธารณะ |
| GeoIP (offline) | geoip-lite (MaxMind GeoLite2) | CC BY-SA 4.0 |

---

## การตั้งค่าแจ้งเตือน

### LINE Notify
1. ไปที่ [notify-bot.line.me](https://notify-bot.line.me/th/) → Login
2. **My page** → **Generate token** → ตั้งชื่อ → เลือก group/1:1 → **Generate**
3. คัดลอก token → ใส่ใน `.env`:
   ```
   LINE_NOTIFY_TOKEN=your_token_here
   ```
4. ระบบจะส่งข้อความเมื่อ: sync มีการเปลี่ยนแปลง หรือ watch list hit

### Email (SMTP)
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@gmail.com
SMTP_PASS=app_password_here    # ใช้ App Password ไม่ใช่ password จริง
SMTP_FROM=your@gmail.com
SMTP_TO=alert@yourcompany.com
```
> **Gmail:** ต้องเปิด 2FA แล้วสร้าง App Password ที่ myaccount.google.com/apppasswords

### Webhook (Discord/Slack/Custom)
```env
WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy
WEBHOOK_SECRET=random_secret_here    # optional: HMAC signing
```
ตรวจสอบ signature ฝั่ง receiver:
```js
const sig = req.headers['x-signature']; // "sha256=<hex>"
const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
if (sig !== expected) return res.status(401).end();
```

---

## Integration Guide

### iptables (Linux firewall)
```bash
# Download + apply blocklist
curl http://localhost:3939/export/iptables -o ncsa-block.sh
chmod +x ncsa-block.sh && sudo bash ncsa-block.sh

# หรือ auto-update ทุกวันผ่าน cron:
0 7 * * * curl -s http://localhost:3939/export/iptables | bash
```

### dnsmasq (DNS blocking)
```bash
# เพิ่มใน /etc/dnsmasq.d/ncsa-blacklist.conf
curl http://localhost:3939/export/dnsmasq -o /etc/dnsmasq.d/ncsa-blacklist.conf
systemctl reload dnsmasq
```

### Wazuh SIEM (hash lookup)
```bash
# ดาวน์โหลด CDB list
curl http://localhost:3939/export/wazuh -o /var/ossec/etc/lists/ncsa-blacklist

# ossec.conf — เพิ่ม rule:
# <list>etc/lists/ncsa-blacklist</list>
```

### Python / curl
```python
import requests

# ตรวจสอบ IP เดียว
r = requests.get('http://localhost:3939/check/auto/1.2.3.4')
print(r.json())  # {type, blacklisted, risk, geo, rdns}

# Bulk check
r = requests.post('http://localhost:3939/check/bulk', json={
    'type': 'auto',
    'values': ['1.2.3.4', 'evil.com', 'abc...hash...']
})
hits = [x for x in r.json()['results'] if x['blacklisted']]
```

---

## Troubleshooting

### ข้อมูลว่าง (0 IPs)
```bash
# รัน fetch เองทันที
docker compose exec ncsa-blacklist node src/fetch.js

# ดู log
docker compose logs ncsa-blacklist-sync
```

### Sync ไม่ทำงาน
- ตรวจสอบว่า container `ncsa-blacklist-sync` ยัง run อยู่: `docker compose ps`
- ดู log: `docker compose logs ncsa-blacklist-sync --tail=50`
- รัน fetch เองด้วยมือเพื่อทดสอบ

### GeoIP ไม่มีข้อมูล
- `geoip-lite` ใช้ฐานข้อมูล MaxMind ฟรี → IP บางส่วนไม่มีข้อมูล AS
- อัปเดต database: `docker compose exec ncsa-blacklist node -e "require('geoip-lite').reloadDataSync()"`

### LINE Notify ไม่ส่ง
- ตรวจสอบ token ถูกต้อง: `curl -H "Authorization: Bearer <token>" https://notify-api.line.me/api/status`
- Token expire หรือถูก revoke → สร้างใหม่

### Port 3939 ถูก block
```bash
# เปลี่ยน port ใน .env
PORT=8080
docker compose up -d
```

### Disk space (DATA_DIR)
- `history.jsonl` จำกัด 1,000 บรรทัด (auto-trim)
- `recent.jsonl` จำกัด 120 รายการ (auto-trim)
- feed JSON (~10-50MB ต่อไฟล์)

---

## Backup & Recovery

ข้อมูลทั้งหมดอยู่ใน `DATA_DIR` (Docker volume: `ncsa-data` หรือ `./data`):

```bash
# Backup (Docker)
docker run --rm -v ncsa-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/ncsa-backup-$(date +%Y%m%d).tar.gz /data

# Restore
docker run --rm -v ncsa-data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/ncsa-backup-20260626.tar.gz -C /
```

ไฟล์สำคัญที่ควร backup: `watchlist.json` (รายการที่ติดตาม) — ที่เหลือสร้างใหม่ได้จาก `npm run fetch`

---

## FAQ

**Q: ข้อมูลอัปเดตบ่อยแค่ไหน?**
A: Sync ทุก 6 ชั่วโมง upstream NCSA อัปเดตรายวัน

**Q: รองรับ IPv6 ไหม?**
A: ใช่ — `/check/auto`, `/check/bulk`, `/scan` ทุกตัวรองรับ IPv6

**Q: ใช้ฟรีไหม? มี limit ไหม?**
A: ฟรีทั้งหมด ข้อมูล NCSA เป็น CC0 open data ไม่มี API key ไม่มี rate limit จาก upstream

**Q: ติดตั้งบน Raspberry Pi / ARM ได้ไหม?**
A: ได้ — Docker image รองรับ linux/arm64 และ linux/arm/v7

**Q: ขยาย feed เพิ่มเองได้ไหม?**
A: ได้ — ใช้ `EXTRA_FEEDS=mylist:https://your-feed.com/blocklist.json` (format เดียวกับ NCSA)

**Q: watch list แจ้งเตือนยังไง?**
A: ทุกครั้งที่ sync — ถ้า value ใน watch list ถูกเพิ่มเข้า blacklist → ส่ง webhook/LINE/email ทันที

---

## ใบอนุญาต

Code: **MIT** — ดู `LICENSE`

ข้อมูล NCSA: **CC0 / Open Data Common** — [ดูชุดข้อมูล](https://data.go.th/dataset/gdpublish-th-ncsa-blacklist)
