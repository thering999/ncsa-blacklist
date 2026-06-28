# 🛡 NCSA Blacklist SOC Dashboard

ระบบ Dashboard สำหรับ Security Operations Center (SOC) ของหน่วยงานภาครัฐและเอกชนไทย  
รองรับทุกบริบท: โรงพยาบาล · สสจ. · อบจ./อบต. · โรงเรียน · มหาวิทยาลัย · กระทรวง · เอกชน

[![Docker](https://img.shields.io/badge/Docker-ready-blue)](https://hub.docker.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Thai](https://img.shields.io/badge/ภาษา-ไทย-red)](README.md)

---

## 📋 สารบัญ

1. [ฟีเจอร์หลัก](#ฟีเจอร์หลัก)
2. [ความต้องการของระบบ](#ความต้องการของระบบ)
3. [การติดตั้งด้วย Docker (แนะนำ)](#การติดตั้งด้วย-docker-แนะนำ)
4. [การตั้งค่าเบื้องต้น](#การตั้งค่าเบื้องต้น)
5. [การตั้งค่าสำหรับหน่วยงาน](#การตั้งค่าสำหรับหน่วยงาน)
6. [ฟีเจอร์แต่ละส่วน](#ฟีเจอร์แต่ละส่วน)
7. [การเชื่อมต่อระบบภายนอก](#การเชื่อมต่อระบบภายนอก)
8. [การอัปเดตระบบ](#การอัปเดตระบบ)
9. [คำถามที่พบบ่อย](#คำถามที่พบบ่อย)
10. [การพัฒนาต่อ](#การพัฒนาต่อ)

---

## ฟีเจอร์หลัก

### 🔍 Threat Intelligence
- ค้นหา IP / Domain / Hash จาก NCSA Blacklist feeds (อัปเดตทุกวัน, CC0)
- Bulk check หลายรายการพร้อมกัน (สูงสุด 10,000 รายการ)
- CIDR scan ตรวจทั้ง subnet (สูงสุด /16)
- Watch list + Allow list พร้อม auto-alert ผ่าน LINE/Email/Webhook
- OSINT links: VirusTotal, Shodan, AbuseIPDB, Greynoise, URLScan
- GeoIP (ประเทศ/เมือง/ASN), rDNS, Risk Score 0–100
- ASN Analysis, Network /24 breakdown, ThaiCERT news feed

### 📊 SOC Dashboard
- Security Score รวม (CTAM+/KPI/Vuln weighted)
- CTAM+ 17 เกณฑ์ (filter อัตโนมัติตามประเภทหน่วยงาน)
- MOPH 100-Point Cybersecurity Standard FY2569 (10 domains)
- MOPH Cybersecurity KPI v2.1 (ขั้นต่ำ 7 + ขั้นสูง 8 เกณฑ์)
- SOC Metrics: MTTD/MTTR, Alerts Today, New IPs 24h, Feed Age
- Threat Intel Summary, Vulnerability Breakdown, Security Calendar
- NIST CSF 5-pillar assessment, Compliance Gap Analysis
- Hourly threat chart, Executive Print Report (PDF-ready)

### 🚨 Incident Response
- IR Playbook: Ransomware / Web Attack / PDPA Breach / DDoS / Malware
- Incident Log & Timeline (CRUD, status workflow)
- BCP/Drill Tracker + DRP Tracker (RTO/RPO per system)
- CSIRT Contact Directory (ThaiCERT/NCSA/MOPH pre-filled)
- Ransomware Readiness Score (12-point checklist, weighted)

### 🏗 Assets & Compliance
- Asset Inventory (Hardware/Software/Cloud), SSL Certificate Monitor
- Vulnerability Tracker + CVE live lookup (NVD API)
- Staff Training + Security Awareness Quiz (10 ข้อ, ≥70% pass)
- Licensed Software Tracker (expiry alerts ≤90 วัน)
- Policy Document Register (CTAM+ ข้อ 17, auto-complete)
- PDPA Data Flow Register (มาตรา 39, DPIA tracking)
- Phishing Simulation Tracker, Pentest Tracker
- Vendor/Third-party Risk Register
- Zero Trust Assessment (NIST SP 800-207, 6 pillars)
- Risk Assessment Matrix 5×5 + Risk Register CRUD

### 🔗 Integrations
- Wazuh Live REST API (alerts real-time, color-coded by level)
- MISP Live Event Viewer (threat level, IOC count, org)
- Firewall config: FortiGate / MikroTik / Cisco / pfSense / OPNsense
- Email Security Checker (SPF/DKIM/DMARC via Google DNS)
- IOC Sharing: ThaiCERT email template + STIX-2.1 JSON
- LINE Notify integration, Geofence Country Block
- Sigma Rules Library (8 rules, MITRE-tagged, Thai health sector)
- Threat Hunt IOC Pivot (Elastic/Splunk/Windows Event queries)
- Dashboard Export/Import (JSON full backup/restore)
- Prometheus metrics (`/metrics`), Webhook, Email notifications

---

## ความต้องการของระบบ

| รายการ | ขั้นต่ำ | แนะนำ |
|--------|---------|--------|
| CPU | 1 core | 2 cores |
| RAM | 512 MB | 1 GB |
| Disk | 2 GB | 10 GB |
| OS | Linux/Windows/macOS | Ubuntu 22.04 LTS |
| Docker | 20.10+ | 24.x |
| Docker Compose | 2.x | 2.x |
| Network | LAN (ไม่ต้อง expose public) | LAN + VPN |

> ไม่ต้องการ database ภายนอก — ข้อมูล feed เก็บใน JSON files บน Docker volume

---

## การติดตั้งด้วย Docker (แนะนำ)

### ขั้นตอนที่ 1: Clone หรือ Download

```bash
# Clone จาก GitHub
git clone https://github.com/YOUR_ORG/ncsa-blacklist.git
cd ncsa-blacklist

# หรือ Download ZIP แล้วแตกไฟล์
wget https://github.com/YOUR_ORG/ncsa-blacklist/archive/main.zip
unzip main.zip && cd ncsa-blacklist-main
```

### ขั้นตอนที่ 2: สร้างไฟล์ .env

```bash
# Linux/macOS
cp .env.example .env
nano .env

# Windows
copy .env.example .env
notepad .env
```

ตัวอย่างการตั้งค่าขั้นต่ำ:

```env
PORT=3939
DATA_DIR=/data
ADMIN_TOKEN=your-secret-token-change-this
```

ตัวอย่างการตั้งค่าครบ:

```env
PORT=3939
DATA_DIR=/data
ADMIN_TOKEN=your-secret-admin-token-here

# อีเมลแจ้งเตือน
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@email.com
SMTP_PASS=your-app-password
SMTP_FROM=your@email.com
SMTP_TO=security@your-org.go.th

# LINE Notify
LINE_NOTIFY_TOKEN=your-line-notify-token

# Rate limit
RATE_LIMIT=60
```

### ขั้นตอนที่ 3: รัน Docker

```bash
# Build และ start (ครั้งแรก)
docker-compose up -d --build

# ตรวจสอบสถานะ
docker-compose ps

# ดู logs แบบ real-time
docker-compose logs -f ncsa-blacklist

# หยุด
docker-compose down
```

### ขั้นตอนที่ 4: เปิด Dashboard

เปิด browser: **http://localhost:3939**  
หรือจากเครื่องอื่นใน LAN: `http://[IP-Server]:3939`

> ครั้งแรกที่เปิด จะมี **Setup Wizard** ให้ตั้งค่าหน่วยงาน

---

## การตั้งค่าเบื้องต้น

### Setup Wizard (ครั้งแรก)

เมื่อเปิด Dashboard ครั้งแรก Wizard จะขึ้นมาอัตโนมัติ 3 ขั้นตอน:

**ขั้นตอนที่ 1 — ข้อมูลองค์กร**

| ประเภท | ค่า | ตัวอย่าง |
|--------|-----|----------|
| โรงพยาบาล | `hospital` | รพ.มุกดาหาร, รพ.สรรพสิทธิ์ |
| สำนักงานสาธารณสุขจังหวัด | `provincial` | สสจ.มุกดาหาร, สสจ.อุบล |
| สำนักงานสาธารณสุขอำเภอ | `district` | สสอ.เมืองมุกดาหาร |
| อบจ./อบต./เทศบาล | `localGov` | อบจ.มุกดาหาร |
| โรงเรียน/สถาบัน | `school` | โรงเรียนมุกดาหาร |
| มหาวิทยาลัย | `university` | ม.มหาสารคาม |
| กระทรวง/กรม | `ministry` | กรมควบคุมโรค |
| บริษัทเอกชน | `private` | บริษัท ABC จำกัด |
| NGO | `ngo` | มูลนิธิ... |
| รัฐวิสาหกิจ | `stateEnterprise` | การไฟฟ้า, ปตท. |

**ขั้นตอนที่ 2 — ระบบ Security**
- **SIEM**: Wazuh / Splunk / ELK / Microsoft Sentinel / IBM QRadar / อื่นๆ
- **EDR**: CrowdStrike / SentinelOne / Microsoft Defender / Trend Vision One / อื่นๆ  
- **Firewall**: FortiGate / MikroTik / Cisco / pfSense / OPNsense / อื่นๆ

**ขั้นตอนที่ 3 — การเชื่อมต่อ (Optional)**
- Wazuh API URL: `https://wazuh.internal:55000`
- MISP URL: `https://misp.internal`
- LINE Notify Token

> **หมายเหตุ:** ทุกการตั้งค่าเก็บใน `localStorage` ของ browser เท่านั้น — ไม่ส่งออกไปที่ใด

### เปลี่ยนการตั้งค่าในภายหลัง

คลิก **⚙ Settings** (มุมบนขวา) → แก้ไขได้ทุกรายการ

---

## การตั้งค่าสำหรับหน่วยงาน

### Network Zone Presets อัตโนมัติ

เมื่อเลือกประเภทหน่วยงาน ระบบตั้งค่า zone อัตโนมัติ:

| ประเภทหน่วยงาน | Network Zones |
|---------------|--------------|
| โรงพยาบาล | HIS/EMR Zone · DMZ · Admin Zone · IoMT Zone · Backup Zone |
| สสจ./สสอ. | Internal Network · DMZ · Admin Zone · Public Wi-Fi |
| มหาวิทยาลัย | Student · Staff · Research · DMZ · Admin · Data Center |
| โรงเรียน | Student Zone · Teacher/Staff Zone · Admin Zone · Wi-Fi Zone |
| อบจ./อบต. | Internal Zone · Public Services Zone · Admin Zone |
| กระทรวง | Internal · DMZ · Secret Zone · Admin · DR Zone |

### CTAM+ Filter อัตโนมัติ

CTAM+ 17 เกณฑ์จะ filter ตามประเภทหน่วยงาน:

| เกณฑ์ | แสดงสำหรับ |
|-------|-----------|
| WAF (ข้อ 8) | รพ./สสจ./มหาวิทยาลัย/กระทรวง/รัฐวิสาหกิจ |
| SIEM (ข้อ 10) | รพ./สสจ./สสอ./มหาวิทยาลัย/กระทรวง/รัฐวิสาหกิจ |
| เกณฑ์อื่น (15 ข้อ) | ทุกหน่วยงาน |

### CTAM+ ข้อ 17 — Policy Register

ระบบ auto-complete CTAM+ ข้อ 17 เมื่อตั้ง 5 policies ครบ:
1. Privacy Policy (นโยบายความเป็นส่วนตัว)
2. Privacy Notice (ประกาศความเป็นส่วนตัว)
3. Web Security Policy
4. Cybersecurity Policy
5. Cybersecurity Practices

ไปที่ **Assets → Policy Register** → ตั้งสถานะ `อนุมัติแล้ว` → ระบบ mark ข้อ 17 ให้อัตโนมัติ

---

## ฟีเจอร์แต่ละส่วน

### 🔍 ค้นหา IP / Domain / Hash
1. พิมพ์ค่าในช่องค้นหา (auto-detect ประเภท)
2. กด Enter หรือคลิก **ค้นหา**
3. ผลลัพธ์: สถานะ Blacklist · ประเทศ · ASN · Risk Score · rDNS
4. คลิก **OSINT** → เปิด VT/Shodan/AbuseIPDB พร้อมกัน

### 📊 CTAM+ 17 เกณฑ์
1. แท็บ **SOC** → CTAM+
2. คลิก checkbox แต่ละเกณฑ์เมื่อผ่าน
3. ใส่ Note/หลักฐาน
4. ระบบคำนวณ Compliance Gap + Security Score อัตโนมัติ

### 💯 MOPH 100-Point Standard
1. แท็บ **SOC** → MOPH 100-Point
2. คลิก domain (Governance/Asset/Access/...) เพื่อขยาย
3. ติ๊ก checkbox ตามที่ผ่านจริง
4. คะแนนรวมแสดงที่มุมขวา

### 🚨 Incident Response
1. แท็บ **IRP** → เลือก Playbook
2. ทำตามขั้นตอน: Identify → Contain → Eradicate → Recover → Lessons
3. บันทึก Incident ใน Incident Log
4. ดูสถานะ Open/In-Progress/Closed

### 📧 Email Security Checker
1. **Integrations** → Email Security
2. ใส่ domain เช่น `moph.go.th`
3. ใส่ DKIM selector (ถ้ารู้: `google`, `default`, `s1`, ฯลฯ)
4. คลิก **ตรวจสอบ** → ผล SPF/DKIM/DMARC พร้อมคำแนะนำ

### 🔴 Wazuh Live Alerts
1. **Integrations** → Wazuh tab
2. ใส่ URL: `https://[wazuh-ip]:55000`
3. Username: `wazuh-wui`, Password: (ดูจาก installer)
4. คลิก **Connect** → alerts แสดง real-time สี-coded ตาม level

### 🕸 MISP Event Viewer
1. **Integrations** → MISP tab
2. ใส่ URL + API Key (ดูจาก MISP → Administration → Auth Keys)
3. คลิก **Load Events** → threat level color-coded

### 📡 IOC Sharing
1. **Integrations** → IOC Sharing
2. เลือกประเภท + ความน่าเชื่อถือ
3. ใส่ IOC values (ทีละบรรทัด)
4. **สร้าง Report** / **Copy Email Template** / **Copy STIX-2.1 JSON**

### 📄 Executive Report
1. แท็บ **SOC** → Executive Report
2. คลิก **Preview** → ดูสรุปก่อน
3. คลิก **พิมพ์/Export PDF** → เปิด print dialog
4. บันทึกเป็น PDF สำหรับผู้บริหาร

---

## การเชื่อมต่อระบบภายนอก

### Wazuh REST API

```
URL:  https://[WAZUH-IP]:55000
User: wazuh-wui
Pass: ดูจาก /var/ossec/etc/passwords
      หรือ: cat /var/ossec/etc/passwords | grep wazuh-wui
```

หาก Wazuh อยู่หลัง self-signed cert:
```bash
# เพิ่ม CORS header บน Wazuh (wazuh-manager)
# /etc/wazuh-dashboard/opensearch_dashboards.yml
# เพิ่ม: server.cors: true
```

### MISP

```
URL:     https://[MISP-IP]
API Key: MISP UI → Administration → Auth Keys → Add Auth Key
```

### LINE Notify

1. เปิด https://notify-bot.line.me/my/
2. คลิก **Generate token** → เลือก Group หรือ 1-on-1
3. Copy token → ใส่ใน `.env` หรือ Settings ใน dashboard

### Email (Gmail App Password)

1. Gmail → Account → Security → App passwords
2. สร้าง App password สำหรับ "Mail"
3. ใส่ใน `SMTP_PASS` ใน `.env`

---

## การอัปเดตระบบ

```bash
# ดึง code ใหม่จาก GitHub
git pull origin main

# Rebuild image + restart (ข้อมูลไม่หาย)
docker-compose up -d --build

# ตรวจสอบ
docker-compose ps
```

> **ข้อมูลไม่หาย** — feed data เก็บใน Docker volume `ncsa-data` · config/CTAM/Risk เก็บใน browser localStorage

### Force sync feed ทันที

```bash
curl -X POST http://localhost:3939/admin/sync \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

---

## คำถามที่พบบ่อย

**Q: ข้อมูล CTAM+/Risk/Incident หายหลัง rebuild Docker ไหม?**  
A: ไม่หาย — เก็บใน browser localStorage · feed data เก็บใน Docker volume แยกต่างหาก

**Q: ใช้ได้กี่คนพร้อมกัน?**  
A: ได้ไม่จำกัด — เป็น static HTML + API server · config ของแต่ละคนแยกกัน (localStorage per browser)

**Q: รองรับ HTTPS ไหม?**  
A: ไม่มี built-in — แนะนำ nginx reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name soc.your-org.go.th;
    ssl_certificate /etc/ssl/certs/your.crt;
    ssl_certificate_key /etc/ssl/private/your.key;
    location / {
        proxy_pass http://localhost:3939;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Q: Wazuh/MISP connect ไม่ได้ (CORS error)?**  
A: เพิ่ม nginx proxy ที่ใส่ CORS header:
```nginx
add_header Access-Control-Allow-Origin "http://localhost:3939";
add_header Access-Control-Allow-Headers "Authorization, Content-Type";
```

**Q: Export ข้อมูลทั้งหมดได้ไหม?**  
A: ได้ — **Integrations → Export/Import** → Download JSON backup ครอบคลุมทุก module

**Q: เพิ่ม feed นอกเหนือ NCSA ได้ไหม?**  
A: ได้ — ใส่ `EXTRA_FEEDS=ชื่อ:url` ใน `.env` แล้ว rebuild

**Q: CTAM+ ข้อ 17 ผ่านอัตโนมัติยังไง?**  
A: Assets → Policy Register → ตั้ง 5 policies เป็น `อนุมัติแล้ว` → ระบบ mark ให้เอง

**Q: Admin Token คืออะไร ใช้ทำอะไร?**  
A: ป้องกัน endpoint `/admin/sync` และ `/reload` · ตั้งใน `.env` → `ADMIN_TOKEN=xxx` · ใส่ใน dashboard Settings เพื่อกดปุ่ม Sync

---

## การพัฒนาต่อ

### โครงสร้างไฟล์

```
ncsa-blacklist/
├── public/
│   └── index.html          # Dashboard หลัก (single-file app, ~9000+ lines)
├── src/
│   ├── server.js           # Express API server (check/bulk/recent/admin)
│   └── scheduler.js        # Feed sync scheduler (ทุกวัน 01:00)
├── Dockerfile
├── docker-compose.yml
├── .env.example            # ต้นแบบ environment variables
└── README.md
```

### API Endpoints

| Endpoint | Method | คำอธิบาย |
|----------|--------|-----------|
| `/check?q=X` | GET | ตรวจสอบ IP/domain/hash |
| `/bulk` | POST | ตรวจสอบหลายรายการ (JSON array) |
| `/recent` | GET | รายการ IOC เพิ่มล่าสุด |
| `/stats` | GET | สถิติ feed |
| `/search?q=X` | GET | ค้นหาแบบ partial match |
| `/admin/sync` | POST | sync feed ทันที (**ต้องการ Admin Token**) |
| `/healthz` | GET | health check |
| `/metrics` | GET | Prometheus metrics |

### เพิ่ม Feed ใหม่

```env
# ใน .env
EXTRA_FEEDS=mylist:https://your-feed.go.th/blacklist.json,another:https://...
```

Format JSON feed:
```json
{
  "type": "ip",
  "entries": ["1.2.3.4", "5.6.7.8"],
  "updated": "2025-01-01T00:00:00Z"
}
```

### Custom Sigma Rules

เพิ่ม rule ใน `SIGMA_RULES` array ใน `public/index.html`:

```js
{
  id: 'SR009',
  title: 'ชื่อ Rule',
  tags: ['ransomware'],   // ransomware|lateral|exfil|phishing|webshell|privesc
  level: 'high',          // critical|high|medium|low
  mitre: 'T1234',
  desc: 'คำอธิบาย',
  sigma: `title: ...`     // YAML Sigma rule
}
```

---

## 🔒 Security Notes

- **อย่า expose port 3939** บน public internet โดยตรง
- ตั้งค่า `ADMIN_TOKEN` เสมอก่อนใช้งานจริง (สร้าง: `openssl rand -hex 32`)
- ตั้งค่า `ADMIN_ALLOWED_IPS` จำกัด IP ที่เข้า `/admin/*`
- ใช้ nginx reverse proxy + SSL certificate สำหรับ production
- ข้อมูล Wazuh/MISP credentials ไม่ถูกเก็บใน server — ใส่ใน browser เท่านั้น

---

## 📞 ติดต่อ / รายงานปัญหา

- **GitHub Issues**: สร้าง issue ผ่าน GitHub
- **ThaiCERT**: thaicert@etda.or.th | โทร 1212
- **NCSA**: ncsa@mict.go.th

---

*พัฒนาบน NCSA Blacklist Open Data (CC0) · MIT License*
