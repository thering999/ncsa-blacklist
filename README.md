# 🛡 NCSA Blacklist SOC Dashboard

ระบบ Dashboard สำหรับ Security Operations Center (SOC) ของหน่วยงานภาครัฐและเอกชนไทย  
รองรับทุกบริบท: โรงพยาบาล · สสจ. · อบจ./อบต. · โรงเรียน · มหาวิทยาลัย · กระทรวง · เอกชน

> ⚠️ **หมายเหตุ**: Dashboard นี้ **ไม่ใช่ผลิตภัณฑ์อย่างเป็นทางการของ สกมช. (NCSA)**  
> เป็น Open Source ที่นำ NCSA Blacklist Feed (CC0) มาพัฒนาต่อยอด  
> โดย **กลุ่มงานสุขภาพดิจิทัล สสจ.มุกดาหาร** เพื่อใช้งานในหน่วยงานสาธารณสุขไทย

[![Docker](https://img.shields.io/badge/Docker-ready-blue)](https://hub.docker.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Thai](https://img.shields.io/badge/ภาษา-ไทย-red)](README.md)

---

## 📋 สารบัญ

1. [ภาพรวมระบบ](#ภาพรวมระบบ)
2. [คุณสมบัติทั้งหมด](#คุณสมบัติทั้งหมด)
3. [ความต้องการของระบบ](#ความต้องการของระบบ)
4. [การติดตั้งด้วย Docker บน Linux (แนะนำ)](#การติดตั้งด้วย-docker-บน-linux-แนะนำ)
5. [การติดตั้งบน Windows](#การติดตั้งบน-windows)
6. [การตั้งค่าครั้งแรก (Setup Wizard)](#การตั้งค่าครั้งแรก-setup-wizard)
7. [คู่มือการใช้งานแต่ละโมดูล](#คู่มือการใช้งานแต่ละโมดูล)
8. [การเชื่อมต่อระบบภายนอก](#การเชื่อมต่อระบบภายนอก)
9. [Production Deployment (Linux Server)](#-production-deployment-linux-server)
10. [การสำรองและกู้คืนข้อมูล](#การสำรองและกู้คืนข้อมูล)
11. [การอัปเดตระบบ](#การอัปเดตระบบ)
12. [แก้ปัญหาที่พบบ่อย](#แก้ปัญหาที่พบบ่อย)
13. [API Reference](#api-reference)
14. [การพัฒนาต่อ](#การพัฒนาต่อ)
15. [เกี่ยวกับโครงการ](#เกี่ยวกับโครงการ)

---

## ภาพรวมระบบ

NCSA Blacklist SOC Dashboard คือเครื่องมือ Cybersecurity แบบครบวงจรสำหรับหน่วยงานไทย รวมทุกฟังก์ชันที่ SOC ต้องการไว้ในหน้าเดียว — ตั้งแต่การตรวจสอบ IP/Domain ด้วย Threat Intelligence จนถึงการบริหารจัดการ Incident Response และการออกรายงานให้ผู้บริหาร

**จุดเด่นของระบบ:**
- ติดตั้งง่ายด้วย Docker คำสั่งเดียว ไม่ต้องการ database ภายนอก
- รองรับหน่วยงานทุกประเภท พร้อม preset อัตโนมัติตามบริบท
- ข้อมูล Feed อัปเดตจาก NCSA Blacklist ทุกวัน (ฟรี, CC0)
- ทำงานบน LAN ไม่จำเป็นต้องเชื่อมต่ออินเทอร์เน็ตสาธารณะ
- Single HTML file — ไม่มี framework ซับซ้อน โหลดเร็ว

---

## คุณสมบัติทั้งหมด

### 🔍 Threat Intelligence — ตรวจสอบภัยคุกคาม

- **ค้นหา IP / Domain / File Hash** แบบ Real-time จาก NCSA Blacklist Feed
  - Auto-detect ประเภท: IPv4, IPv6, domain, MD5/SHA1/SHA256
  - แสดง GeoIP (ประเทศ, เมือง, ASN), rDNS Lookup
  - Risk Score 0–100 พร้อมการจัดระดับ (Critical/High/Medium/Low)
  - OSINT links: VirusTotal, Shodan, AbuseIPDB, Greynoise, URLScan เปิดได้ทันที
- **Bulk Check** ตรวจสอบหลายรายการพร้อมกัน สูงสุด 10,000 รายการ
  - วาง IP/domain ทีละบรรทัด หรืออัปโหลดไฟล์ `.txt`
  - ผลลัพธ์ Export เป็น CSV ได้ทันที
- **CIDR Scan** ตรวจทั้ง Subnet สูงสุด /16 (65,536 IP)
- **Watch List** — ติดตาม IP/Domain เฉพาะที่ต้องการ
  - แจ้งเตือนอัตโนมัติผ่าน LINE / Email / Webhook เมื่อพบในฐาน
- **Allow List** — ยกเว้น False Positive ออกจากการแจ้งเตือน
- **ASN Analysis** — วิเคราะห์ AS Organization
- **Network /24 Breakdown** — breakdown subnet ที่พบบ่อย
- **ThaiCERT News Feed** — ข่าวสารความปลอดภัยไทยล่าสุด

---

### 📊 SOC Dashboard — แผงควบคุม SOC

- **Security Score รวม** คำนวณถ่วงน้ำหนักจาก CTAM+, KPI และ Vulnerability
- **CTAM+ 17 เกณฑ์** (Critical Technology Asset Management Plus)
  - Filter อัตโนมัติตามประเภทหน่วยงาน (เช่น WAF/SIEM แสดงเฉพาะ รพ./สสจ./กระทรวง)
  - บันทึก Note/หลักฐานต่อเกณฑ์ได้
  - คำนวณ Compliance Gap + แนะนำสิ่งที่ต้องแก้ไข
- **MOPH 100-Point Cybersecurity Standard FY2569** — มาตรฐาน 100 คะแนน กระทรวงสาธารณสุข
  - 10 โดเมน: Governance, Asset, Access, Data, Incident, Recovery, Supply Chain, Awareness, Physical, Audit
  - คะแนนรวมแสดง Real-time
- **MOPH Cybersecurity KPI v2.1** — ตัวชี้วัดขั้นต่ำ 7 เกณฑ์ + ขั้นสูง 8 เกณฑ์
- **SOC Metrics Live:**
  - MTTD (Mean Time to Detect)
  - MTTR (Mean Time to Respond)
  - Alerts Today / New IPs 24h / Feed Age
- **NIST CSF 5-pillar Assessment** — Identify / Protect / Detect / Respond / Recover
- **Compliance Gap Analysis** — แสดง gap ระหว่างสถานะปัจจุบันกับเป้าหมาย
- **Hourly Threat Chart** — กราฟ threat ตลอด 24 ชั่วโมง
- **Security Calendar** — ปฏิทินงาน Cybersecurity (drill, audit, review)
- **Executive Print Report** — รายงานสรุปสำหรับผู้บริหาร พิมพ์/Export PDF ได้ทันที

---

### 🚨 Incident Response — การรับมือเหตุการณ์

- **IR Playbook** แบบ Step-by-step สำหรับ 5 สถานการณ์:
  - Ransomware Attack
  - Web Application Attack / Defacement
  - PDPA Data Breach (ละเมิดข้อมูลส่วนบุคคล)
  - DDoS Attack
  - Malware / APT Infection
- **Incident Log & Timeline** — บันทึก Incident แบบ CRUD
  - สถานะ Workflow: Open → In-Progress → Contained → Eradicated → Closed
  - Timeline แสดงเหตุการณ์ตามลำดับเวลา
- **BCP Tracker** (Business Continuity Plan) — ติดตาม drill/test แผน BCP
- **DRP Tracker** (Disaster Recovery Plan) — RTO/RPO tracking ต่อระบบ
- **CSIRT Contact Directory** — รายชื่อติดต่อฉุกเฉิน ThaiCERT/NCSA/MOPH พร้อมใช้
- **Ransomware Readiness Score** — checklist 12 ข้อ ถ่วงน้ำหนัก ประเมินความพร้อมรับ Ransomware

---

### 🏗 Assets & Compliance — สินทรัพย์และการปฏิบัติตามกฎหมาย

- **Asset Inventory** — รายการทรัพย์สินดิจิทัล
  - Hardware: เซิร์ฟเวอร์, เครือข่าย, อุปกรณ์ end-user
  - Software: ระบบปฏิบัติการ, แอปพลิเคชัน, Database
  - Cloud: Virtual Machine, Storage, SaaS
- **SSL Certificate Monitor** — ติดตาม SSL ของทุก domain พร้อมแจ้งเตือนใกล้หมดอายุ
- **Vulnerability Tracker** — บันทึกช่องโหว่ตาม CVE
  - เชื่อมต่อ NVD API — ดึงรายละเอียด CVE แบบ Live
  - สถานะ: Open / Mitigated / Accepted Risk
- **Staff Training Tracker** — บันทึกการอบรม Cybersecurity ของบุคลากร
- **Security Awareness Quiz** — แบบทดสอบ 10 ข้อ เกณฑ์ผ่าน ≥70%
- **Licensed Software Tracker** — ติดตามใบอนุญาต Software
  - แจ้งเตือนอัตโนมัติเมื่อใกล้หมดอายุ ≤90 วัน
- **Policy Document Register** — ทะเบียนนโยบาย Cybersecurity (รองรับ CTAM+ ข้อ 17)
  - Auto-complete CTAM+ ข้อ 17 เมื่อตั้ง 5 policies ครบ
- **PDPA Data Flow Register** — ทะเบียนการไหลของข้อมูลส่วนบุคคล (มาตรา 39 PDPA)
  - DPIA (Data Protection Impact Assessment) tracking
- **Phishing Simulation Tracker** — บันทึกผลการทดสอบ Phishing ของบุคลากร
- **Pentest Tracker** — บันทึกผลการทดสอบเจาะระบบ (scope, findings, remediation)
- **Vendor / Third-party Risk Register** — ประเมินความเสี่ยงผู้ให้บริการภายนอก
- **Zero Trust Assessment** — ประเมินตาม NIST SP 800-207 ทั้ง 6 pillars
- **Risk Assessment Matrix 5×5** — เมทริกซ์ประเมินความเสี่ยง
- **Risk Register CRUD** — บันทึก/แก้ไข/ลบ รายการความเสี่ยง พร้อม risk level

---

### 🔗 Integrations — การเชื่อมต่อระบบภายนอก

- **Wazuh Live REST API** — ดู alert real-time, color-coded ตาม severity level
- **MISP Live Event Viewer** — ดู Threat Intelligence event, threat level, IOC count
- **Firewall Config Templates** — FortiGate / MikroTik / Cisco / pfSense / OPNsense
- **Email Security Checker** — ตรวจ SPF / DKIM / DMARC ผ่าน Google DNS
- **IOC Sharing Module:**
  - สร้าง Email Template ส่งให้ ThaiCERT
  - Export STIX-2.1 JSON format มาตรฐานสากล
- **LINE Notify** — ส่งการแจ้งเตือนเข้า LINE Group/1-on-1
- **Geofence Country Block** — แนะนำ Block list ตามประเทศแหล่งที่มาภัยคุกคาม
- **Sigma Rules Library** — 8 detection rules, MITRE ATT&CK tagged, สำหรับ Health Sector ไทย
- **Threat Hunt IOC Pivot** — สร้าง query พร้อมใช้สำหรับ Elastic / Splunk / Windows Event Log
- **Dashboard Export/Import** — JSON backup/restore ครอบคลุมทุก module
- **Prometheus Metrics** (`/metrics`) — ส่งตัวชี้วัดสู่ Monitoring Stack
- **Webhook** — แจ้งเตือน custom ไปยัง endpoint ใดก็ได้
- **Email Notifications** — ผ่าน SMTP (รองรับ Gmail App Password)

---

### 🏥 Cloud CSPM-Lite — Cloud Security (โมดูลเสริม)

- ประเมิน Cloud Security Posture ตาม CIS Benchmark 20 controls
- รองรับ: AWS / Azure / GCP / OCI / Alibaba Cloud
- แสดง Pass/Fail/Manual status ต่อ control
- คำนวณ Cloud Security Score

---

### 🔌 OT/IoMT Device Tracker — อุปกรณ์ทางการแพทย์และอุตสาหกรรม

- บันทึก Medical Device และ IoMT (Internet of Medical Things)
- ติดตาม OS, Firmware, Network Zone ของแต่ละอุปกรณ์
- แจ้งเตือน end-of-support และ patch status

---

### 📰 SOC Daily Brief — สรุปประจำวัน

- สร้างรายงานสรุปประจำวันอัตโนมัติสำหรับ SOC Analyst
- รวม: Alerts สรุป, Feed update, Incidents ล่าสุด, แนวโน้มภัยคุกคาม
- Export เป็น PDF / Copy เป็น Text

---

## ความต้องการของระบบ

| รายการ | ขั้นต่ำ | แนะนำ |
|--------|---------|--------|
| CPU | 1 core | 2 cores |
| RAM | 512 MB | 1 GB |
| Disk | 2 GB | 10 GB |
| OS | Linux / Windows / macOS | Ubuntu 22.04 LTS |
| Docker | 20.10+ | 24.x |
| Docker Compose | 2.x | 2.x |
| Network | LAN | LAN + VPN |
| Browser | Chrome 90+ / Firefox 90+ / Edge 90+ | Chrome ล่าสุด |

> ไม่ต้องการ database ภายนอก — feed data เก็บใน JSON บน Docker volume · config เก็บใน browser localStorage

---

## การติดตั้งด้วย Docker บน Linux (แนะนำ)

### ขั้นตอนที่ 1: ติดตั้ง Docker (ถ้ายังไม่มี)

```bash
# Ubuntu / Debian
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# ตรวจสอบ
docker --version
docker compose version
```

### ขั้นตอนที่ 2: Clone โปรแกรม

```bash
git clone https://github.com/thering999/ncsa-blacklist.git
cd ncsa-blacklist
```

> ถ้าไม่มี git: `wget https://github.com/thering999/ncsa-blacklist/archive/main.zip && unzip main.zip && cd ncsa-blacklist-main`

### ขั้นตอนที่ 3: ตั้งค่า Environment

```bash
cp .env.example .env
nano .env
```

ตัวอย่างการตั้งค่าขั้นต่ำ (ทำงานได้ทันที):

```env
PORT=3939
DATA_DIR=/data
ADMIN_TOKEN=your-secret-token-change-this
```

ตัวอย่างการตั้งค่าครบสมบูรณ์:

```env
# Server
PORT=3939
DATA_DIR=/data
ADMIN_TOKEN=your-secret-admin-token-here   # สร้างด้วย: openssl rand -hex 32
ADMIN_ALLOWED_IPS=10.0.0.0/8,192.168.0.0/16  # จำกัด IP เข้า /admin/*

# อีเมลแจ้งเตือน (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@gmail.com
SMTP_PASS=your-16-char-app-password        # Gmail App Password (ไม่ใช่ password ปกติ)
SMTP_FROM=your@gmail.com
SMTP_TO=security@your-org.go.th

# LINE Notify (Optional)
LINE_NOTIFY_TOKEN=your-line-notify-token

# Rate limiting
RATE_LIMIT=60                              # requests per minute per IP

# Extra Feeds (Optional)
EXTRA_FEEDS=mylist:https://your-feed.go.th/blacklist.json
```

### ขั้นตอนที่ 4: รันระบบ

```bash
# รัน (โหมด development)
docker compose up -d --build

# ตรวจสอบสถานะ
docker compose ps

# ดู logs
docker compose logs -f ncsa-blacklist

# หยุดระบบ
docker compose down
```

ผลลัพธ์ที่ถูกต้อง:
```
[+] Running 2/2
 ✔ Container ncsa-blacklist-1       Healthy
 ✔ Container ncsa-blacklist-sync-1  Started
```

### ขั้นตอนที่ 5: เปิดใช้งาน

เปิด browser: **http://localhost:3939**  
จากเครื่องอื่นใน LAN: **http://[IP-Server]:3939**

> ครั้งแรกที่เปิด จะมี **Setup Wizard** ขึ้นอัตโนมัติ ตั้งค่าข้อมูลหน่วยงาน 3 ขั้นตอน

---

## การติดตั้งบน Windows

### ขั้นตอนที่ 1: ติดตั้ง Docker Desktop

1. ดาวน์โหลด **Docker Desktop for Windows** จาก https://www.docker.com/products/docker-desktop/
2. รันไฟล์ `Docker Desktop Installer.exe` (ต้องการสิทธิ์ Admin)
3. ติ๊ก ✅ **Use WSL 2 instead of Hyper-V** (แนะนำ)
4. คลิก **OK** รอติดตั้งเสร็จ ~5 นาที
5. **Restart เครื่อง** (บังคับ)
6. เปิด **Docker Desktop** จาก Start Menu
7. รอจน icon 🐳 ใน Taskbar ล่างขวา **หยุดหมุน** = พร้อมใช้งาน

> ⚠️ ถ้าขึ้น "WSL 2 kernel update required":  
> ดาวน์โหลด [WSL2 Linux kernel update](https://aka.ms/wsl2kernel) ติดตั้ง แล้วเปิด Docker Desktop ใหม่

### ขั้นตอนที่ 2: ดาวน์โหลดโปรแกรม

เปิด **Command Prompt** หรือ **PowerShell**:

```cmd
git clone https://github.com/thering999/ncsa-blacklist.git
cd ncsa-blacklist
```

หรือ Download ZIP: ไปที่ GitHub → กด **Code** → **Download ZIP** → แตกไฟล์

### ขั้นตอนที่ 3: สร้างไฟล์ .env

```cmd
copy .env.example .env
notepad .env
```

แก้ไข `ADMIN_TOKEN` เป็น password ที่ยากเดา (≥20 ตัวอักษร):
```env
ADMIN_TOKEN=MySecureToken2569!ChangeThis
```

### ขั้นตอนที่ 4: รัน Dashboard

**วิธีที่ 1 — ใช้ไฟล์ `start.bat` (ง่ายที่สุด):**

ดับเบิ้ลคลิก `start.bat` ที่อยู่ในโฟลเดอร์โปรแกรม

**วิธีที่ 2 — ผ่าน Command Prompt:**

```cmd
docker-compose up -d --build
```

รอประมาณ **3-5 นาที** ผลลัพธ์ที่ถูกต้อง:
```
[+] Running 2/2
 ✔ Container ncsa-blacklist-1       Healthy
 ✔ Container ncsa-blacklist-sync-1  Started
```

### ขั้นตอนที่ 5: เปิด Dashboard

เปิด Chrome/Edge/Firefox → **http://localhost:3939** 🎉

---

## การตั้งค่าครั้งแรก (Setup Wizard)

เมื่อเปิด Dashboard ครั้งแรก Wizard จะขึ้นมาอัตโนมัติ 3 ขั้นตอน:

### ขั้นตอนที่ 1 — ข้อมูลองค์กร

| ประเภทหน่วยงาน | ค่า | ตัวอย่าง |
|----------------|-----|----------|
| โรงพยาบาล | `hospital` | รพ.มุกดาหาร, รพ.สรรพสิทธิ์ |
| สำนักงานสาธารณสุขจังหวัด | `provincial` | สสจ.มุกดาหาร, สสจ.อุบลฯ |
| สำนักงานสาธารณสุขอำเภอ | `district` | สสอ.เมืองมุกดาหาร |
| อบจ./อบต./เทศบาล | `localGov` | อบจ.มุกดาหาร |
| โรงเรียน/สถาบัน | `school` | โรงเรียนมุกดาหาร |
| มหาวิทยาลัย | `university` | ม.มหาสารคาม |
| กระทรวง/กรม | `ministry` | กรมควบคุมโรค |
| บริษัทเอกชน | `private` | บริษัท ABC จำกัด |
| NGO | `ngo` | มูลนิธิ... |
| รัฐวิสาหกิจ | `stateEnterprise` | การไฟฟ้า, ปตท. |

### ขั้นตอนที่ 2 — ระบบ Security ที่ใช้งาน

- **SIEM**: Wazuh / Splunk / ELK / Microsoft Sentinel / IBM QRadar / อื่นๆ
- **EDR**: CrowdStrike / SentinelOne / Microsoft Defender / Trend Vision One / อื่นๆ
- **Firewall**: FortiGate / MikroTik / Cisco / pfSense / OPNsense / อื่นๆ

### ขั้นตอนที่ 3 — การเชื่อมต่อ (Optional)

- Wazuh API URL: `https://wazuh.internal:55000`
- MISP URL: `https://misp.internal`
- LINE Notify Token

> ทุกการตั้งค่าเก็บใน `localStorage` ของ browser เท่านั้น — ไม่ส่งออกไปที่ใด

### Network Zones อัตโนมัติตามประเภทหน่วยงาน

| ประเภทหน่วยงาน | Network Zones ที่ตั้งอัตโนมัติ |
|----------------|-------------------------------|
| โรงพยาบาล | HIS/EMR Zone · DMZ · Admin Zone · IoMT Zone · Backup Zone |
| สสจ./สสอ. | Internal Network · DMZ · Admin Zone · Public Wi-Fi |
| มหาวิทยาลัย | Student · Staff · Research · DMZ · Admin · Data Center |
| โรงเรียน | Student Zone · Teacher/Staff Zone · Admin Zone · Wi-Fi Zone |
| อบจ./อบต. | Internal Zone · Public Services Zone · Admin Zone |
| กระทรวง | Internal · DMZ · Secret Zone · Admin · DR Zone |

### เปลี่ยนการตั้งค่าในภายหลัง

คลิก **⚙ Settings** (มุมบนขวา) → แก้ไขได้ทุกรายการ

---

## คู่มือการใช้งานแต่ละโมดูล

### 🔍 ตรวจสอบ IP / Domain / Hash

1. พิมพ์ค่าในช่องค้นหาหลัก (ระบบ auto-detect ประเภทอัตโนมัติ)
2. กด **Enter** หรือคลิกปุ่ม **ค้นหา**
3. ผลลัพธ์แสดง: สถานะ Blacklist · ประเทศ/เมือง · ASN · Risk Score · rDNS
4. คลิก **OSINT** เปิด VirusTotal, Shodan, AbuseIPDB พร้อมกัน
5. คลิก **Watch** เพิ่มเข้า Watch List สำหรับติดตามต่อเนื่อง

### 📊 CTAM+ 17 เกณฑ์

1. แท็บ **SOC** → เลือก **CTAM+**
2. คลิก checkbox แต่ละเกณฑ์เมื่อผ่าน
3. ใส่ Note/หลักฐานประกอบ
4. ระบบคำนวณ Compliance Gap + Security Score อัตโนมัติ
5. เกณฑ์ที่ไม่เกี่ยวกับประเภทหน่วยงานจะซ่อนโดยอัตโนมัติ

### 💯 MOPH 100-Point Standard

1. แท็บ **SOC** → **MOPH 100-Point**
2. คลิก domain ที่ต้องการ (Governance / Asset / Access / ...) เพื่อขยาย
3. ติ๊ก checkbox ตามที่ผ่านจริง พร้อมใส่หลักฐาน
4. คะแนนรวมแสดงแบบ Real-time มุมขวาบน

### 🚨 Incident Response

1. แท็บ **IRP** → เลือก **Playbook** ตามประเภทเหตุการณ์
2. ทำตามขั้นตอน: **Identify → Contain → Eradicate → Recover → Lessons Learned**
3. บันทึก Incident ใน **Incident Log** พร้อมหลักฐาน timeline
4. อัปเดตสถานะ: Open → In-Progress → Closed

### 📧 Email Security Checker

1. ไปที่ **Integrations** → **Email Security**
2. ใส่ domain ที่ต้องการตรวจ เช่น `moph.go.th`
3. ใส่ DKIM selector (ถ้าทราบ: `google`, `default`, `s1`, `mail`)
4. คลิก **ตรวจสอบ** → ผล SPF / DKIM / DMARC พร้อมคำแนะนำการแก้ไข

### 🔴 Wazuh Live Alerts

1. ไปที่ **Integrations** → แท็บ **Wazuh**
2. ใส่ URL: `https://[wazuh-ip]:55000`
3. Username: `wazuh-wui` · Password: (ดูจาก installer)
4. คลิก **Connect** → alerts แสดง Real-time color-coded ตาม level

### 🕸 MISP Event Viewer

1. ไปที่ **Integrations** → แท็บ **MISP**
2. ใส่ URL: `https://[misp-ip]` และ API Key
   - API Key: MISP UI → Administration → Auth Keys → Add Auth Key
3. คลิก **Load Events** → threat level color-coded

### 📡 IOC Sharing

1. ไปที่ **Integrations** → **IOC Sharing**
2. เลือก IOC Type (IP/domain/hash) และระดับความน่าเชื่อถือ
3. ใส่ IOC values ทีละบรรทัด
4. คลิก **สร้าง Report** / **Copy Email Template** (ThaiCERT) / **Copy STIX-2.1 JSON**

### 📄 Executive Report

1. แท็บ **SOC** → **Executive Report**
2. คลิก **Preview** → ตรวจสอบรายงานก่อนพิมพ์
3. คลิก **พิมพ์/Export PDF** → เลือก "Save as PDF" ใน print dialog

### 📋 Policy Register (CTAM+ ข้อ 17)

1. ไปที่ **Assets** → **Policy Register**
2. เพิ่ม/แก้ไข policies ทั้ง 5 รายการ:
   - Privacy Policy (นโยบายความเป็นส่วนตัว)
   - Privacy Notice (ประกาศความเป็นส่วนตัว)
   - Web Security Policy
   - Cybersecurity Policy
   - Cybersecurity Practices
3. ตั้งสถานะเป็น `อนุมัติแล้ว` ทั้ง 5 → ระบบ auto-mark CTAM+ ข้อ 17 ให้อัตโนมัติ

### 🔒 PDPA Data Flow Register

1. ไปที่ **Assets** → **PDPA Register**
2. เพิ่มรายการ Data Flow แต่ละ process
3. บันทึก: ประเภทข้อมูล, วัตถุประสงค์, ผู้รับข้อมูล, มาตรการคุ้มครอง
4. ทำ DPIA (Data Protection Impact Assessment) สำหรับ high-risk processing

---

## การเชื่อมต่อระบบภายนอก

### Wazuh REST API

```
URL:  https://[WAZUH-IP]:55000
User: wazuh-wui
Pass: ดูจาก: sudo cat /var/ossec/etc/passwords | grep wazuh-wui
```

หาก Wazuh ใช้ self-signed certificate (CORS error):
```nginx
# เพิ่มใน nginx proxy สำหรับ Wazuh
add_header Access-Control-Allow-Origin "http://[dashboard-ip]:3939";
add_header Access-Control-Allow-Headers "Authorization, Content-Type";
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
```

### MISP

```
URL:     https://[MISP-IP]
API Key: MISP UI → Administration → Auth Keys → Add Auth Key
         (เลือก permission: read-only สำหรับ dashboard)
```

### LINE Notify

1. เปิด https://notify-bot.line.me/my/
2. คลิก **Generate token** → เลือก Group หรือ 1-on-1
3. Copy token → ใส่ใน `.env` หรือ Settings ใน dashboard

### Email (Gmail App Password)

1. Gmail → บัญชี → ความปลอดภัย → **App passwords**
2. สร้าง App password → เลือก "Mail" + "Other device"
3. Copy รหัส 16 หลัก → ใส่ใน `SMTP_PASS` ใน `.env`

> ⚠️ ใช้ App Password เท่านั้น ไม่ใช่ password Gmail ปกติ (ต้องเปิด 2-Factor Authentication ก่อน)

---

## 🚀 Production Deployment (Linux Server)

### วิธีที่ 1: Auto Deploy Script (แนะนำ)

```bash
git clone https://github.com/thering999/ncsa-blacklist.git
cd ncsa-blacklist
sudo bash deploy.sh
```

Script ทำให้อัตโนมัติ:
1. ติดตั้ง Docker + Docker Compose (ถ้ายังไม่มี)
2. สร้าง `.env` พร้อม random Admin Token (`openssl rand -hex 32`)
3. Build + รัน containers พร้อม health check
4. ถามว่าต้องการ nginx reverse proxy
5. ถามว่ามี domain สำหรับ SSL (Let's Encrypt ฟรี)
6. ตั้งค่า systemd service (auto-start on reboot)
7. เปิด firewall (ufw) port 80/443

### วิธีที่ 2: Manual Deploy

```bash
# 1. ติดตั้ง Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# 2. Clone + ตั้งค่า
git clone https://github.com/thering999/ncsa-blacklist.git
cd ncsa-blacklist
cp .env.example .env
# ตั้ง ADMIN_TOKEN ด้วย:
echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env

# 3. รัน (production mode)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# 4. ตรวจสอบ
docker compose ps
curl http://localhost:3939/healthz
```

### ตั้งค่า nginx + SSL (Let's Encrypt ฟรี)

```bash
apt install nginx certbot python3-certbot-nginx -y

cp nginx.conf /etc/nginx/sites-available/ncsa-blacklist
sed -i 's/YOUR_DOMAIN/soc.hospital.go.th/g' /etc/nginx/sites-available/ncsa-blacklist
ln -sf /etc/nginx/sites-available/ncsa-blacklist /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# ขอ SSL certificate (ฟรี, ต่ออายุอัตโนมัติ)
certbot --nginx -d soc.hospital.go.th
```

### Auto-start on Reboot

```bash
# deploy.sh ตั้งให้อัตโนมัติ หรือทำเองด้วย:
systemctl enable ncsa-blacklist
systemctl start ncsa-blacklist
systemctl status ncsa-blacklist
```

### เปิด Firewall

```bash
# Ubuntu (ufw)
ufw allow 80/tcp && ufw allow 443/tcp && ufw enable

# CentOS/RHEL (firewalld)
firewall-cmd --permanent --add-service={http,https}
firewall-cmd --reload
```

---

## การสำรองและกู้คืนข้อมูล

### Export ข้อมูลทั้งหมด (แนะนำทำทุกสัปดาห์)

1. ไปที่ **Integrations** → **Export/Import**
2. คลิก **📥 Export ข้อมูลทั้งหมด**
3. บันทึกไฟล์ `dashboard-backup-[date].json`

> ไฟล์รวม: CTAM+, Risk Register, Assets, Incidents, PDPA, Policies, Training, Quiz History

### Import ข้อมูล (กู้คืน)

1. ไปที่ **Integrations** → **Export/Import**
2. คลิก **📤 Import** → เลือกไฟล์ `.json`
3. ยืนยัน → ข้อมูลจะถูกแทนที่ทั้งหมด

### Backup Docker Volume (Feed Data)

```bash
# Backup feed data
docker run --rm \
  -v ncsa-data:/data \
  -v $(pwd):/backup \
  ubuntu tar czf /backup/ncsa-feed-backup-$(date +%Y%m%d).tar.gz /data

# Restore
docker run --rm \
  -v ncsa-data:/data \
  -v $(pwd):/backup \
  ubuntu tar xzf /backup/ncsa-feed-backup-[date].tar.gz -C /
```

---

## การอัปเดตระบบ

```bash
# ดึง code ใหม่
git pull origin main

# Rebuild + restart (ข้อมูลไม่หาย)
docker compose up -d --build

# ตรวจสอบ
docker compose ps
curl http://localhost:3939/healthz
```

> Feed data เก็บใน Docker volume `ncsa-data` · Config/CTAM/Risk เก็บใน browser localStorage — ไม่หายเมื่อ rebuild

### Force sync feed ทันที

```bash
curl -X POST http://localhost:3939/admin/sync \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

---

## แก้ปัญหาที่พบบ่อย

### Error: `load metadata for docker.io/library/node:20-alpine`

```
ERROR [internal] load metadata for docker.io/library/node:20-alpine
```

**สาเหตุ**: Docker Desktop Windows บางเวอร์ชันมีปัญหาดึง image metadata ผ่าน BuildKit

**วิธีแก้ที่ 1 — Disable BuildKit:**
```cmd
# Command Prompt
set DOCKER_BUILDKIT=0
docker-compose up -d --build

# PowerShell
$env:DOCKER_BUILDKIT=0
docker-compose up -d --build
```

**วิธีแก้ที่ 2 — Pre-pull image ก่อน:**
```cmd
docker pull node:20-alpine
docker-compose up -d --build
```

**วิธีแก้ที่ 3 — Restart Docker Desktop:**  
คลิกขวา icon 🐳 ใน Taskbar → **Restart Docker Desktop** → รอ icon หยุดหมุน → รันใหม่

---

### Error: `Docker Desktop is not running`

```
error during connect: This error may indicate that the docker daemon is not running
```

**แก้**: เปิด **Docker Desktop** จาก Start Menu → รอ icon หยุดหมุน → รัน command ใหม่

---

### Error: `port is already allocated` (Port 3939 ถูกใช้แล้ว)

แก้ไขใน `docker-compose.yml`:
```yaml
ports:
  - "3940:3939"   # เปลี่ยน 3940 เป็น port ที่ว่าง
```
แล้วเปิดที่ **http://localhost:3940**

---

### Dashboard เปิดไม่ได้ / cannot connect

```bash
docker compose ps           # ตรวจสอบสถานะ container
docker compose logs ncsa-blacklist   # ดู error log
docker compose restart      # รีสตาร์ท
```

---

### Feed ว่างเปล่า / ไม่มีข้อมูล

```bash
# Sync ด้วยมือ
curl -X POST http://localhost:3939/admin/sync \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

# ดู sync log
docker compose logs ncsa-blacklist-sync
```

---

### Setup Wizard ไม่ขึ้น (ต้องการตั้งค่าใหม่)

กด **F12** → Console → พิมพ์:
```javascript
localStorage.removeItem('org_config'); location.reload();
```

---

### Wazuh / MISP CORS Error

เพิ่ม nginx proxy ที่ใส่ CORS header:
```nginx
location / {
    proxy_pass http://wazuh-or-misp-ip:port;
    add_header Access-Control-Allow-Origin "http://[dashboard-ip]:3939";
    add_header Access-Control-Allow-Headers "Authorization, Content-Type";
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
}
```

---

## API Reference

| Endpoint | Method | คำอธิบาย | Auth |
|----------|--------|-----------|------|
| `/check?q=X` | GET | ตรวจสอบ IP/domain/hash | ไม่ต้อง |
| `/bulk` | POST | ตรวจสอบหลายรายการ (JSON array, max 10,000) | ไม่ต้อง |
| `/recent` | GET | IOC ที่เพิ่มล่าสุด | ไม่ต้อง |
| `/stats` | GET | สถิติ feed (count, last update) | ไม่ต้อง |
| `/search?q=X` | GET | ค้นหาแบบ partial match | ไม่ต้อง |
| `/healthz` | GET | health check | ไม่ต้อง |
| `/metrics` | GET | Prometheus metrics | ไม่ต้อง |
| `/admin/sync` | POST | sync feed ทันที | Admin Token |
| `/reload` | POST | reload config | Admin Token |

ตัวอย่าง bulk check:
```bash
curl -X POST http://localhost:3939/bulk \
  -H "Content-Type: application/json" \
  -d '{"items": ["1.2.3.4", "evil.example.com", "5.6.7.8"]}'
```

---

## การพัฒนาต่อ

### โครงสร้างไฟล์

```
ncsa-blacklist/
├── public/
│   └── index.html          # Dashboard หลัก (single-file app)
├── src/
│   ├── server.js           # Express API server
│   └── scheduler.js        # Feed sync scheduler (ทุกวัน 01:00)
├── Dockerfile
├── docker-compose.yml
├── docker-compose.prod.yml # Production overrides
├── deploy.sh               # Auto deployment script (Linux)
├── start.bat               # Quick start (Windows)
├── nginx.conf              # nginx template
├── .env.example
└── README.md
```

### เพิ่ม Feed ใหม่

```env
# ใน .env
EXTRA_FEEDS=mylist:https://your-feed.go.th/blacklist.json,another:https://...
```

รูปแบบ JSON feed:
```json
{
  "type": "ip",
  "entries": ["1.2.3.4", "5.6.7.8"],
  "updated": "2025-01-01T00:00:00Z"
}
```

### เพิ่ม Custom Sigma Rule

เพิ่มใน `SIGMA_RULES` array ใน `public/index.html`:

```js
{
  id: 'SR009',
  title: 'ชื่อ Rule',
  tags: ['ransomware'],    // ransomware|lateral|exfil|phishing|webshell|privesc
  level: 'high',           // critical|high|medium|low
  mitre: 'T1234',
  desc: 'คำอธิบาย',
  sigma: `title: ...`      // YAML Sigma rule content
}
```

---

## 🔒 Security Notes

- **อย่า expose port 3939** บน public internet โดยตรง — ใช้ nginx reverse proxy + SSL เสมอ
- ตั้งค่า `ADMIN_TOKEN` เสมอก่อนใช้งานจริง (`openssl rand -hex 32`)
- ตั้งค่า `ADMIN_ALLOWED_IPS` จำกัด IP ที่เข้า `/admin/*` ได้
- Wazuh/MISP credentials ไม่ถูกเก็บใน server — เก็บเฉพาะใน browser localStorage
- ข้อมูล CTAM+/Risk/Incident เก็บใน browser localStorage ไม่ส่งออกไปที่ใด

---

## คำถามที่พบบ่อย

**Q: ข้อมูล CTAM+/Risk/Incident หายหลัง rebuild Docker ไหม?**  
A: ไม่หาย — เก็บใน browser localStorage · feed data เก็บใน Docker volume แยกต่างหาก

**Q: ใช้ได้กี่คนพร้อมกัน?**  
A: ไม่จำกัด — เป็น static HTML + API server · config ของแต่ละคนแยกกัน (localStorage per browser)

**Q: รองรับ HTTPS ไหม?**  
A: ไม่มี built-in — ใช้ nginx reverse proxy + SSL certificate (ดูหัวข้อ Production Deployment)

**Q: เพิ่ม feed นอกเหนือ NCSA ได้ไหม?**  
A: ได้ — ใส่ `EXTRA_FEEDS=ชื่อ:url` ใน `.env` แล้ว rebuild

**Q: CTAM+ ข้อ 17 ผ่านอัตโนมัติยังไง?**  
A: Assets → Policy Register → ตั้ง 5 policies เป็น `อนุมัติแล้ว` → ระบบ mark ให้เอง

**Q: Admin Token คืออะไร?**  
A: ป้องกัน endpoint `/admin/sync` และ `/reload` · ตั้งใน `.env` → `ADMIN_TOKEN=xxx` · ใส่ใน Settings เพื่อกดปุ่ม Sync

**Q: Export ข้อมูลทั้งหมดได้ไหม?**  
A: ได้ — **Integrations → Export/Import** → JSON backup ครอบคลุมทุก module

**Q: ใช้กับ FortiGate ได้ยังไง?**  
A: ไปที่ **Integrations → Firewall** → เลือก FortiGate → ระบบสร้าง config template สำหรับ block IP ใน blacklist ให้อัตโนมัติ

---

## 📞 ติดต่อ / รายงานปัญหา

- **GitHub Issues**: https://github.com/thering999/ncsa-blacklist/issues
- **ThaiCERT**: thaicert@etda.or.th | โทร 1212
- **NCSA**: ncsa@mict.go.th

---

## เกี่ยวกับโครงการ

> ⚠️ **หมายเหตุสำคัญ**: Dashboard นี้ **ไม่ใช่ผลิตภัณฑ์อย่างเป็นทางการของ สกมช. (NCSA)**  
> เป็นซอฟต์แวร์ Open Source ที่นำ **NCSA Blacklist Open Data (CC0)** มาพัฒนาต่อยอด  
> โดย **กลุ่มงานสุขภาพดิจิทัล สำนักงานสาธารณสุขจังหวัดมุกดาหาร**  
> เพื่อใช้งานในบริบทสาธารณสุขและหน่วยงานภาครัฐไทย

| รายการ | รายละเอียด |
|--------|-----------|
| **ข้อมูล Feed** | NCSA Blacklist Open Data — CC0 (สาธารณสมบัติ, ข้อมูลโดย สกมช.) |
| **Dashboard** | พัฒนาต่อยอดโดย กลุ่มงานสุขภาพดิจิทัล สสจ.มุกดาหาร |
| **License** | MIT — ใช้งาน แก้ไข แจกจ่ายได้ฟรี ไม่มีค่าใช้จ่าย |
| **Source Code** | https://github.com/thering999/ncsa-blacklist |

*ข้อมูล Blacklist Feed มาจาก สกมช. (NCSA) · Dashboard เป็น Open Source โดย กลุ่มงานสุขภาพดิจิทัล สสจ.มุกดาหาร · MIT License*
