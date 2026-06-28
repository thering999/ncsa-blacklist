#!/bin/bash
# ================================================================
# NCSA Blacklist SOC Dashboard — Auto Deploy Script
# รองรับ: Ubuntu 20.04/22.04/24.04, Debian 11/12
# ใช้งาน: sudo bash deploy.sh
# ================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[ "$EUID" -ne 0 ] && error "กรุณารันด้วย sudo: sudo bash deploy.sh"

INSTALL_DIR=${INSTALL_DIR:-/opt/ncsa-blacklist}

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║   NCSA Blacklist SOC Dashboard           ║"
echo "║   Production Deploy Script               ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ── ติดตั้ง Docker ──────────────────────────────
info "ตรวจสอบ Docker..."
if ! command -v docker &>/dev/null; then
  info "ติดตั้ง Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
  success "Docker ติดตั้งเรียบร้อย"
else
  success "Docker พบแล้ว: $(docker --version)"
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  info "ติดตั้ง Docker Compose..."
  apt-get install -y docker-compose-plugin 2>/dev/null || \
  curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose
  success "Docker Compose ติดตั้งเรียบร้อย"
else
  success "Docker Compose พบแล้ว"
fi

# ── หาโฟลเดอร์ repo ─────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
  INSTALL_DIR="$SCRIPT_DIR"
  info "ใช้ไฟล์จาก: $INSTALL_DIR"
elif [ -d "$INSTALL_DIR/.git" ]; then
  info "พบการติดตั้งเดิม — อัปเดต..."
  git -C "$INSTALL_DIR" pull origin main
else
  error "ไม่พบ docker-compose.yml กรุณารัน script จากภายในโฟลเดอร์ที่ clone มา"
fi

cd "$INSTALL_DIR"

# ── ตั้งค่า .env ─────────────────────────────────
if [ ! -f .env ]; then
  info "สร้างไฟล์ .env..."
  cp .env.example .env
  ADMIN_TOKEN=$(openssl rand -hex 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 64)
  sed -i "s/^ADMIN_TOKEN=.*/ADMIN_TOKEN=$ADMIN_TOKEN/" .env
  echo ""
  warn "═══════════════════════════════════════════"
  warn "Admin Token: $ADMIN_TOKEN"
  warn "บันทึก token นี้ไว้! จำเป็นสำหรับ /admin/*"
  warn "═══════════════════════════════════════════"
  echo ""
else
  success "พบ .env เดิม — ใช้การตั้งค่าเดิม"
fi

# ── รัน Docker ───────────────────────────────────
info "Build และรัน Docker containers..."
if docker compose version &>/dev/null 2>&1; then
  docker compose -f docker-compose.yml up -d --build
else
  docker-compose -f docker-compose.yml up -d --build
fi

info "รอ containers พร้อม..."
sleep 5
for i in {1..12}; do
  if curl -sf http://localhost:3939/healthz &>/dev/null; then
    success "Dashboard พร้อมใช้งาน!"
    break
  fi
  echo -n "."
  sleep 5
  [ $i -eq 12 ] && error "Timeout — ตรวจสอบ: docker compose logs"
done

# ── nginx (optional) ─────────────────────────────
echo ""
read -p "ติดตั้ง nginx reverse proxy? [y/N]: " USE_NGINX
if [[ "$USE_NGINX" =~ ^[Yy]$ ]]; then
  read -p "Domain name (เช่น soc.hospital.go.th) หรือกด Enter ข้าม SSL: " DOMAIN

  apt-get install -y nginx &>/dev/null
  systemctl enable nginx

  if [ -n "$DOMAIN" ]; then
    cat > /etc/nginx/sites-available/ncsa-blacklist <<NGINXEOF
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    location / {
        proxy_pass http://localhost:3939;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
    }
}
NGINXEOF
    ln -sf /etc/nginx/sites-available/ncsa-blacklist /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl reload nginx
    success "nginx ตั้งค่าแล้ว"
    info "ติดตั้ง SSL ฟรี: apt install certbot python3-certbot-nginx -y && certbot --nginx -d $DOMAIN"
  else
    SERVER_IP=$(hostname -I | awk '{print $1}')
    cat > /etc/nginx/sites-available/ncsa-blacklist <<NGINXEOF
server {
    listen 80;
    server_name $SERVER_IP _;
    location / {
        proxy_pass http://localhost:3939;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NGINXEOF
    ln -sf /etc/nginx/sites-available/ncsa-blacklist /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl reload nginx
    success "nginx ตั้งค่าแล้ว (HTTP only)"
  fi
fi

# ── Firewall ─────────────────────────────────────
if command -v ufw &>/dev/null; then
  ufw allow 80/tcp &>/dev/null || true
  ufw allow 443/tcp &>/dev/null || true
  ufw allow 3939/tcp &>/dev/null || true
  success "ufw: เปิดพอร์ต 80/443/3939"
fi

# ── Systemd service ───────────────────────────────
cat > /etc/systemd/system/ncsa-blacklist.service <<SVCEOF
[Unit]
Description=NCSA Blacklist SOC Dashboard
Requires=docker.service
After=docker.service network-online.target

[Service]
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload
systemctl enable ncsa-blacklist &>/dev/null || true
success "systemd service ตั้งค่าแล้ว (auto-start on reboot)"

# ── สรุป ─────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗"
echo -e "║   ติดตั้งเสร็จเรียบร้อย! 🎉                ║"
echo -e "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard: ${CYAN}http://$SERVER_IP:3939${NC}"
[ -n "$DOMAIN" ] && echo -e "  Domain:    ${CYAN}https://$DOMAIN${NC} (หลังติดตั้ง SSL)"
echo ""
echo -e "  คำสั่งที่มีประโยชน์:"
echo -e "  ${YELLOW}docker compose logs -f${NC}                         # ดู logs"
echo -e "  ${YELLOW}docker compose ps${NC}                              # ดูสถานะ"
echo -e "  ${YELLOW}git pull && docker compose up -d --build${NC}       # อัปเดต"
echo -e "  ${YELLOW}systemctl status ncsa-blacklist${NC}                # ดูสถานะ service"
echo ""
