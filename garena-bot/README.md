# ⚔️ Garena RoV Academy Auto-Solver & Auto-Redeem (`garena-bot` v3.0)

ระบบเว็บแอปพลิเคชันส่งคำตอบ **Garena RoV Academy (`https://academy.rov.in.th`)** ครบทั้ง **40 บทเรียน** พร้อมระบบแลกของรางวัลอัตโนมัติ (**Auto-Redeem**), ระบบจัดการหลายบัญชี (**สูงสุด 10 บัญชี**) และ **Worker Queue (`asyncio.Queue`) + Token-Bucket Rate Limiter** แบบ **Zero-Playwright / 100% Pure HTTP**

---

## 📂 โครงสร้างโปรเจกต์ (`garena-bot/`)

```text
garena-bot/
├── main.py                 # FastAPI + asyncio.Queue Worker + Rate Limiter + Auth + Solver + Auto-Redeem
├── requirements.txt        # รายการไลบรารีสำหรับ Production Server (ไร้ Playwright 100%)
├── README.md               # คู่มือการติดตั้งและ Deploy บน Production Server
├── static/
│   └── index.html          # Mobile-First 4-Step Dark Mode UI (Single/Multi-Account, Stepper, Stop, Redeem)
└── data/
    ├── answers_cache.json  # คลังเฉลยแท้ครบ 40 บท (183 ข้อ — ยืนยันผลกับเซิร์ฟเวอร์ RoV Academy)
    ├── accounts_vault.json # (สร้างอัตโนมัติ) ข้อมูลเซสชันสูงสุด 10 บัญชี
    ├── preferences.json    # (สร้างอัตโนมัติ) ตั้งค่า Auto-Redeem และ Proxy เริ่มต้น
    ├── jobs_state.json     # (สร้างอัตโนมัติ) สถานะคิวงานเบื้องหลัง (ปิดเว็บเปิดใหม่ดูต่อได้)
    └── run_history.json    # (สร้างอัตโนมัติ) ประวัติการทำข้อสอบและแลกของรางวัล
```

---

## ✨ สถาปัตยกรรมหลัก (Blueprint v3.0)

1. **Zero-Playwright Pure-HTTP Auth (`curl_cffi` Chrome TLS Spoofing + `httpx` Fallback)**
   - จำลอง TLS Fingerprint ของ Chrome (`impersonate="chrome"`) ยิง Garena SSO (`prelogin` → AES-256-ECB → `login` → OAuth `100055` → `/auth/callback/`)
   - รองรับ **Proxy** (`http://`, `https://`, `socks5://`) ทั้งระดับ Global และรายบัญชี
   - **DataDome WAF / HTTP 403 Fallback:** เมื่อตรวจพบการบล็อก คืนค่า `blocked_by_waf: true` พร้อมแจ้ง `"ระบบความปลอดภัยของ Garena บล็อกการเข้าถึงอัตโนมัติ"` และสลับเปิดช่องวาง **Token / ลิงก์ (`?token=`, `?access_token=`, `?code=`, `Cookie`)** ให้ทำงานต่อได้ทันที
2. **`asyncio.Queue` Background Worker & Rate Limiting**
   - ใช้ `asyncio.Queue` ร่วมกับ Worker Pool (`ROV_WORKER_COUNT`) รันงานเบื้องหลังต่อเนื่องแม้ผู้ใช้ปิดหน้าเว็บ (`ปิดหน้านี้ได้ ระบบทำต่อให้`) พร้อมปุ่ม `■ หยุด` ยกเลิกงานได้อย่างปลอดภัย
   - มี `AsyncRateLimiter` (Token-Bucket RPS + `asyncio.Semaphore` Concurrency Guard + Exponential Backoff เมื่อเจอ `429/5xx`) ป้องกันโดนแบน IP
3. **Zero-AI 40-Chapter Adaptive Solver + Auto-Redeem**
   - ตอบครบ 40 บทด้วยคลังเฉลยในตัว + Local HTML Analyzer (ไม่ต้องพึ่ง Gemini API Key)
   - เชื่อม `GET /api/rewards` และ `POST /api/redeem` แลกของรางวัลให้อัตโนมัติหลังทำแบบทดสอบเสร็จ

---

## 🚀 ขั้นตอนการติดตั้งและรันบน Production Server (Ubuntu / Debian Linux)

### 1. เตรียมสภาพแวดล้อมและติดตั้ง Dependencies

```bash
cd garena-bot
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. การกำหนดค่า Environment Variables (ทางเลือก)

```bash
export ROV_BASE_URL="https://academy.rov.in.th"
export GARENA_SSO_BASE_URL="https://sso.garena.com"
export ROV_WORKER_COUNT="2"          # จำนวน Background Workers ที่ดึงงานจาก asyncio.Queue
export ROV_RPS_LIMIT="4.0"           # จำกัดอัตราการยิง API สูงสุด (Requests/วินาที)
export ROV_MAX_CONCURRENCY="3"       # จำกัดจำนวน HTTP Requests พร้อมกันสูงสุด
export ROV_PROXY=""                  # ตัวอย่าง: http://user:pass@ip:port หรือ socks5://ip:port
```

### 3. การรันเซิร์ฟเวอร์ (พร้อมเคลียร์โปรเซส `uvicorn` ตัวเก่าก่อนเสมอ)

```bash
pkill -f "uvicorn main:app" || true
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```
> **หมายเหตุสำคัญ:** แนะนำให้ใช้ `--workers 1` เพื่อให้ `asyncio.Queue` และ WebSocket Subscribers ทำงานร่วมกันใน Event Loop เดียวอย่างสมบูรณ์ (รองรับการสเกลหลายบัญชีพร้อมกันผ่าน Async I/O อยู่แล้ว)

---

## 🛡️ การตั้งค่า Production ด้วย `systemd` + `Nginx` (แนะนำสำหรับ Server จริง)

### ตัวอย่างไฟล์ `/etc/systemd/system/garena-bot.service`

```ini
[Unit]
Description=Garena RoV Academy Auto-Solver & Queue Worker
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/garena-bot
Environment="ROV_WORKER_COUNT=2"
Environment="ROV_RPS_LIMIT=4.0"
ExecStartPre=-/usr/bin/pkill -f "uvicorn main:app"
ExecStart=/opt/garena-bot/.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

เปิดใช้งาน Service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now garena-bot
sudo systemctl status garena-bot
```

### ตัวอย่างตั้งค่า Nginx Reverse Proxy (รองรับ WebSocket)

```nginx
server {
    listen 80;
    server_name rov-solver.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
    }
}
```

---

## 🐳 การ Deploy ด้วย Docker (ทางเลือก)

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```

---

## 🔌 สรุป API Endpoints หลัก

| Method | Endpoint | คำอธิบาย |
|---|---|---|
| `GET` | `/api/health` | ตรวจสอบสถานะเซิร์ฟเวอร์, คลังเฉลย 40 บท และจำนวนคิวงาน |
| `POST` | `/api/login` (`/login`) | ล็อกอิน Garena SSO (`curl_cffi`) หรือแลก Token/URL (`?access_token=`, `?code=`, `JWT`) |
| `GET` | `/api/accounts` | ดูรายการบัญชีที่บันทึกไว้ (สูงสุด 10 บัญชี) |
| `POST` | `/api/accounts/batch` | นำเข้าหลายบัญชีพร้อมกัน (`id:password` หรือ `id\|token`) |
| `POST` | `/api/jobs/enqueue` | ส่งบัญชีที่เลือกเข้า `asyncio.Queue` เพื่อตอบคำถาม + แลกรางวัลเบื้องหลัง |
| `GET` | `/api/jobs/active` | ดึงสถานะงานที่กำลังทำ/ล่าสุด (รองรับเปิดเว็บกลับมาดูต่อ) |
| `POST` | `/api/jobs/{job_id}/stop` | สั่งหยุดงาน (`■ หยุด`) อย่างปลอดภัย |
| `GET` | `/api/rewards` | ดึงรายการของรางวัลจาก RoV Academy (`/api/rewards`) |
| `POST` | `/api/preferences` | บันทึกการตั้งค่า Auto-Redeem และ Global Proxy |
| `WS` | `/ws/jobs/{job_id}` | สตรีมสถานะ Stepper, Progress Bar และ Live Log แบบเรียลไทม์ |
