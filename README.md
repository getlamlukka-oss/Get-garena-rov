# ⚔️ Get-garena-rov — ระบบส่งคำตอบ RoV Academy ครบ 40 บทอัตโนมัติ (v2.0 Clean-Room)

ระบบเว็บแอปพลิเคชันส่งคำตอบ **Garena RoV Academy (`https://academy.rov.in.th`)** ครบทั้ง **40 บทเรียน (+304 Gold, +810 Silver)** ที่พัฒนาขึ้นใหม่ทั้งหมดจากศูนย์ เน้นความเบา เร็ว และไม่ต้องใช้ Gemini API Key

---

## ✨ จุดเด่นของระบบ (v2.0)

1. **ไม่ต้องใช้ Gemini API (100% Zero-AI Local Engine)**
   - ตัดปัญหาโควตา Gemini เต็ม (`HTTP 429 Quota Exceeded`) หรือเซิร์ฟเวอร์ AI ล่ม (`HTTP 503`) ออก 100%
   - มาพร้อม **คลังเฉลยแท้ครบทั้ง 40 บทเรียน (`data/answers_cache.json`)** ที่ผ่านการยืนยันผลลัพธ์กับเซิร์ฟเวอร์ RoV Academy จริงทุกข้อ
   - มี **`LocalAdaptiveSolver` (`solver_engine.py`)** ในตัว วิเคราะห์เนื้อหาบทเรียน HTML และตัดตัวเลือกอัตโนมัติหากเกมอัปเดตคำถามใหม่
2. **ล็อกอิน Garena ID / Password แบบเบื้องหลัง (`auth_engine.py`)**
   - กรอก **Garena ID & Password** เพื่อล็อกอินเบื้องหลังและดึง `jwt_token` + `csrf_token` อัตโนมัติ
   - จดจำเซสชันแยกตามบัญชี (`data/sessions/`) ไม่ต้องล็อกอินซ้ำตราบใดที่ Token ยังไม่หมดอายุ
   - มีช่อง **วาง JWT Token / ลิงก์ `?token=eyJ...` สำรอง** ที่สกัด Token สะอาดให้อัตโนมัติ
3. **ดีไซน์ UI ใหม่ 2 แท็บเรียบง่าย (`static/index.html`, `static/style.css`, `static/app.js`)**
   - **แท็บ 1: ล็อกอิน & รันบอทอัตโนมัติ** — กรอกไอดี/รหัสผ่าน กดปุ่มเดียว ดูผล Gold / Silver / ความคืบหน้า 40 บทแบบเรียลไทม์ผ่าน WebSocket
   - **แท็บ 2: ประวัติ & รายการเฉลยทั้ง 40 บท** — ดูประวัติการรับรางวัล ค้นหาเฉลยทั้ง 40 บท และดาวน์โหลดไฟล์ `.csv` สรุประบบได้ทันทีบนหน้าเว็บ

---

## 📊 ไฟล์สรุประบบทั้งหมด (.CSV) สำหรับนำไปสร้างใหม่

- [`system_blueprint.csv`](./system_blueprint.csv) — ตารางสรุปสถาปัตยกรรม โมดูล ลำดับ API RoV Academy กฎ CSRF และระบบ UI ทั้งหมด
- [`rov_academy_40_chapters_answers.csv`](./rov_academy_40_chapters_answers.csv) — ตารางโจทย์และเฉลยที่ยืนยันแล้วครบทั้ง 40 บทเรียน

---

## 🚀 วิธีรันใช้งาน

```bash
python3 -m uvicorn main:app --host 127.0.0.1 --port 8000
```

จากนั้นเปิดเบราว์เซอร์ไปที่ `http://127.0.0.1:8000`
