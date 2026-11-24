import asyncio
import inspect
import logging
import random
import re
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from config import (
    extract_clean_jwt,
    get_rov_base_url,
    inspect_jwt,
    load_session,
    save_session,
)

logger = logging.getLogger("rov-auth-engine")

STEALTH_INIT_JS = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
window.chrome = { runtime: {}, loadTimes: function() {}, csi: function() {}, app: {} };
Object.defineProperty(navigator, 'languages', { get: () => ['th-TH', 'th', 'en-US', 'en'] });
"""


async def _emit_log(log_fn: Optional[Callable[..., Any]], msg: str, level: str = "info") -> None:
    if not log_fn:
        return
    try:
        res = log_fn(msg, level, "auth")
        if inspect.isawaitable(res):
            await res
    except TypeError:
        try:
            res = log_fn(msg, level)
            if inspect.isawaitable(res):
                await res
        except Exception:
            pass
    except Exception:
        pass


def _extract_jwt_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    try:
        qs = parse_qs(urlparse(url).query)
        for key in ("token", "jwt_token", "access_token", "jwt"):
            vals = qs.get(key)
            if vals and vals[0]:
                cand = extract_clean_jwt(vals[0])
                if inspect_jwt(cand).get("valid_structure"):
                    return cand
    except Exception:
        pass
    m = re.search(r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", url)
    return m.group(1) if m else None


async def _try_solve_datadome_slider(page: Any, log_fn: Optional[Callable[..., Any]]) -> bool:
    try:
        frames = [page.main_frame] + [f for f in page.frames if f != page.main_frame]
        slider_box = None
        for frame in frames:
            for sel in (
                ".slider",
                ".geetest_slider_button",
                "[class*='slider-button']",
                "[class*='slider_btn']",
                "div[role='slider']",
                "i.slider-icon",
            ):
                try:
                    loc = frame.locator(sel).first
                    if await loc.count() > 0 and await loc.is_visible():
                        slider_box = await loc.bounding_box()
                        if slider_box:
                            break
                except Exception:
                    continue
            if slider_box:
                break

        if not slider_box:
            return False

        await _emit_log(log_fn, "🧩 ตรวจพบตัวต่อ CAPTCHA เบื้องหลัง — กำลังเลื่อนแก้ CAPTCHA อัตโนมัติ...", "warning")
        start_x = slider_box["x"] + slider_box["width"] / 2
        start_y = slider_box["y"] + slider_box["height"] / 2

        for dist in (145, 185, 115, 215):
            await page.mouse.move(start_x, start_y)
            await page.mouse.down()
            steps = 18
            for s in range(1, steps + 1):
                progress = 1 - ((1 - (s / steps)) ** 2)
                cur_x = start_x + dist * progress + random.uniform(-1.0, 1.0)
                cur_y = start_y + random.uniform(-1.5, 1.5)
                await page.mouse.move(cur_x, cur_y)
                await asyncio.sleep(0.018)
            await page.mouse.up()
            await asyncio.sleep(1.5)
            return True
    except Exception:
        pass
    return False


async def authenticate_garena_background(
    garena_id: Optional[str] = None,
    garena_password: Optional[str] = None,
    jwt_token: Optional[str] = None,
    csrf_token: Optional[str] = None,
    base_url: Optional[str] = None,
    log_fn: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    clean_id = (garena_id or "").strip() or None
    clean_pw = (garena_password or "").strip() or None
    rov_base = get_rov_base_url(base_url)

    direct_jwt = extract_clean_jwt(jwt_token)
    if not inspect_jwt(direct_jwt).get("valid_structure") and clean_id:
        maybe_from_id = extract_clean_jwt(clean_id)
        if inspect_jwt(maybe_from_id).get("valid_structure"):
            direct_jwt = maybe_from_id
            clean_id = None

    if direct_jwt:
        claims = inspect_jwt(direct_jwt)
        if not claims.get("valid_structure"):
            return {"success": False, "error": "รูปแบบ JWT Token ที่ระบุไม่ถูกต้อง"}
        if claims.get("is_expired"):
            return {"success": False, "error": "JWT Token ที่ระบุหมดอายุแล้ว กรุณาล็อกอินใหม่"}
        save_session(direct_jwt, csrf_token, garena_id=clean_id)
        await _emit_log(log_fn, "⚡ ใช้ JWT Token ที่ระบุโดยตรงสำเร็จ", "success")
        return {
            "success": True,
            "jwt_token": direct_jwt,
            "csrf_token": csrf_token,
            "garena_id": clean_id,
            "source": "direct_token",
        }

    cached_jwt, cached_csrf, cached_acc = load_session(clean_id)
    if cached_jwt:
        effective_acc = clean_id or cached_acc or "saved_session"
        await _emit_log(
            log_fn,
            f"⚡ พบเซสชันที่ยังไม่หมดอายุของบัญชี '{effective_acc}' — ดึง Token อัตโนมัติทันที!",
            "success",
        )
        if clean_id and clean_id != cached_acc:
            save_session(cached_jwt, cached_csrf, garena_id=clean_id)
        return {
            "success": True,
            "jwt_token": cached_jwt,
            "csrf_token": cached_csrf,
            "garena_id": effective_acc,
            "source": "session_cache",
        }

    if not clean_id or not clean_pw:
        return {
            "success": False,
            "error": "กรุณากรอก Garena ID และ Password (หรือวาง Token) เพื่อเข้าสู่ระบบ",
        }

    await _emit_log(
        log_fn,
        f"🔐 กำลังล็อกอินบัญชี Garena '{clean_id}' แบบเบื้องหลังและดึง Token อัตโนมัติ...",
        "info",
    )

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "success": False,
            "error": "ไม่พบโมดูล Playwright สำหรับล็อกอินเบื้องหลัง กรุณาวาง Token ในช่องตัวเลือกเสริม",
        }

    captured_jwt: Optional[str] = None
    captured_csrf: Optional[str] = None

    try:
        async with async_playwright() as p:
            browser = None
            owns_browser = False
            try:
                browser = await p.chromium.connect_over_cdp("http://127.0.0.1:9222", timeout=1800)
                await _emit_log(log_fn, "🌐 เชื่อมต่อเบราว์เซอร์ในเครื่องสำเร็จ กำลังตรวจสอบเซสชัน...", "info")
            except Exception:
                browser = None

            if browser is None:
                owns_browser = True
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                    ],
                )

            context = (
                browser.contexts[0]
                if (not owns_browser and browser.contexts)
                else await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    locale="th-TH",
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                    ),
                )
            )
            await context.add_init_script(STEALTH_INIT_JS)
            page = await context.new_page()

            def _on_request_or_nav(url: str) -> None:
                nonlocal captured_jwt
                if not captured_jwt:
                    tok = _extract_jwt_from_url(url)
                    if tok:
                        captured_jwt = tok

            page.on("framenavigated", lambda frame: _on_request_or_nav(frame.url))
            page.on("request", lambda req: _on_request_or_nav(req.url))

            async def _harvest_tokens() -> Tuple[Optional[str], Optional[str]]:
                nonlocal captured_jwt, captured_csrf
                _on_request_or_nav(page.url)
                try:
                    for c in await context.cookies():
                        if c.get("name") == "jwt_token" and c.get("value"):
                            cand = extract_clean_jwt(c["value"])
                            if inspect_jwt(cand).get("valid_structure"):
                                captured_jwt = cand
                        elif c.get("name") == "csrf_token" and c.get("value"):
                            captured_csrf = str(c["value"]).strip()
                except Exception:
                    pass
                if not captured_jwt and "rov.in.th" in page.url:
                    try:
                        storage_tok = await page.evaluate(
                            """() => {
                                for (const s of [window.localStorage, window.sessionStorage]) {
                                    if (!s) continue;
                                    for (let i = 0; i < s.length; i++) {
                                        const k = s.key(i);
                                        const v = s.getItem(k) || '';
                                        const m = v.match(/(eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})/);
                                        if (m) return m[1];
                                    }
                                }
                                return null;
                            }"""
                        )
                        if storage_tok:
                            captured_jwt = extract_clean_jwt(storage_tok)
                    except Exception:
                        pass
                return captured_jwt, captured_csrf

            await page.goto(rov_base, wait_until="domcontentloaded", timeout=25000)
            await asyncio.sleep(1.0)
            await _harvest_tokens()

            if not captured_jwt:
                for btn_sel in (
                    "a[href*='garena']",
                    "a[href*='login']",
                    "a[href*='auth']",
                    "button:has-text('เข้าสู่ระบบ')",
                    "button:has-text('Login')",
                    ".btn-login",
                ):
                    try:
                        loc = page.locator(btn_sel).first
                        if await loc.count() > 0 and await loc.is_visible():
                            await loc.click()
                            await asyncio.sleep(1.5)
                            break
                    except Exception:
                        continue

                user_sel = "input[name='username'], input[name='account'], input[type='text'], #sso_username"
                pass_sel = "input[name='password'], input[type='password'], #sso_password"
                try:
                    await page.wait_for_selector(user_sel, timeout=12000)
                    u_input = page.locator(user_sel).first
                    p_input = page.locator(pass_sel).first
                    await u_input.click()
                    await u_input.fill(clean_id)
                    await asyncio.sleep(0.25)
                    await p_input.click()
                    await p_input.fill(clean_pw)
                    await asyncio.sleep(0.3)

                    for sub_sel in (
                        "button[type='submit']",
                        "input[type='submit']",
                        "#confirm-btn",
                        "button:has-text('Login Now')",
                        "button:has-text('เข้าสู่ระบบ')",
                    ):
                        sub = page.locator(sub_sel).first
                        if await sub.count() > 0:
                            await sub.click()
                            break
                    else:
                        await p_input.press("Enter")
                except Exception as exc:
                    logger.warning(f"Garena SSO form fill warning: {exc}")

                for _ in range(18):
                    await asyncio.sleep(1.0)
                    await _harvest_tokens()
                    if captured_jwt:
                        break
                    await _try_solve_datadome_slider(page, log_fn)

            try:
                cookies_dump = await context.cookies()
            except Exception:
                cookies_dump = []

            if owns_browser:
                await browser.close()

            if captured_jwt:
                save_session(captured_jwt, captured_csrf, garena_id=clean_id, cookies_list=cookies_dump)
                await _emit_log(
                    log_fn,
                    f"✅ ล็อกอินเบื้องหลังและดึง Token บัญชี '{clean_id}' สำเร็จ!",
                    "success",
                )
                return {
                    "success": True,
                    "jwt_token": captured_jwt,
                    "csrf_token": captured_csrf,
                    "garena_id": clean_id,
                    "source": "background_playwright",
                }

            return {
                "success": False,
                "error": (
                    "Garena บล็อกการล็อกอินเบื้องหลังด้วย CAPTCHA หรือรหัสผ่านไม่ถูกต้อง — "
                    "คุณสามารถเปิดช่อง 'วาง Token สำรอง' ด้านล่างเพื่อวาง Token แล้วรันต่อได้ทันที"
                ),
            }
    except Exception as exc:
        return {
            "success": False,
            "error": f"ล็อกอินเบื้องหลังไม่สำเร็จ ({exc}) — กรุณาตรวจสอบ Garena ID/Password หรือวาง Token สำรอง",
        }
