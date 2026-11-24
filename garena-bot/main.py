import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import random
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from itertools import product
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, quote, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession

    HAS_CURL_CFFI = True
except ImportError:
    CurlAsyncSession = None  # type: ignore[assignment]
    HAS_CURL_CFFI = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("garena-bot")

# ============================================================================
# 1. CONFIGURATION & PERSISTENT STORAGE
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"

ANSWERS_CACHE_PATH = (
    DATA_DIR / "answers_cache.json"
    if (DATA_DIR / "answers_cache.json").exists()
    else BASE_DIR.parent / "data" / "answers_cache.json"
)
ACCOUNTS_VAULT_PATH = DATA_DIR / "accounts_vault.json"
PREFERENCES_PATH = DATA_DIR / "preferences.json"
JOBS_STATE_PATH = DATA_DIR / "jobs_state.json"
HISTORY_PATH = DATA_DIR / "run_history.json"

MAX_ACCOUNTS = 10
OAUTH_APP_ID = "100055"
DEFAULT_ROV_BASE_URL = os.getenv("ROV_BASE_URL", "https://academy.rov.in.th").rstrip("/")
DEFAULT_SSO_BASE_URL = os.getenv("GARENA_SSO_BASE_URL", "https://sso.garena.com").rstrip("/")
DEFAULT_WORKER_COUNT = max(1, int(os.getenv("ROV_WORKER_COUNT", "2")))
DEFAULT_RPS_LIMIT = max(0.5, float(os.getenv("ROV_RPS_LIMIT", "4.0")))
DEFAULT_MAX_CONCURRENCY = max(1, int(os.getenv("ROV_MAX_CONCURRENCY", "3")))
DEFAULT_GLOBAL_PROXY = os.getenv("ROV_PROXY", "").strip()

WAF_BLOCK_THAI_MSG = "ระบบความปลอดภัยของ Garena บล็อกการเข้าถึงอัตโนมัติ"
JWT_REGEX = re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
CHROME_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
)


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, payload: Any) -> None:
    ensure_dirs()
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def mask_account_name(name: str) -> str:
    clean = (name or "").strip()
    return (clean or "player") if len(clean) <= 4 else f"{clean[:3]}••••{clean[-2:]}"


def extract_clean_jwt(raw: Optional[str]) -> str:
    if not raw or not isinstance(raw, str):
        return ""
    m = JWT_REGEX.search(raw.strip())
    return m.group(1) if m else ""


def inspect_jwt(token: Optional[str]) -> Dict[str, Any]:
    cleaned = extract_clean_jwt(token)
    parts = cleaned.split(".") if cleaned else []
    if len(parts) != 3:
        return {"valid_structure": False, "is_expired": False, "remaining_seconds": None}
    try:
        hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)).decode("utf-8"))
        pld = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)).decode("utf-8"))
    except Exception:
        return {"valid_structure": False, "is_expired": False, "remaining_seconds": None}

    exp = pld.get("exp")
    now_ts = int(time.time())
    is_expired = isinstance(exp, (int, float)) and exp > 0 and now_ts >= int(exp)
    rem = (int(exp) - now_ts) if isinstance(exp, (int, float)) and exp > 0 else None
    return {
        "valid_structure": True,
        "alg": hdr.get("alg", "HS256"),
        "exp": int(exp) if isinstance(exp, (int, float)) else None,
        "is_expired": is_expired,
        "remaining_seconds": rem,
        "uid": pld.get("uid") or pld.get("sub") or pld.get("id"),
        "preview": f"{cleaned[:10]}...{cleaned[-6:]}" if len(cleaned) > 20 else "***",
    }


def extract_auth_material(raw_input: Optional[str], explicit_csrf: str = "") -> Dict[str, str]:
    result = {"jwt_token": "", "csrf_token": explicit_csrf.strip(), "access_token": "", "code": ""}
    if not raw_input or not isinstance(raw_input, str):
        return result
    text = raw_input.strip()
    direct_jwt = extract_clean_jwt(text)
    if direct_jwt:
        result["jwt_token"] = direct_jwt
    csrf_match = re.search(r"csrf_token=([^;\s&]+)", text)
    if csrf_match and not result["csrf_token"]:
        result["csrf_token"] = csrf_match.group(1).strip()

    if any(tok in text for tok in ("http://", "https://", "?", "access_token=", "code=")):
        q_part = urlparse(text).query if "://" in text else text.lstrip("?")
        qs = parse_qs(q_part)
        for k in ("token", "jwt_token", "jwt"):
            if qs.get(k) and not result["jwt_token"]:
                result["jwt_token"] = extract_clean_jwt(qs[k][0])
        if qs.get("access_token"):
            cand_at = qs["access_token"][0].strip()
            if extract_clean_jwt(cand_at):
                result["jwt_token"] = extract_clean_jwt(cand_at)
            else:
                result["access_token"] = cand_at
        if qs.get("code"):
            result["code"] = qs["code"][0].strip()

    if not any(result.values()) and re.fullmatch(r"[A-Fa-f0-9]{32,128}", text):
        result["access_token"] = text
    return result


def load_preferences() -> Dict[str, Any]:
    raw = _read_json(PREFERENCES_PATH, {})
    return {
        "auto_redeem_enabled": bool(raw.get("auto_redeem_enabled", True)),
        "preferred_reward_ids": list(raw.get("preferred_reward_ids") or []),
        "global_proxy": str(raw.get("global_proxy") if "global_proxy" in raw else DEFAULT_GLOBAL_PROXY).strip(),
    }


def save_preferences(prefs: Dict[str, Any]) -> Dict[str, Any]:
    cur = load_preferences()
    if prefs.get("auto_redeem_enabled") is not None:
        cur["auto_redeem_enabled"] = bool(prefs["auto_redeem_enabled"])
    if prefs.get("preferred_reward_ids") is not None:
        cur["preferred_reward_ids"] = list(prefs["preferred_reward_ids"])
    if prefs.get("global_proxy") is not None:
        cur["global_proxy"] = str(prefs["global_proxy"]).strip()
    _write_json(PREFERENCES_PATH, cur)
    return cur


def load_accounts_vault() -> Dict[str, Any]:
    raw = _read_json(ACCOUNTS_VAULT_PATH, {})
    accounts = raw.get("accounts") if isinstance(raw.get("accounts"), list) else []
    active_id = str(raw.get("active_garena_id") or "")
    if accounts and not any(a.get("garena_id") == active_id for a in accounts):
        active_id = str(accounts[0].get("garena_id") or "")
    return {"active_garena_id": active_id, "accounts": accounts}


def _public_vault_view(vault: Dict[str, Any]) -> Dict[str, Any]:
    items = []
    selected_count = 0
    for acc in vault.get("accounts", []):
        jwt_info = inspect_jwt(acc.get("jwt_token"))
        has_valid_jwt = bool(jwt_info.get("valid_structure") and not jwt_info.get("is_expired"))
        is_sel = bool(acc.get("selected", True))
        if is_sel:
            selected_count += 1
        gid = str(acc.get("garena_id") or "player")
        items.append({
            "garena_id": gid,
            "masked_id": mask_account_name(gid),
            "selected": is_sel,
            "has_valid_token": has_valid_jwt,
            "has_password": bool(acc.get("garena_password")),
            "proxy": str(acc.get("proxy") or ""),
            "remaining_seconds": jwt_info.get("remaining_seconds"),
            "gold": int(acc.get("gold", 0) or 0),
            "silver": int(acc.get("silver", 0) or 0),
            "completed_chapters": int(acc.get("completed_chapters", 0) or 0),
            "updated_at": acc.get("updated_at"),
        })
    return {
        "active_garena_id": vault.get("active_garena_id") or "",
        "accounts": items,
        "count": len(items),
        "max_accounts": MAX_ACCOUNTS,
        "selected_count": selected_count,
    }


def upsert_account(
    garena_id: str,
    jwt_token: str = "",
    csrf_token: str = "",
    garena_password: str = "",
    proxy: str = "",
    selected: bool = True,
    activate: bool = True,
    gold: Optional[int] = None,
    silver: Optional[int] = None,
    completed_chapters: Optional[int] = None,
) -> Dict[str, Any]:
    gid = (garena_id or "").strip()
    if not gid:
        raise ValueError("กรุณาระบุชื่อบัญชี Garena ID")
    vault = load_accounts_vault()
    accounts: List[Dict[str, Any]] = vault["accounts"]
    existing = next((a for a in accounts if str(a.get("garena_id", "")).lower() == gid.lower()), None)
    if existing is None and len(accounts) >= MAX_ACCOUNTS:
        raise ValueError(f"บันทึกได้สูงสุด {MAX_ACCOUNTS} บัญชี กรุณาลบบัญชีเก่าก่อนเพิ่มใหม่")

    clean_jwt = extract_clean_jwt(jwt_token)
    if existing is None:
        accounts.append({
            "garena_id": gid,
            "garena_password": garena_password,
            "jwt_token": clean_jwt,
            "csrf_token": csrf_token.strip(),
            "proxy": proxy.strip(),
            "selected": bool(selected),
            "gold": int(gold or 0),
            "silver": int(silver or 0),
            "completed_chapters": int(completed_chapters or 0),
            "updated_at": int(time.time()),
        })
    else:
        gid = existing["garena_id"]
        if clean_jwt:
            existing["jwt_token"] = clean_jwt
        if csrf_token.strip():
            existing["csrf_token"] = csrf_token.strip()
        if garena_password:
            existing["garena_password"] = garena_password
        if proxy:
            existing["proxy"] = proxy.strip()
        existing["selected"] = bool(selected)
        if gold is not None:
            existing["gold"] = int(gold)
        if silver is not None:
            existing["silver"] = int(silver)
        if completed_chapters is not None:
            existing["completed_chapters"] = int(completed_chapters)
        existing["updated_at"] = int(time.time())

    if activate or not vault.get("active_garena_id"):
        vault["active_garena_id"] = gid
    _write_json(ACCOUNTS_VAULT_PATH, vault)
    return _public_vault_view(vault)


# ============================================================================
# 2. RATE LIMITER & ZERO-PLAYWRIGHT HTTP TRANSPORT (curl_cffi + httpx fallback)
# ============================================================================


class AsyncRateLimiter:
    def __init__(self, rps: float = DEFAULT_RPS_LIMIT, max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> None:
        self.min_interval = 1.0 / max(0.2, rps)
        self.semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._lock = asyncio.Lock()
        self._last_ts = 0.0

    async def __aenter__(self) -> "AsyncRateLimiter":
        await self.semaphore.acquire()
        async with self._lock:
            wait_for = self.min_interval - (time.monotonic() - self._last_ts)
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_ts = time.monotonic()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.semaphore.release()


GLOBAL_RATE_LIMITER = AsyncRateLimiter()


@dataclass
class NormalizedResponse:
    status_code: int
    text: str
    headers: Dict[str, str]
    cookies: Dict[str, str]

    def json(self) -> Any:
        return json.loads(self.text) if self.text else {}


class PureHttpClient:
    def __init__(
        self,
        cookies: Optional[Dict[str, str]] = None,
        proxy: str = "",
        timeout: float = 25.0,
        rate_limiter: Optional[AsyncRateLimiter] = None,
    ) -> None:
        self.cookies: Dict[str, str] = dict(cookies or {})
        self.proxy = (proxy or "").strip()
        self.timeout = timeout
        self.rate_limiter = rate_limiter or GLOBAL_RATE_LIMITER
        self._curl_session: Any = None
        self._httpx_client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "PureHttpClient":
        if HAS_CURL_CFFI and CurlAsyncSession is not None:
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            self._curl_session = CurlAsyncSession(
                impersonate="chrome",
                proxies=proxies,
                cookies=self.cookies,
                timeout=self.timeout,
            )
            await self._curl_session.__aenter__()
        else:
            kwargs: Dict[str, Any] = {"cookies": self.cookies, "timeout": self.timeout, "follow_redirects": True}
            if self.proxy:
                kwargs["proxy"] = self.proxy
            try:
                self._httpx_client = httpx.AsyncClient(**kwargs)
            except TypeError:
                kwargs.pop("proxy", None)
                if self.proxy:
                    kwargs["proxies"] = self.proxy
                self._httpx_client = httpx.AsyncClient(**kwargs)
            await self._httpx_client.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._curl_session is not None:
            await self._curl_session.__aexit__(exc_type, exc, tb)
        if self._httpx_client is not None:
            await self._httpx_client.__aexit__(exc_type, exc, tb)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        allow_redirects: bool = True,
        max_retries: int = 3,
    ) -> NormalizedResponse:
        merged_headers = {"User-Agent": CHROME_UA, **(headers or {})}
        last_err: Optional[Exception] = None
        for attempt in range(max_retries + 1):
            try:
                async with self.rate_limiter:
                    if self._curl_session is not None:
                        raw = await self._curl_session.request(
                            method.upper(),
                            url,
                            headers=merged_headers,
                            params=params,
                            json=json_body,
                            cookies=self.cookies,
                            allow_redirects=allow_redirects,
                        )
                        resp_cookies: Dict[str, str] = {}
                        for src in (getattr(self._curl_session, "cookies", {}), getattr(raw, "cookies", {})):
                            try:
                                resp_cookies.update(dict(src))
                            except Exception:
                                pass
                        resp_headers = {str(k).lower(): str(v) for k, v in raw.headers.items()}
                        norm = NormalizedResponse(raw.status_code, raw.text, resp_headers, resp_cookies)
                    else:
                        assert self._httpx_client is not None
                        for ck, cv in self.cookies.items():
                            self._httpx_client.cookies.set(ck, cv)
                        raw_hx = await self._httpx_client.request(
                            method.upper(),
                            url,
                            headers=merged_headers,
                            params=params,
                            json=json_body,
                            follow_redirects=allow_redirects,
                        )
                        resp_cookies = {c.name: c.value for c in self._httpx_client.cookies.jar if c.value}
                        resp_cookies.update({k: v for k, v in raw_hx.cookies.items() if v})
                        resp_headers = {str(k).lower(): str(v) for k, v in raw_hx.headers.items()}
                        norm = NormalizedResponse(raw_hx.status_code, raw_hx.text, resp_headers, resp_cookies)

                self.cookies.update({k: v for k, v in norm.cookies.items() if v})
                if norm.status_code in RETRYABLE_STATUS_CODES and attempt < max_retries:
                    await asyncio.sleep(0.45 * (2**attempt) + random.uniform(0.05, 0.2))
                    continue
                return norm
            except Exception as exc:
                last_err = exc
                if attempt < max_retries:
                    await asyncio.sleep(0.45 * (2**attempt))
                    continue
                raise
        raise RuntimeError(f"HTTP request failed: {last_err}")


# ============================================================================
# 3. GARENA SSO AES-256-ECB + DATADOME 403 FALLBACK + CALLBACK TOKEN EXCHANGE
# ============================================================================

_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)


def _xtime(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def _aes256_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    if HAS_CRYPTOGRAPHY:
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return encryptor.update(block) + encryptor.finalize()

    w = [list(key[i : i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        temp = list(w[i - 1])
        if i % 8 == 0:
            temp = [_AES_SBOX[temp[1]] ^ rcon, _AES_SBOX[temp[2]], _AES_SBOX[temp[3]], _AES_SBOX[temp[0]]]
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            temp = [_AES_SBOX[b] for b in temp]
        w.append([w[i - 8][j] ^ temp[j] for j in range(4)])

    state = [block[i] ^ w[i // 4][i % 4] for i in range(16)]
    for rnd in range(1, 15):
        state = [_AES_SBOX[b] for b in state]
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]
        if rnd < 14:
            mixed = []
            for c in range(4):
                s0, s1, s2, s3 = state[c * 4 : c * 4 + 4]
                t = s0 ^ s1 ^ s2 ^ s3
                mixed.extend([
                    s0 ^ t ^ _xtime(s0 ^ s1),
                    s1 ^ t ^ _xtime(s1 ^ s2),
                    s2 ^ t ^ _xtime(s2 ^ s3),
                    s3 ^ t ^ _xtime(s3 ^ s0),
                ])
            state = mixed
        rk = w[rnd * 4 : (rnd + 1) * 4]
        state = [state[i] ^ rk[i // 4][i % 4] for i in range(16)]
    return bytes(state)


def encrypt_garena_sso_password(raw_password: str, v1: str, v2: str) -> str:
    md5_pw = hashlib.md5(raw_password.encode("utf-8")).hexdigest()
    inner = hashlib.md5((md5_pw + v1).encode("utf-8")).hexdigest()
    aes_key = hashlib.sha256((inner + v2).encode("utf-8")).digest()
    return _aes256_ecb_encrypt_block(aes_key, bytes.fromhex(md5_pw)).hex()


def _is_waf_blocked(resp: NormalizedResponse) -> bool:
    return resp.status_code == 403 or any(k in (resp.text or "").lower() for k in ("captcha-delivery.com", "datadome"))


async def authenticate_garena_http(
    garena_id: str = "",
    garena_password: str = "",
    token_or_url: str = "",
    csrf_token: str = "",
    proxy: str = "",
    base_url: str = DEFAULT_ROV_BASE_URL,
    sso_base_url: str = DEFAULT_SSO_BASE_URL,
) -> Dict[str, Any]:
    rov_base = (base_url or DEFAULT_ROV_BASE_URL).rstrip("/")
    sso_base = (sso_base_url or DEFAULT_SSO_BASE_URL).rstrip("/")
    eff_proxy = (proxy or load_preferences().get("global_proxy") or "").strip()
    parsed = extract_auth_material(token_or_url or garena_id, explicit_csrf=csrf_token)

    async with PureHttpClient(proxy=eff_proxy) as client:
        if parsed["jwt_token"]:
            info = inspect_jwt(parsed["jwt_token"])
            if not info.get("valid_structure"):
                return {"ok": False, "blocked_by_waf": False, "status_code": 400, "message": "รูปแบบ JWT Token ไม่ถูกต้อง"}
            if info.get("is_expired"):
                return {"ok": False, "blocked_by_waf": False, "status_code": 401, "message": "JWT Token หมดอายุแล้ว กรุณาใช้ Token ใหม่"}
            eff_id = garena_id.strip() if (garena_id and not extract_clean_jwt(garena_id)) else f"uid_{info.get('uid') or 'rov'}"
            return {
                "ok": True,
                "garena_id": eff_id,
                "jwt_token": parsed["jwt_token"],
                "csrf_token": parsed["csrf_token"],
                "source": "direct_token",
                "proxy": eff_proxy,
                "token_info": info,
            }

        if parsed["access_token"] or parsed["code"]:
            q_param = f"access_token={quote(parsed['access_token'])}" if parsed["access_token"] else f"code={quote(parsed['code'])}"
            cb_resp = await client.request("GET", f"{rov_base}/auth/callback/?{q_param}")
            if _is_waf_blocked(cb_resp):
                return {"ok": False, "blocked_by_waf": True, "status_code": 403, "message": WAF_BLOCK_THAI_MSG}
            jwt_from_cb = extract_clean_jwt(client.cookies.get("jwt_token") or cb_resp.text)
            csrf_from_cb = client.cookies.get("csrf_token") or parsed["csrf_token"]
            if jwt_from_cb:
                info = inspect_jwt(jwt_from_cb)
                eff_id = garena_id.strip() or f"uid_{info.get('uid') or 'rov'}"
                return {
                    "ok": True,
                    "garena_id": eff_id,
                    "jwt_token": jwt_from_cb,
                    "csrf_token": csrf_from_cb,
                    "source": "callback_exchange",
                    "proxy": eff_proxy,
                    "token_info": info,
                }
            return {"ok": False, "blocked_by_waf": False, "status_code": 401, "message": "แลก Token จากลิงก์ /auth/callback/ ไม่สำเร็จ"}

        vault = load_accounts_vault()
        clean_id = (garena_id or "").strip()
        if clean_id and not garena_password:
            saved = next((a for a in vault["accounts"] if a.get("garena_id", "").lower() == clean_id.lower()), None)
            if saved and saved.get("jwt_token"):
                info = inspect_jwt(saved["jwt_token"])
                if info.get("valid_structure") and not info.get("is_expired"):
                    return {
                        "ok": True,
                        "garena_id": saved["garena_id"],
                        "jwt_token": saved["jwt_token"],
                        "csrf_token": saved.get("csrf_token", ""),
                        "source": "vault_session",
                        "proxy": eff_proxy,
                        "token_info": info,
                    }

        if not clean_id or not garena_password:
            return {"ok": False, "blocked_by_waf": False, "status_code": 400, "message": "กรุณากรอก Garena ID และรหัสผ่าน หรือวาง Token/ลิงก์โดยตรง"}

        redirect_uri = f"{rov_base}/auth/callback/"
        pre_resp = await client.request(
            "GET",
            f"{sso_base}/api/prelogin",
            params={"account": clean_id, "format": "json", "id": str(int(time.time() * 1000)), "app_id": OAUTH_APP_ID},
            headers={"Referer": f"{sso_base}/universal/login?app_id={OAUTH_APP_ID}&locale=th-TH"},
        )
        if _is_waf_blocked(pre_resp):
            return {"ok": False, "blocked_by_waf": True, "status_code": 403, "message": WAF_BLOCK_THAI_MSG}
        try:
            pre_data = pre_resp.json()
        except Exception:
            pre_data = {}
        if "error" in pre_data:
            return {"ok": False, "blocked_by_waf": False, "status_code": 401, "message": f"Garena ปฏิเสธการเข้าสู่ระบบ: {pre_data.get('error')}"}

        v1, v2 = str(pre_data.get("v1") or ""), str(pre_data.get("v2") or "")
        if not v1 or not v2:
            return {"ok": False, "blocked_by_waf": True, "status_code": 403, "message": WAF_BLOCK_THAI_MSG}

        enc_pw = encrypt_garena_sso_password(garena_password, v1, v2)
        login_resp = await client.request(
            "GET",
            f"{sso_base}/api/login",
            params={
                "account": clean_id,
                "password": enc_pw,
                "redirect_uri": redirect_uri,
                "format": "json",
                "id": str(pre_data.get("id") or int(time.time() * 1000)),
                "app_id": OAUTH_APP_ID,
            },
            headers={"Referer": f"{sso_base}/universal/login?app_id={OAUTH_APP_ID}&locale=th-TH"},
        )
        if _is_waf_blocked(login_resp):
            return {"ok": False, "blocked_by_waf": True, "status_code": 403, "message": WAF_BLOCK_THAI_MSG}
        try:
            login_data = login_resp.json()
        except Exception:
            login_data = {}
        if login_data.get("error"):
            return {"ok": False, "blocked_by_waf": False, "status_code": 401, "message": f"ไอดีหรือรหัสผ่านไม่ถูกต้อง ({login_data.get('error')})"}

        jwt_tok = extract_clean_jwt(login_data.get("jwt_token") or client.cookies.get("jwt_token") or "")
        if not jwt_tok:
            grant_url = (
                login_data.get("redirect_uri")
                or f"https://{OAUTH_APP_ID}.connect.garena.com/oauth/login?response_type=code&client_id={OAUTH_APP_ID}&redirect_uri={quote(redirect_uri, safe='')}&locale=th-TH&platform=1"
            )
            cb_final = await client.request("GET", grant_url)
            if _is_waf_blocked(cb_final):
                return {"ok": False, "blocked_by_waf": True, "status_code": 403, "message": WAF_BLOCK_THAI_MSG}
            jwt_tok = extract_clean_jwt(client.cookies.get("jwt_token") or cb_final.text)
        if not jwt_tok:
            return {"ok": False, "blocked_by_waf": True, "status_code": 403, "message": WAF_BLOCK_THAI_MSG}

        return {
            "ok": True,
            "garena_id": clean_id,
            "jwt_token": jwt_tok,
            "csrf_token": client.cookies.get("csrf_token") or "",
            "source": "curl_cffi_sso" if HAS_CURL_CFFI else "httpx_sso",
            "proxy": eff_proxy,
            "token_info": inspect_jwt(jwt_tok),
        }


# ============================================================================
# 4. ZERO-AI 40-CHAPTER SOLVER + ROV ACADEMY AUTO-REDEEM ENGINE
# ============================================================================


def strip_html(raw: Optional[str]) -> str:
    if not raw:
        return ""
    txt = re.sub(r"<br\s*/?>", "\n", str(raw), flags=re.IGNORECASE)
    txt = re.sub(r"<[^>]+>", " ", txt)
    return re.sub(r"\s+", " ", html.unescape(txt)).strip()


def load_answers_vault() -> Dict[str, Any]:
    parsed = _read_json(ANSWERS_CACHE_PATH, {})
    return parsed if isinstance(parsed, dict) else {}


class RoVAcademySession:
    def __init__(
        self,
        jwt_token: str,
        csrf_token: str = "",
        base_url: str = DEFAULT_ROV_BASE_URL,
        proxy: str = "",
        cancel_event: Optional[asyncio.Event] = None,
        log_cb: Optional[Callable[[str, str], Any]] = None,
        progress_cb: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> None:
        self.jwt_token = extract_clean_jwt(jwt_token)
        self.csrf_token = (csrf_token or "").strip()
        self.base_url = (base_url or DEFAULT_ROV_BASE_URL).rstrip("/")
        self.proxy = (proxy or "").strip()
        self.cancel_event = cancel_event
        self.log_cb = log_cb
        self.progress_cb = progress_cb

    async def _log(self, msg: str, level: str = "info") -> None:
        if self.log_cb:
            res = self.log_cb(msg, level)
            if asyncio.iscoroutine(res):
                await res

    async def _progress(self, payload: Dict[str, Any]) -> None:
        if self.progress_cb:
            res = self.progress_cb(payload)
            if asyncio.iscoroutine(res):
                await res

    def _headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/",
            "Authorization": f"Bearer {self.jwt_token}",
        }
        if self.csrf_token:
            h["X-CSRF-TOKEN"] = self.csrf_token
        return h

    def _cookies(self) -> Dict[str, str]:
        c = {"jwt_token": self.jwt_token}
        if self.csrf_token:
            c["csrf_token"] = self.csrf_token
        return c

    async def _api(self, client: PureHttpClient, method: str, path: str, json_body: Optional[Any] = None) -> NormalizedResponse:
        client.cookies.update(self._cookies())
        resp = await client.request(method, f"{self.base_url}{path}", headers=self._headers(), json_body=json_body)
        new_csrf = resp.cookies.get("csrf_token") or resp.headers.get("x-csrf-token")
        if new_csrf:
            self.csrf_token = new_csrf.strip()
            client.cookies["csrf_token"] = self.csrf_token
        return resp

    @staticmethod
    def _rank_choices(q_item: Dict[str, Any], ch_obj: Dict[str, Any], ch_cache: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], int]:
        q_txt = strip_html(q_item.get("question"))
        choices = list(q_item.get("choice") or [])
        if not choices:
            return [], 0
        raw_cand = ch_cache.get(q_txt)
        if raw_cand is None:
            for k, v in ch_cache.items():
                if strip_html(k) == q_txt:
                    raw_cand = v
                    break
        cands = [str(x) for x in raw_cand] if isinstance(raw_cand, list) else ([str(raw_cand)] if raw_cand else [])
        lesson_blob = " ".join(
            [strip_html(ch_obj.get("title")), strip_html(ch_obj.get("description"))]
            + [f"{strip_html(s.get('section'))} {strip_html(s.get('description'))}" for s in (ch_obj.get("content") or [])]
        ).lower()
        is_neg = any(w in q_txt for w in ("ไม่ใช่", "ไม่ถูกต้อง", "ไม่ควร", "ไม่สามารถ", "ไม่เหมาะ", "ไม่นิยม", "น้อยที่สุด"))

        scored, matches = [], 0
        for idx, ch in enumerate(choices):
            c_txt = strip_html(str(ch.get("text") or ""))
            score = 0.0
            for r_i, cand in enumerate(cands):
                if c_txt == strip_html(cand):
                    score += 1000.0 - r_i * 120.0
                    matches += 1
                    break
            tokens = [t for t in re.findall(r"[ก-๙a-zA-Z0-9\.]+", c_txt.lower()) if len(t) >= 2]
            if tokens and lesson_blob:
                overlap = (sum(1 for t in tokens if t in lesson_blob) / len(tokens)) * 30.0
                score += -overlap if is_neg else overlap
            if any(p in c_txt for p in ("ถูกทุกข้อ", "ถูกทั้ง", "ข้อ 1 และ 2 ถูก", "ผิดทุกข้อ")):
                score += 18.0
            scored.append((score, -idx, ch))

        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [x[2] for x in scored], matches

    async def solve_all_and_redeem(self, auto_redeem: bool = True, preferred_reward_ids: Optional[List[Any]] = None) -> Dict[str, Any]:
        vault = load_answers_vault()
        redeemed_items: List[Dict[str, Any]] = []
        async with PureHttpClient(cookies=self._cookies(), proxy=self.proxy) as client:
            if not self.csrf_token:
                await self._api(client, "GET", "/")
            u_resp = await self._api(client, "GET", "/api/user")
            if u_resp.status_code != 200:
                return {"ok": False, "error": f"ยืนยันตัวตน /api/user ไม่สำเร็จ (HTTP {u_resp.status_code})"}
            u_data = u_resp.json().get("data") or {}
            completed = {int(x) for x in (u_data.get("chapter_completed") or []) if str(x).isdigit()}
            visited = u_data.get("chapter_visited") or {}
            init_gold, init_silver = int(u_data.get("gold", 0) or 0), int(u_data.get("silver", 0) or 0)

            info_resp = await self._api(client, "GET", "/api/info")
            if info_resp.status_code != 200:
                return {"ok": False, "error": f"ดึงบทเรียน /api/info ไม่สำเร็จ (HTTP {info_resp.status_code})"}

            all_cids = [int(cid) for t in ((info_resp.json().get("data") or {}).get("topics") or []) for cid in (t.get("chapters") or [])]
            pending = [cid for cid in all_cids if cid not in completed]
            total_chapters = len(all_cids) or 40
            passed = questions_answered = gold_earned = silver_earned = 0

            chapters_map: Dict[str, Any] = {}
            if pending:
                ch_resp = await self._api(client, "POST", "/api/chapters", {"chapter_id_list": pending})
                if ch_resp.status_code == 200:
                    chapters_map = (ch_resp.json().get("data") or {}).get("chapters") or {}

            for idx, cid in enumerate(pending, start=1):
                if self.cancel_event and self.cancel_event.is_set():
                    await self._log("⏹️ หยุดทำแบบทดสอบตามคำสั่งผู้ใช้", "warning")
                    break
                ch_obj = chapters_map.get(str(cid)) or {}
                ch_title = ch_obj.get("title") or f"บทที่ {cid}"
                if str(cid) not in visited and cid not in visited:
                    await self._api(client, "POST", "/api/learned", {"id": cid})
                qz_resp = await self._api(client, "POST", "/api/quiz", {"id": cid})
                if qz_resp.status_code != 200:
                    continue
                qz_data = qz_resp.json().get("data")
                quiz_list = (qz_data.get("quiz") or qz_data.get("questions") or []) if isinstance(qz_data, dict) else (qz_data if isinstance(qz_data, list) else [])
                if not quiz_list:
                    continue

                ch_cache = vault.get(str(cid)) if isinstance(vault.get(str(cid)), dict) else {}
                ranked_per_q, match_counts = [], []
                for q_item in quiz_list:
                    ranked, m_cnt = self._rank_choices(q_item, ch_obj, ch_cache)
                    if ranked:
                        ranked_per_q.append(ranked)
                        match_counts.append(m_cnt)
                if len(ranked_per_q) != len(quiz_list):
                    continue

                candidate_vectors = [[r[0] for r in ranked_per_q]]
                multi_qis = [qi for qi, cnt in enumerate(match_counts) if cnt >= 2 and len(ranked_per_q[qi]) >= 2]
                if multi_qis:
                    for combo in product(*[range(min(3, len(ranked_per_q[qi]))) for qi in multi_qis]):
                        vec = list(candidate_vectors[0])
                        for qi, r_i in zip(multi_qis, combo):
                            vec[qi] = ranked_per_q[qi][r_i]
                        candidate_vectors.append(vec)
                for alt in (1, 2, 3):
                    for qi in range(len(quiz_list)):
                        if alt < len(ranked_per_q[qi]):
                            vec = list(candidate_vectors[0])
                            vec[qi] = ranked_per_q[qi][alt]
                            candidate_vectors.append(vec)

                seen_vecs: Set[Tuple[str, ...]] = set()
                for vec in candidate_vectors:
                    key = tuple(str(c["id"]) for c in vec)
                    if key in seen_vecs:
                        continue
                    seen_vecs.add(key)
                    ans_resp = await self._api(client, "POST", "/api/answer", {"id": cid, "answers": [c["id"] for c in vec]})
                    ans_data = (ans_resp.json().get("data") or {}) if ans_resp.status_code == 200 else {}
                    if ans_resp.status_code == 200 and ans_data.get("quiz_status"):
                        g_add = int(ans_data.get("gold") if ans_data.get("gold") is not None else (ch_obj.get("gold") or 0))
                        s_add = int(ans_data.get("silver") if ans_data.get("silver") is not None else (ch_obj.get("silver") or 0))
                        passed += 1
                        questions_answered += len(quiz_list)
                        gold_earned += g_add
                        silver_earned += s_add
                        await self._log(f"✅ ผ่านบทที่ {cid}: {ch_title} (+{g_add} Gold, +{s_add} Silver)", "success")
                        break

                await self._progress({
                    "done_chapters": len(completed) + passed,
                    "total_chapters": total_chapters,
                    "passed_chapters": passed,
                    "questions_answered": questions_answered,
                    "gold_earned": gold_earned,
                    "silver_earned": silver_earned,
                    "current_text": f"ตอบบทที่ {cid} ({idx}/{len(pending)})",
                })

            cur_gold, cur_silver = init_gold + gold_earned, init_silver + silver_earned
            if auto_redeem and not (self.cancel_event and self.cancel_event.is_set()):
                rw_resp = await self._api(client, "GET", "/api/rewards")
                if rw_resp.status_code == 200:
                    rewards = (rw_resp.json().get("data") or {}).get("rewards") or []
                    pref_set = {str(x) for x in (preferred_reward_ids or [])}
                    for rw in rewards:
                        rid = rw.get("id")
                        if rid is None or (pref_set and str(rid) not in pref_set) or rw.get("redeemed") or rw.get("is_redeemed"):
                            continue
                        cost_g, cost_s = int(rw.get("gold", 0) or 0), int(rw.get("silver", 0) or 0)
                        if cur_gold >= cost_g and cur_silver >= cost_s and (cost_g > 0 or cost_s > 0):
                            rd_resp = await self._api(client, "POST", "/api/redeem", {"id": rid})
                            if rd_resp.status_code == 200 and rd_resp.json().get("status") == "OK":
                                cur_gold -= cost_g
                                cur_silver -= cost_s
                                item_info = {"id": rid, "title": rw.get("title") or rw.get("name") or f"Reward #{rid}", "gold_cost": cost_g, "silver_cost": cost_s}
                                redeemed_items.append(item_info)
                                await self._log(f"🎁 แลกรางวัลสำเร็จ: {item_info['title']}", "success")

            return {
                "ok": True,
                "cancelled": bool(self.cancel_event and self.cancel_event.is_set()),
                "total_chapters": total_chapters,
                "completed_chapters": len(completed) + passed,
                "passed_chapters": passed,
                "questions_answered": questions_answered,
                "gold_earned": gold_earned,
                "silver_earned": silver_earned,
                "user_gold": cur_gold,
                "user_silver": cur_silver,
                "rewards_redeemed": len(redeemed_items),
                "redeemed_items": redeemed_items,
                "csrf_token": self.csrf_token,
            }


# ============================================================================
# 5. ASYNCIO.QUEUE BACKGROUND WORKER POOL & REAL-TIME WEBSOCKET HUB
# ============================================================================


class QueueWorkerManager:
    def __init__(self, worker_count: int = DEFAULT_WORKER_COUNT) -> None:
        self.worker_count = worker_count
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.jobs: Dict[str, Dict[str, Any]] = _read_json(JOBS_STATE_PATH, {})
        if not isinstance(self.jobs, dict):
            self.jobs = {}
        self.cancel_events: Dict[str, asyncio.Event] = {}
        self.ws_subscribers: Dict[str, Set[WebSocket]] = {}
        self._workers: List[asyncio.Task[None]] = []
        self.running_jobs_count = 0

    async def start(self) -> None:
        for idx in range(self.worker_count):
            self._workers.append(asyncio.create_task(self._worker_loop(idx), name=f"rov-worker-{idx}"))

    async def stop(self) -> None:
        for ev in self.cancel_events.values():
            ev.set()
        for t in self._workers:
            t.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    def telemetry(self) -> Dict[str, int]:
        return {"running": self.running_jobs_count, "queued": self.queue.qsize()}

    def _persist(self) -> None:
        _write_json(JOBS_STATE_PATH, dict(list(self.jobs.items())[-25:]))

    async def broadcast(self, job_id: str, event_type: str = "update") -> None:
        job = self.jobs.get(job_id)
        if not job:
            return
        payload = {"type": event_type, "job": job, "telemetry": self.telemetry()}
        dead: List[WebSocket] = []
        for ws in list(self.ws_subscribers.get(job_id, set())):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.ws_subscribers.get(job_id, set()).discard(ws)

    async def enqueue(self, garena_ids: List[str], base_url: str = DEFAULT_ROV_BASE_URL) -> Dict[str, Any]:
        job_id = uuid.uuid4().hex[:8]
        now_str = datetime.now().strftime("%d/%m %H:%M")
        job = {
            "job_id": job_id,
            "ref_code": f"#{job_id}",
            "status": "queued",
            "step": 1,
            "created_at": now_str,
            "updated_at": now_str,
            "base_url": base_url,
            "accounts": garena_ids,
            "remaining_accounts": len(garena_ids),
            "percent": 0,
            "progress_label": "รอคิวประมวลผล...",
            "summary": {"questions_added": 0, "chapters_passed": 0, "silver_earned": 0, "gold_earned": 0, "rewards_redeemed": 0, "redeemed_items": []},
            "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] เข้าคิวเรียบร้อย ({len(garena_ids)} บัญชี)"],
        }
        self.jobs[job_id] = job
        self.cancel_events[job_id] = asyncio.Event()
        self._persist()
        await self.queue.put(job_id)
        await self.broadcast(job_id, "queued")
        return job

    async def cancel(self, job_id: str) -> Optional[Dict[str, Any]]:
        job = self.jobs.get(job_id)
        if not job:
            return None
        if job_id in self.cancel_events:
            self.cancel_events[job_id].set()
        if job["status"] == "queued":
            job["status"] = "cancelled"
            job["step"] = 4
            job["progress_label"] = "ยกเลิกคิวงานแล้ว"
            self._persist()
            await self.broadcast(job_id, "cancelled")
        return job

    def get_active_or_latest(self) -> Optional[Dict[str, Any]]:
        for jid in reversed(list(self.jobs.keys())):
            if self.jobs[jid].get("status") in ("running", "queued"):
                return self.jobs[jid]
        return self.jobs[list(self.jobs.keys())[-1]] if self.jobs else None

    async def _worker_loop(self, worker_idx: int) -> None:
        while True:
            job_id = await self.queue.get()
            try:
                job = self.jobs.get(job_id)
                if not job or job.get("status") == "cancelled":
                    continue
                self.running_jobs_count += 1
                await self._execute_job(job_id, job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception(f"Worker-{worker_idx} job {job_id} error: {exc}")
                if job_id in self.jobs:
                    self.jobs[job_id]["status"] = "failed"
                    self.jobs[job_id]["progress_label"] = "เกิดข้อผิดพลาดระหว่างประมวลผล"
                    self._persist()
                    await self.broadcast(job_id, "failed")
            finally:
                self.running_jobs_count = max(0, self.running_jobs_count - 1)
                self.queue.task_done()

    async def _execute_job(self, job_id: str, job: Dict[str, Any]) -> None:
        cancel_ev = self.cancel_events.setdefault(job_id, asyncio.Event())
        prefs = load_preferences()
        vault = load_accounts_vault()
        acc_lookup = {str(a.get("garena_id", "")).lower(): a for a in vault["accounts"]}
        target_ids: List[str] = job.get("accounts") or []
        total_accs = max(1, len(target_ids))

        async def add_log(msg: str, _lvl: str = "info") -> None:
            job["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            job["logs"] = job["logs"][-120:]
            job["updated_at"] = datetime.now().strftime("%d/%m %H:%M")
            await self.broadcast(job_id, "log")

        job["status"] = "running"
        for idx, gid in enumerate(target_ids):
            if cancel_ev.is_set():
                break
            job["remaining_accounts"] = len(target_ids) - idx
            job["step"] = 2
            job["progress_label"] = f"กำลังเข้าสู่ระบบ {mask_account_name(gid)}..."
            self._persist()
            await self.broadcast(job_id, "progress")

            acc = acc_lookup.get(gid.lower()) or {"garena_id": gid}
            jwt_tok, csrf_tok = str(acc.get("jwt_token") or ""), str(acc.get("csrf_token") or "")
            acc_proxy = str(acc.get("proxy") or prefs.get("global_proxy") or "")

            if not inspect_jwt(jwt_tok).get("valid_structure") or inspect_jwt(jwt_tok).get("is_expired"):
                auth_res = await authenticate_garena_http(
                    garena_id=gid,
                    garena_password=str(acc.get("garena_password") or ""),
                    proxy=acc_proxy,
                    base_url=job.get("base_url") or DEFAULT_ROV_BASE_URL,
                )
                if not auth_res.get("ok"):
                    await add_log(f"❌ [{mask_account_name(gid)}] {auth_res.get('message')}", "error")
                    continue
                jwt_tok, csrf_tok = auth_res["jwt_token"], auth_res.get("csrf_token") or ""
                upsert_account(gid, jwt_token=jwt_tok, csrf_token=csrf_tok, activate=False)

            job["step"] = 3
            job["progress_label"] = f"กำลังทำแบบทดสอบ ({mask_account_name(gid)})..."
            await self.broadcast(job_id, "progress")

            async def on_quiz_progress(p: Dict[str, Any]) -> None:
                ch_ratio = p.get("done_chapters", 0) / max(1, p.get("total_chapters", 40))
                job["percent"] = min(99, max(1, int(((idx + ch_ratio) / total_accs) * 100)))
                job["progress_label"] = f"{job['percent']}% · บทเรียน {p.get('done_chapters', 0)}/{p.get('total_chapters', 40)} ({mask_account_name(gid)})"
                await self.broadcast(job_id, "progress")

            session = RoVAcademySession(
                jwt_token=jwt_tok,
                csrf_token=csrf_tok,
                base_url=job.get("base_url") or DEFAULT_ROV_BASE_URL,
                proxy=acc_proxy,
                cancel_event=cancel_ev,
                log_cb=add_log,
                progress_cb=on_quiz_progress,
            )
            res = await session.solve_all_and_redeem(
                auto_redeem=bool(prefs.get("auto_redeem_enabled", True)),
                preferred_reward_ids=prefs.get("preferred_reward_ids"),
            )
            if not res.get("ok"):
                await add_log(f"⚠️ [{mask_account_name(gid)}] {res.get('error')}", "warning")
                continue

            upsert_account(
                gid,
                jwt_token=jwt_tok,
                csrf_token=res.get("csrf_token") or csrf_tok,
                gold=res.get("user_gold", 0),
                silver=res.get("user_silver", 0),
                completed_chapters=res.get("completed_chapters", 0),
                activate=False,
            )
            job["summary"]["questions_added"] += int(res.get("questions_answered", 0))
            job["summary"]["chapters_passed"] += int(res.get("passed_chapters", 0))
            job["summary"]["gold_earned"] += int(res.get("gold_earned", 0))
            job["summary"]["silver_earned"] += int(res.get("silver_earned", 0))
            job["summary"]["rewards_redeemed"] += int(res.get("rewards_redeemed", 0))
            job["summary"]["redeemed_items"].extend(res.get("redeemed_items") or [])

        job["remaining_accounts"] = 0
        job["step"] = 4
        job["status"] = "cancelled" if cancel_ev.is_set() else "completed"
        job["percent"] = 100 if job["status"] == "completed" else job["percent"]
        job["updated_at"] = datetime.now().strftime("%d/%m %H:%M")
        job["progress_label"] = (
            "หยุดการทำงานตามคำสั่งผู้ใช้"
            if cancel_ev.is_set()
            else f"เสร็จสมบูรณ์! (+{job['summary']['gold_earned']} Gold, +{job['summary']['silver_earned']} Silver)"
        )
        self._persist()

        history = _read_json(HISTORY_PATH, [])
        if not isinstance(history, list):
            history = []
        history.insert(0, {
            "job_id": job_id,
            "ref_code": job["ref_code"],
            "timestamp": job["updated_at"],
            "status": job["status"],
            "accounts": [mask_account_name(x) for x in target_ids],
            "summary": job["summary"],
        })
        _write_json(HISTORY_PATH, history[:40])
        await self.broadcast(job_id, "completed")


WORKER_MANAGER = QueueWorkerManager()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_dirs()
    await WORKER_MANAGER.start()
    yield
    await WORKER_MANAGER.stop()


# ============================================================================
# 6. FASTAPI APPLICATION, SECURITY GUARDS & ROUTES
# ============================================================================

app = FastAPI(title="Garena RoV Academy Auto-Solver & Queue Worker", version="3.0.0", lifespan=lifespan)

GENERIC_ERROR_BODY: Dict[str, Any] = {
    "ok": False,
    "error": "Internal server error",
    "message": "An unexpected error occurred. Please try again later.",
}

_SECRET_KV_RE = re.compile(
    r"(?i)(jwt_token|csrf_token|access_token|garena_password|password|token|authorization)\s*([=:])\s*([^\s&;\"',}]+)"
)


def _redact_sensitive(raw: Any) -> str:
    text = str(raw or "")
    text = JWT_REGEX.sub("[REDACTED_JWT]", text)
    text = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED]", text)
    return _SECRET_KV_RE.sub(r"\1\2[REDACTED]", text)


@app.middleware("http")
async def global_security_and_error_guard(request: Request, call_next: Callable[[Request], Any]) -> Response:
    try:
        response: Response = await call_next(request)
    except Exception as exc:
        logger.error("Unhandled API failure on %s %s: %s", request.method, request.url.path, _redact_sensitive(exc))
        response = JSONResponse(status_code=500, content=dict(GENERIC_ERROR_BODY))
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


@app.exception_handler(HTTPException)
async def sanitized_http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    if exc.status_code >= 500:
        return JSONResponse(status_code=500, content=dict(GENERIC_ERROR_BODY))
    safe_detail = _redact_sensitive(exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"ok": False, "detail": safe_detail, "message": safe_detail})


@app.exception_handler(RequestValidationError)
async def sanitized_validation_exception_handler(_request: Request, _exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"ok": False, "error": "Invalid request", "message": "Request validation failed."})


@app.exception_handler(Exception)
async def global_unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, _redact_sensitive(exc))
    return JSONResponse(status_code=500, content=dict(GENERIC_ERROR_BODY))


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class LoginPayload(BaseModel):
    garena_id: Optional[str] = ""
    garena_password: Optional[str] = ""
    token_or_url: Optional[str] = ""
    jwt_token: Optional[str] = ""
    csrf_token: Optional[str] = ""
    proxy: Optional[str] = ""
    base_url: Optional[str] = None
    sso_base_url: Optional[str] = None
    auto_start: Optional[bool] = False


class BatchAccountsPayload(BaseModel):
    raw_text: str = Field(..., description="One account per line: username:password or username|token")
    proxy: Optional[str] = ""


class AccountSelectPayload(BaseModel):
    garena_id: Optional[str] = None
    selected: Optional[bool] = None
    select_all: Optional[bool] = None
    set_active: Optional[bool] = False


class EnqueuePayload(BaseModel):
    garena_ids: Optional[List[str]] = None
    base_url: Optional[str] = None


class PreferencesPayload(BaseModel):
    auto_redeem_enabled: Optional[bool] = None
    preferred_reward_ids: Optional[List[Union[int, str]]] = None
    global_proxy: Optional[str] = None


@app.get("/")
async def serve_ui() -> Response:
    index_file = STATIC_DIR / "index.html"
    return FileResponse(str(index_file)) if index_file.exists() else HTMLResponse("<h1>Garena RoV Bot v3.0 API Ready</h1>")


@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    vault = load_answers_vault()
    return {
        "status": "ok",
        "version": "3.0.0",
        "tls_engine": "curl_cffi (chrome)" if HAS_CURL_CFFI else "httpx (fallback)",
        "verified_chapters": len(vault),
        "queue": WORKER_MANAGER.telemetry(),
        "timestamp": int(time.time()),
    }


@app.post("/api/login")
@app.post("/login")
async def login_endpoint(payload: LoginPayload) -> JSONResponse:
    token_input = (payload.token_or_url or payload.jwt_token or "").strip()
    auth_res = await authenticate_garena_http(
        garena_id=payload.garena_id or "",
        garena_password=payload.garena_password or "",
        token_or_url=token_input,
        csrf_token=payload.csrf_token or "",
        proxy=payload.proxy or "",
        base_url=payload.base_url or DEFAULT_ROV_BASE_URL,
        sso_base_url=payload.sso_base_url or DEFAULT_SSO_BASE_URL,
    )
    if not auth_res.get("ok"):
        code = int(auth_res.get("status_code") or (403 if auth_res.get("blocked_by_waf") else 401))
        return JSONResponse(status_code=code, content=auth_res)

    try:
        vault_view = upsert_account(
            garena_id=auth_res["garena_id"],
            jwt_token=auth_res["jwt_token"],
            csrf_token=auth_res.get("csrf_token") or "",
            garena_password=payload.garena_password or "",
            proxy=payload.proxy or "",
            selected=True,
            activate=True,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "message": str(exc)})

    return JSONResponse(
        status_code=200,
        content={
            **auth_res,
            "vault": vault_view,
            "oauth_helper_url": (
                f"https://{OAUTH_APP_ID}.connect.garena.com/oauth/login?response_type=code"
                f"&client_id={OAUTH_APP_ID}&redirect_uri={quote(DEFAULT_ROV_BASE_URL + '/auth/callback/', safe='')}"
                f"&locale=th-TH&platform=1"
            ),
        },
    )


@app.get("/api/auth/me")
async def get_auth_me() -> JSONResponse:
    vault = load_accounts_vault()
    active_id = vault.get("active_garena_id") or ""
    acc = next((a for a in vault["accounts"] if a.get("garena_id") == active_id), None)
    if not acc and vault["accounts"]:
        acc = vault["accounts"][0]
    if not acc:
        return JSONResponse(
            status_code=200,
            content={"ok": True, "authenticated": False, "user": None},
            headers={"Cache-Control": "no-store"},
        )

    jwt_info = inspect_jwt(acc.get("jwt_token"))
    has_valid_session = bool(jwt_info.get("valid_structure") and not jwt_info.get("is_expired"))
    gid = str(acc.get("garena_id") or "")
    safe_user = {
        "garena_id": gid,
        "masked_id": mask_account_name(gid),
        "uid": jwt_info.get("uid"),
        "has_valid_session": has_valid_session,
        "remaining_seconds": jwt_info.get("remaining_seconds"),
        "gold": int(acc.get("gold", 0) or 0),
        "silver": int(acc.get("silver", 0) or 0),
        "completed_chapters": int(acc.get("completed_chapters", 0) or 0),
        "updated_at": acc.get("updated_at"),
    }
    return JSONResponse(
        status_code=200,
        content={"ok": True, "authenticated": True, "user": safe_user},
        headers={"Cache-Control": "no-store"},
    )


@app.delete("/api/session")
async def delete_session_endpoint() -> JSONResponse:
    _write_json(ACCOUNTS_VAULT_PATH, {"active_garena_id": "", "accounts": []})
    if ACCOUNTS_VAULT_PATH.exists():
        try:
            ACCOUNTS_VAULT_PATH.unlink()
        except OSError:
            pass
    MOCK_TASKS.clear()
    MOCK_ANSWERS.clear()
    resp = JSONResponse(
        status_code=200,
        content={"ok": True, "authenticated": False, "message": "Session cleared successfully"},
        headers={"Cache-Control": "no-store"},
    )
    resp.delete_cookie(key="jwt_token", path="/", httponly=True, samesite="lax")
    resp.delete_cookie(key="csrf_token", path="/", httponly=False, samesite="lax")
    return resp


@app.get("/api/accounts")
async def get_accounts() -> Dict[str, Any]:
    return {
        **_public_vault_view(load_accounts_vault()),
        "queue": WORKER_MANAGER.telemetry(),
        "oauth_helper_url": (
            f"https://{OAUTH_APP_ID}.connect.garena.com/oauth/login?response_type=code"
            f"&client_id={OAUTH_APP_ID}&redirect_uri={quote(DEFAULT_ROV_BASE_URL + '/auth/callback/', safe='')}"
            f"&locale=th-TH&platform=1"
        ),
    }


@app.post("/api/accounts/batch")
async def batch_add_accounts(payload: BatchAccountsPayload) -> Dict[str, Any]:
    added = 0
    errors: List[str] = []
    for raw_line in payload.raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "|" in line:
                gid, tok_raw = [x.strip() for x in line.split("|", 1)]
                mat = extract_auth_material(tok_raw)
                upsert_account(gid, jwt_token=mat["jwt_token"], csrf_token=mat["csrf_token"], proxy=payload.proxy or "")
                added += 1
            elif ":" in line:
                gid, pw = [x.strip() for x in line.split(":", 1)]
                upsert_account(gid, garena_password=pw, proxy=payload.proxy or "")
                added += 1
            elif extract_clean_jwt(line):
                tok = extract_clean_jwt(line)
                info = inspect_jwt(tok)
                upsert_account(f"uid_{info.get('uid') or added + 1}", jwt_token=tok, proxy=payload.proxy or "")
                added += 1
        except ValueError as exc:
            errors.append(str(exc))
            break
    return {"ok": added > 0, "added": added, "errors": errors, "vault": _public_vault_view(load_accounts_vault())}


@app.post("/api/accounts/select")
async def update_account_selection(payload: AccountSelectPayload) -> Dict[str, Any]:
    vault = load_accounts_vault()
    if payload.select_all is not None:
        for acc in vault["accounts"]:
            acc["selected"] = bool(payload.select_all)
    elif payload.garena_id:
        for acc in vault["accounts"]:
            if str(acc.get("garena_id", "")).lower() == payload.garena_id.lower():
                if payload.selected is not None:
                    acc["selected"] = bool(payload.selected)
                if payload.set_active:
                    vault["active_garena_id"] = acc["garena_id"]
    _write_json(ACCOUNTS_VAULT_PATH, vault)
    return _public_vault_view(vault)


@app.delete("/api/accounts/{garena_id}")
async def delete_account(garena_id: str) -> Dict[str, Any]:
    vault = load_accounts_vault()
    vault["accounts"] = [a for a in vault["accounts"] if str(a.get("garena_id", "")).lower() != garena_id.lower()]
    if str(vault.get("active_garena_id", "")).lower() == garena_id.lower():
        vault["active_garena_id"] = vault["accounts"][0]["garena_id"] if vault["accounts"] else ""
    _write_json(ACCOUNTS_VAULT_PATH, vault)
    return _public_vault_view(vault)


@app.post("/api/jobs/enqueue")
async def enqueue_solver_job(payload: EnqueuePayload) -> Dict[str, Any]:
    vault = load_accounts_vault()
    selected_ids = payload.garena_ids or [a["garena_id"] for a in vault["accounts"] if a.get("selected", True)]
    if not selected_ids:
        raise HTTPException(status_code=400, detail="กรุณาเลือกอย่างน้อย 1 บัญชีเพื่อเริ่มทำแบบทดสอบ")
    job = await WORKER_MANAGER.enqueue(selected_ids, base_url=payload.base_url or DEFAULT_ROV_BASE_URL)
    return {"ok": True, "job": job, "telemetry": WORKER_MANAGER.telemetry()}


@app.get("/api/jobs/active")
async def get_active_job() -> Dict[str, Any]:
    return {"job": WORKER_MANAGER.get_active_or_latest(), "telemetry": WORKER_MANAGER.telemetry()}


MOCK_TASKS: Dict[str, Dict[str, Any]] = {}
_MOCK_TASK_REFS: Set[asyncio.Task[None]] = set()
MOCK_STATES: Tuple[str, str, str, str] = ("queued", "logging_in", "testing", "done")


async def _run_mock_bot_task(task_id: str) -> None:
    for next_state in MOCK_STATES[1:]:
        await asyncio.sleep(2.0)
        task = MOCK_TASKS.get(task_id)
        if not task:
            return
        task["status"] = next_state
        task["updated_at"] = int(time.time())


@app.post("/api/start-bot")
async def start_bot_endpoint(payload: LoginPayload) -> Dict[str, Any]:
    task_id = uuid.uuid4().hex[:12]
    now_ts = int(time.time())
    MOCK_TASKS[task_id] = {
        "task_id": task_id,
        "status": "queued",
        "garena_id": (payload.garena_id or "").strip(),
        "auto_start": bool(payload.auto_start),
        "created_at": now_ts,
        "updated_at": now_ts,
    }
    bg_task = asyncio.create_task(_run_mock_bot_task(task_id))
    _MOCK_TASK_REFS.add(bg_task)
    bg_task.add_done_callback(_MOCK_TASK_REFS.discard)
    return {"task_id": task_id, "status": "queued"}


@app.get("/api/status/{task_id}")
async def get_task_status(task_id: str) -> Dict[str, Any]:
    mock_task = MOCK_TASKS.get(task_id)
    if mock_task:
        return {"task_id": task_id, "status": mock_task["status"], "updated_at": mock_task["updated_at"]}
    job = WORKER_MANAGER.jobs.get(task_id)
    if not job:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task_id, "status": job.get("status", "queued"), "job": job}


MOCK_QUESTIONS: List[Dict[str, Any]] = [
    {"id": 1, "question": "ฮีโร่ตัวใดมักอยู่ในเลน Abyssal Dragon?", "options": ["Nakroth (ป่า)", "Yorn (แครี่)", "Maloch (ออฟเลน)", "Krixi (เมจ)"]},
    {"id": 2, "question": "สกิลชาเลนเจอร์ใด สามารถใช้สังหาร Dark Slayer ได้?", "options": ["Flicker", "Execute", "Punish", "Purify"]},
    {"id": 3, "question": "หากต้องการเพิ่มประสิทธิภาพในการป้องกัน ควรใส่รูนสีอะไร?", "options": ["สีแดง", "สีม่วง", "สีเขียว", "สีทอง"]},
]
MOCK_ANSWERS: List[Dict[str, Any]] = []


class BotAnswerPayload(BaseModel):
    task_id: str
    answer: Union[str, int]


@app.get("/api/questions/random")
async def get_random_question() -> Dict[str, Any]:
    selected = random.choice(MOCK_QUESTIONS)
    return {"id": selected["id"], "question": selected["question"], "options": list(selected["options"])}


@app.post("/api/bot/answer")
async def submit_bot_answer(payload: BotAnswerPayload) -> Dict[str, Any]:
    entry = {"task_id": payload.task_id, "answer": payload.answer, "submitted_at": int(time.time())}
    MOCK_ANSWERS.append(entry)
    if payload.task_id in MOCK_TASKS:
        MOCK_TASKS[payload.task_id].setdefault("answers", []).append(entry)
    return {"ok": True, "message": "Answer submitted successfully", "task_id": payload.task_id, "answer": payload.answer}


@app.post("/api/jobs/{job_id}/stop")
async def stop_job_endpoint(job_id: str) -> Dict[str, Any]:
    job = await WORKER_MANAGER.cancel(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="ไม่พบรหัสงานนี้")
    return {"ok": True, "job": job}


@app.get("/api/preferences")
async def get_preferences_endpoint() -> Dict[str, Any]:
    return load_preferences()


@app.post("/api/preferences")
async def update_preferences_endpoint(payload: PreferencesPayload) -> Dict[str, Any]:
    return save_preferences(payload.model_dump(exclude_none=True))


@app.get("/api/rewards")
async def list_rov_rewards() -> Dict[str, Any]:
    vault = load_accounts_vault()
    active_id = vault.get("active_garena_id")
    acc = next((a for a in vault["accounts"] if a.get("garena_id") == active_id), None)
    if not acc and vault["accounts"]:
        acc = vault["accounts"][0]
    if not acc or not acc.get("jwt_token"):
        return {"ok": True, "rewards": [], "prefs": load_preferences()}

    prefs = load_preferences()
    proxy = str(acc.get("proxy") or prefs.get("global_proxy") or "")
    async with PureHttpClient(cookies={"jwt_token": acc["jwt_token"]}, proxy=proxy) as client:
        resp = await client.request(
            "GET",
            f"{DEFAULT_ROV_BASE_URL}/api/rewards",
            headers={"Authorization": f"Bearer {acc['jwt_token']}", "Accept": "application/json"},
        )
        rewards = ((resp.json().get("data") or {}).get("rewards") or []) if resp.status_code == 200 else []
    return {"ok": True, "rewards": rewards, "prefs": prefs}


@app.get("/api/history")
async def get_history_endpoint() -> Dict[str, Any]:
    hist = _read_json(HISTORY_PATH, [])
    return {"history": hist if isinstance(hist, list) else []}


@app.get("/api/vault")
async def get_answers_vault_endpoint() -> Dict[str, Any]:
    vault = load_answers_vault()
    chapters = [
        {"chapter_id": cid, "count": len(vault[cid]), "qa": vault[cid]}
        for cid in sorted(vault.keys(), key=lambda x: int(x) if str(x).isdigit() else 999)
        if isinstance(vault[cid], dict)
    ]
    return {"total_chapters": len(chapters), "chapters": chapters}


@app.websocket("/ws/jobs/{job_id}")
async def job_websocket(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    WORKER_MANAGER.ws_subscribers.setdefault(job_id, set()).add(websocket)
    try:
        job = WORKER_MANAGER.jobs.get(job_id)
        if job:
            await websocket.send_json({"type": "snapshot", "job": job, "telemetry": WORKER_MANAGER.telemetry()})
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong", "telemetry": WORKER_MANAGER.telemetry()})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        WORKER_MANAGER.ws_subscribers.get(job_id, set()).discard(websocket)
