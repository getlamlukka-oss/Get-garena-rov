import base64
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SESSIONS_DIR = DATA_DIR / "sessions"
ANSWERS_CACHE_PATH = DATA_DIR / "answers_cache.json"
ACTIVE_SESSION_PATH = DATA_DIR / "active_session.json"
HISTORY_PATH = DATA_DIR / "run_history.json"

DEFAULT_ROV_BASE_URL = "https://academy.rov.in.th"
JWT_REGEX = re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def get_rov_base_url(override: Optional[str] = None) -> str:
    raw = (override or os.environ.get("ROV_ACADEMY_BASE_URL") or DEFAULT_ROV_BASE_URL).strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid RoV Academy base URL: {raw}")
    return raw.rstrip("/")


def extract_clean_jwt(raw: Optional[str]) -> str:
    """Extracts a clean 3-part JWT from raw string, URL (?token=...), Cookie header, or JSON."""
    if not raw or not isinstance(raw, str):
        return ""
    text = raw.strip()
    m = JWT_REGEX.search(text)
    if m:
        return m.group(1)
    return text


def _b64url_decode_json(segment: str) -> Optional[Dict[str, Any]]:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(raw.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def inspect_jwt(token: Optional[str]) -> Dict[str, Any]:
    cleaned = extract_clean_jwt(token)
    if not cleaned:
        return {"valid_structure": False, "is_expired": False, "remaining_seconds": None}
    parts = cleaned.split(".")
    if len(parts) != 3:
        return {"valid_structure": False, "is_expired": False, "remaining_seconds": None}

    header = _b64url_decode_json(parts[0]) or {}
    payload = _b64url_decode_json(parts[1]) or {}
    if not header or not payload:
        return {"valid_structure": False, "is_expired": False, "remaining_seconds": None}

    exp = payload.get("exp")
    now_ts = int(time.time())
    is_expired = isinstance(exp, (int, float)) and exp > 0 and now_ts >= int(exp)
    rem = (int(exp) - now_ts) if isinstance(exp, (int, float)) and exp > 0 else None

    return {
        "valid_structure": True,
        "alg": header.get("alg", "HS256"),
        "exp": int(exp) if isinstance(exp, (int, float)) else None,
        "is_expired": is_expired,
        "remaining_seconds": rem,
        "uid": payload.get("uid") or payload.get("sub") or payload.get("id"),
        "preview": f"{cleaned[:12]}...{cleaned[-8:]}" if len(cleaned) > 24 else "***",
    }


def _safe_account_slug(garena_id: Optional[str]) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "_", (garena_id or "").strip().lower())
    return cleaned or "default"


def get_account_session_path(garena_id: Optional[str] = None) -> Path:
    ensure_dirs()
    if not garena_id or not garena_id.strip():
        return ACTIVE_SESSION_PATH
    return SESSIONS_DIR / f"session_{_safe_account_slug(garena_id)}.json"


def save_session(
    jwt_token: str,
    csrf_token: Optional[str] = None,
    garena_id: Optional[str] = None,
    cookies_list: Optional[List[Dict[str, Any]]] = None,
) -> None:
    ensure_dirs()
    clean_jwt = extract_clean_jwt(jwt_token)
    if not clean_jwt:
        return
    clean_id = (garena_id or "").strip() or None
    payload = {
        "garena_id": clean_id,
        "jwt_token": clean_jwt,
        "csrf_token": (csrf_token or "").strip() or None,
        "updated_at": int(time.time()),
        "cookies": cookies_list or [],
    }
    ACTIVE_SESSION_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if clean_id:
        acc_path = get_account_session_path(clean_id)
        acc_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_session(garena_id: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    ensure_dirs()
    candidates: List[Path] = []
    if garena_id and garena_id.strip():
        candidates.append(get_account_session_path(garena_id))
    candidates.append(ACTIVE_SESSION_PATH)

    for path in candidates:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        saved_id = (data.get("garena_id") or (data.get("_meta") or {}).get("garena_id") or "").strip() or None
        if garena_id and garena_id.strip() and saved_id and saved_id.lower() != garena_id.strip().lower():
            continue

        jwt_tok = extract_clean_jwt(data.get("jwt_token"))
        csrf_tok = (data.get("csrf_token") or "").strip() or None

        if not jwt_tok and isinstance(data.get("cookies"), list):
            for c in data["cookies"]:
                if c.get("name") == "jwt_token" and c.get("value"):
                    jwt_tok = extract_clean_jwt(c["value"])
                elif c.get("name") == "csrf_token" and c.get("value"):
                    csrf_tok = str(c["value"]).strip()

        if jwt_tok:
            claims = inspect_jwt(jwt_tok)
            if claims.get("valid_structure") and not claims.get("is_expired"):
                return jwt_tok, csrf_tok, saved_id

    env_jwt = extract_clean_jwt(os.environ.get("ROV_JWT_TOKEN"))
    if env_jwt:
        claims = inspect_jwt(env_jwt)
        if claims.get("valid_structure") and not claims.get("is_expired"):
            return env_jwt, (os.environ.get("ROV_CSRF_TOKEN") or "").strip() or None, "env"

    return None, None, None


def clear_sessions() -> None:
    ensure_dirs()
    if ACTIVE_SESSION_PATH.exists():
        try:
            ACTIVE_SESSION_PATH.unlink()
        except Exception:
            pass
    for f in SESSIONS_DIR.glob("session_*.json"):
        try:
            f.unlink()
        except Exception:
            pass


def list_saved_accounts() -> List[Dict[str, Any]]:
    ensure_dirs()
    accounts: List[Dict[str, Any]] = []
    seen = set()
    for f in sorted(list(SESSIONS_DIR.glob("session_*.json")) + [ACTIVE_SESSION_PATH]):
        if not f.exists():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            jwt_tok = extract_clean_jwt(data.get("jwt_token"))
            gid = (data.get("garena_id") or "saved_session").strip()
            if not jwt_tok or gid.lower() in seen:
                continue
            claims = inspect_jwt(jwt_tok)
            if claims.get("valid_structure") and not claims.get("is_expired"):
                seen.add(gid.lower())
                accounts.append({
                    "garena_id": gid,
                    "preview": claims.get("preview"),
                    "remaining_seconds": claims.get("remaining_seconds"),
                    "updated_at": data.get("updated_at"),
                })
        except Exception:
            continue
    return accounts


def append_run_history(entry: Dict[str, Any]) -> None:
    ensure_dirs()
    history: List[Dict[str, Any]] = []
    if HISTORY_PATH.exists():
        try:
            parsed = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
            if isinstance(parsed, list):
                history = parsed
        except Exception:
            history = []
    history.insert(0, entry)
    history = history[:30]
    HISTORY_PATH.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")


def load_run_history() -> List[Dict[str, Any]]:
    ensure_dirs()
    if not HISTORY_PATH.exists():
        return []
    try:
        parsed = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []
