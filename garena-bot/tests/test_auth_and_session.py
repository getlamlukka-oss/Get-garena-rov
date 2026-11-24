import base64
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any, Generator, Tuple

import pytest
from fastapi.testclient import TestClient

GARENA_BOT_DIR = Path(__file__).resolve().parent.parent
MAIN_FILE = GARENA_BOT_DIR / "main.py"


def _load_bot_main() -> Any:
    module_name = "garena_bot_main"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, MAIN_FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


bot_main = _load_bot_main()


def _make_test_jwt(uid: int = 8801, exp_offset_sec: int = 3600) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = (
        base64.urlsafe_b64encode(json.dumps({"uid": uid, "exp": int(time.time()) + exp_offset_sec}).encode())
        .decode()
        .rstrip("=")
    )
    return f"{header}.{payload}.mock_signature_xyz987"


@pytest.fixture()
def client_and_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Tuple[TestClient, Path], None, None]:
    vault_path = tmp_path / "accounts_vault.json"
    jobs_path = tmp_path / "jobs_state.json"
    history_path = tmp_path / "run_history.json"
    prefs_path = tmp_path / "preferences.json"

    monkeypatch.setattr(bot_main, "ACCOUNTS_VAULT_PATH", vault_path)
    monkeypatch.setattr(bot_main, "JOBS_STATE_PATH", jobs_path)
    monkeypatch.setattr(bot_main, "HISTORY_PATH", history_path)
    monkeypatch.setattr(bot_main, "PREFERENCES_PATH", prefs_path)

    bot_main.MOCK_TASKS.clear()
    bot_main.MOCK_ANSWERS.clear()

    with TestClient(bot_main.app) as test_client:
        yield test_client, vault_path

    bot_main.MOCK_TASKS.clear()
    bot_main.MOCK_ANSWERS.clear()


def test_get_auth_me_unauthenticated_when_vault_empty(client_and_vault: Tuple[TestClient, Path]) -> None:
    client, vault_path = client_and_vault
    assert not vault_path.exists()

    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "no-store"

    body = resp.json()
    assert body["ok"] is True
    assert body["authenticated"] is False
    assert body["user"] is None


def test_get_auth_me_strictly_excludes_passwords_tokens_and_cookies(
    client_and_vault: Tuple[TestClient, Path],
) -> None:
    client, vault_path = client_and_vault
    secret_password = "TopSecretGarenaPassword!999"
    secret_jwt = _make_test_jwt(uid=4242, exp_offset_sec=1800)
    secret_csrf = "csrf_secret_value_abc123"
    secret_cookie_val = "datadome_cookie_secret_777"

    # Seed vault directly with all sensitive fields including raw cookies to ensure strict allowlist filtering
    seeded_vault = {
        "active_garena_id": "demo_player01",
        "accounts": [
            {
                "garena_id": "demo_player01",
                "garena_password": secret_password,
                "password": secret_password,
                "jwt_token": secret_jwt,
                "csrf_token": secret_csrf,
                "access_token": "raw_oauth_access_token_555",
                "cookies": {"jwt_token": secret_jwt, "csrf_token": secret_csrf, "datadome": secret_cookie_val},
                "selected": True,
                "gold": 120,
                "silver": 480,
                "completed_chapters": 15,
                "updated_at": 1700000000,
            }
        ],
    }
    vault_path.write_text(json.dumps(seeded_vault), encoding="utf-8")

    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "no-store"

    body = resp.json()
    assert body["ok"] is True
    assert body["authenticated"] is True

    user = body["user"]
    assert user["garena_id"] == "demo_player01"
    assert user["masked_id"] == "dem••••01"
    assert user["uid"] == 4242
    assert user["has_valid_session"] is True
    assert user["gold"] == 120
    assert user["silver"] == 480
    assert user["completed_chapters"] == 15

    # 1. Verify forbidden keys are absent at both root and user levels
    forbidden_keys = {
        "password",
        "garena_password",
        "token",
        "jwt_token",
        "csrf_token",
        "access_token",
        "cookies",
        "preview",
    }
    assert forbidden_keys.isdisjoint(body.keys())
    assert forbidden_keys.isdisjoint(user.keys())

    # 2. Verify raw secret values do not appear anywhere in serialized response body or headers
    raw_text = resp.text
    assert secret_password not in raw_text
    assert secret_jwt not in raw_text
    assert secret_csrf not in raw_text
    assert secret_cookie_val not in raw_text
    assert "raw_oauth_access_token_555" not in raw_text
    assert "eyJ" not in raw_text


def test_delete_session_clears_vault_memory_and_cookies(
    client_and_vault: Tuple[TestClient, Path],
) -> None:
    client, vault_path = client_and_vault
    secret_jwt = _make_test_jwt(uid=9001)

    bot_main.upsert_account(
        garena_id="session_test_user",
        jwt_token=secret_jwt,
        csrf_token="csrf_tok_to_clear",
        garena_password="pw_to_clear",
    )
    assert vault_path.exists()

    bot_main.MOCK_TASKS["task_abc"] = {"task_id": "task_abc", "status": "testing", "updated_at": 1}
    bot_main.MOCK_ANSWERS.append({"task_id": "task_abc", "answer": "Punish", "submitted_at": 1})

    client.cookies.set("jwt_token", secret_jwt, domain="testserver.local", path="/")
    client.cookies.set("csrf_token", "csrf_tok_to_clear", domain="testserver.local", path="/")
    assert client.cookies.get("jwt_token") == secret_jwt
    assert client.cookies.get("csrf_token") == "csrf_tok_to_clear"

    del_resp = client.delete("/api/session")
    assert del_resp.status_code == 200
    assert del_resp.headers.get("cache-control") == "no-store"

    del_body = del_resp.json()
    assert del_body["ok"] is True
    assert del_body["authenticated"] is False

    # 1. Vault file on disk must be removed
    assert not vault_path.exists()

    # 2. In-memory mock session/task stores must be emptied
    assert bot_main.MOCK_TASKS == {}
    assert bot_main.MOCK_ANSWERS == []

    # 3. Verify each Set-Cookie header explicitly expires jwt_token and csrf_token
    set_cookie_headers = (
        del_resp.headers.get_list("set-cookie")
        if hasattr(del_resp.headers, "get_list")
        else [v for k, v in del_resp.headers.items() if k.lower() == "set-cookie"]
    )
    jwt_set_cookie = next((h.lower() for h in set_cookie_headers if h.lower().startswith("jwt_token=")), "")
    csrf_set_cookie = next((h.lower() for h in set_cookie_headers if h.lower().startswith("csrf_token=")), "")
    assert jwt_set_cookie, "Expected Set-Cookie header for jwt_token"
    assert csrf_set_cookie, "Expected Set-Cookie header for csrf_token"
    assert "max-age=0" in jwt_set_cookie
    assert "path=/" in jwt_set_cookie
    assert "samesite=lax" in jwt_set_cookie
    assert "httponly" in jwt_set_cookie
    assert "max-age=0" in csrf_set_cookie
    assert "path=/" in csrf_set_cookie
    assert "samesite=lax" in csrf_set_cookie
    assert secret_jwt.lower() not in jwt_set_cookie
    assert "csrf_tok_to_clear" not in csrf_set_cookie

    # 4. Verify client cookie jar no longer contains jwt_token or csrf_token
    assert client.cookies.get("jwt_token") is None
    assert client.cookies.get("csrf_token") is None
    assert "jwt_token" not in client.cookies
    assert "csrf_token" not in client.cookies

    # 5. Subsequent GET /api/auth/me must report unauthenticated
    me_after = client.get("/api/auth/me")
    assert me_after.status_code == 200
    assert me_after.json() == {"ok": True, "authenticated": False, "user": None}


def test_global_error_handler_hides_stack_trace_and_redacts_secrets(
    client_and_vault: Tuple[TestClient, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = client_and_vault
    leaked_jwt = _make_test_jwt(uid=1111)

    def _exploding_vault() -> dict:
        raise RuntimeError(f"Database crash with jwt_token={leaked_jwt} and password=MySecret123")

    monkeypatch.setattr(bot_main, "load_answers_vault", _exploding_vault)

    resp = client.get("/api/health")
    assert resp.status_code == 500
    body = resp.json()
    assert body == {
        "ok": False,
        "error": "Internal server error",
        "message": "An unexpected error occurred. Please try again later.",
    }
    assert "Traceback" not in resp.text
    assert "Database crash" not in resp.text
    assert leaked_jwt not in resp.text
    assert "MySecret123" not in resp.text

    # Also verify HTTPException 4xx redacts any accidental secret substring
    sanitized = bot_main._redact_sensitive(f"Failed auth token={leaked_jwt} password=HiddenPw9")
    assert leaked_jwt not in sanitized
    assert "HiddenPw9" not in sanitized
    assert "[REDACTED" in sanitized
