import asyncio
import base64
import json
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import main
from solver_engine import LocalAdaptiveSolver


def make_test_jwt(uid: int = 1001, exp_offset: int = 3600) -> str:
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    pld = (
        base64.urlsafe_b64encode(
            json.dumps({"uid": uid, "exp": int(time.time()) + exp_offset}).encode()
        )
        .decode()
        .rstrip("=")
    )
    return f"{hdr}.{pld}.sig_test_123456"


class _MockRoVHandler(BaseHTTPRequestHandler):
    server_version = "MockRoV/2.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", "csrf_token=csrf_mock_tok; Path=/")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/":
            self._send_json(200, {"status": "OK"})
        elif self.path == "/api/user":
            self._send_json(
                200,
                {
                    "status": "OK",
                    "data": {
                        "gold": 50,
                        "silver": 100,
                        "chapter_completed": [30],
                        "chapter_visited": {"30": True},
                    },
                },
            )
        elif self.path == "/api/info":
            self._send_json(
                200,
                {
                    "status": "OK",
                    "data": {
                        "topics": [
                            {"id": 1, "title": "พื้นฐาน MOBA", "chapters": [30, 31, 999]},
                        ]
                    },
                },
            )
        else:
            self._send_json(404, {"status": "NOT_FOUND"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        if self.path == "/api/chapters":
            self._send_json(
                200,
                {
                    "status": "OK",
                    "data": {
                        "chapters": {
                            "31": {"title": "การเดินเลน", "description": "Yorn อยู่ในเลน Abyssal Dragon", "gold": 10, "silver": 20},
                            "999": {"title": "บททดสอบใหม่", "description": "คำตอบที่ถูกต้องคือ เลน Dark Slayer เสมอ", "gold": 15, "silver": 30},
                        }
                    },
                },
            )
        elif self.path == "/api/learned":
            self._send_json(200, {"status": "OK", "data": {"learned": True}})
        elif self.path == "/api/quiz":
            cid = int(body.get("id", 0))
            if cid == 31:
                self._send_json(
                    200,
                    {
                        "status": "OK",
                        "data": {
                            "quiz": [
                                {
                                    "question": "ฮีโร่ตัวใดมักอยู่ในเลน Abyssal Dragon",
                                    "choice": [
                                        {"id": "c1", "text": "Nakroth (ป่า)"},
                                        {"id": "c2", "text": "Yorn (แครี่)"},
                                    ],
                                }
                            ]
                        },
                    },
                )
            elif cid == 999:
                self._send_json(
                    200,
                    {
                        "status": "OK",
                        "data": {
                            "quiz": [
                                {
                                    "question": "บททดสอบใหม่ควรเดินไปที่เลนใด",
                                    "choice": [
                                        {"id": "n1", "text": "เลนกลาง"},
                                        {"id": "n2", "text": "เลน Dark Slayer"},
                                    ],
                                }
                            ]
                        },
                    },
                )
        elif self.path == "/api/answer":
            cid = int(body.get("id", 0))
            answers = body.get("answers") or []
            if cid == 31 and answers == ["c2"]:
                self._send_json(200, {"status": "OK", "data": {"quiz_status": True, "gold": 10, "silver": 20}})
            elif cid == 999 and answers == ["n2"]:
                self._send_json(200, {"status": "OK", "data": {"quiz_status": True, "gold": 15, "silver": 30}})
            else:
                self._send_json(200, {"status": "OK", "data": {"quiz_status": False}})


class GetGarenaRovCleanRoomTests(unittest.TestCase):
    def test_40_chapter_verified_vault_integrity(self) -> None:
        vault_path = PROJECT_ROOT / "data" / "answers_cache.json"
        self.assertTrue(vault_path.exists())
        vault = json.loads(vault_path.read_text(encoding="utf-8"))
        self.assertEqual(len(vault), 40)

    def test_smart_jwt_extraction_and_claims(self) -> None:
        tok = make_test_jwt(uid=555, exp_offset=1800)
        wrapped = f"https://academy.rov.in.th/?token={tok}&state=xyz"
        self.assertEqual(config.extract_clean_jwt(wrapped), tok)
        info = config.inspect_jwt(wrapped)
        self.assertTrue(info["valid_structure"])
        self.assertFalse(info["is_expired"])

    def test_zero_ai_local_adaptive_solver_passes_cached_and_new_chapters(self) -> None:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockRoVHandler)
        port = srv.server_address[1]
        import threading

        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_vault = Path(tmp) / "answers_cache.json"
                real_vault = (PROJECT_ROOT / "data" / "answers_cache.json").read_text(encoding="utf-8")
                tmp_vault.write_text(real_vault, encoding="utf-8")

                solver = LocalAdaptiveSolver(
                    jwt_token=make_test_jwt(),
                    garena_id="tester_rov",
                    base_url=f"http://127.0.0.1:{port}",
                    answers_cache_path=tmp_vault,
                    persist_session=False,
                )
                res = asyncio.run(solver.run())
                self.assertTrue(res["success"])
                stats = res["stats"]
                self.assertEqual(stats["passed"], 2)
                self.assertEqual(stats["already_done"], 1)
                self.assertEqual(stats["failed"], 0)
                self.assertEqual(stats["gold_earned"], 25)
                self.assertEqual(stats["silver_earned"], 50)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_fastapi_2_tab_ui_and_vault_endpoints(self) -> None:
        with TestClient(main.app) as client:
            r_home = client.get("/")
            self.assertEqual(r_home.status_code, 200)
            self.assertIn("tabBtnRun", r_home.text)
            self.assertIn("tabBtnVault", r_home.text)
            self.assertIn("garenaIdInput", r_home.text)
            self.assertIn("garenaPasswordInput", r_home.text)

            r_vault = client.get("/api/vault")
            self.assertEqual(r_vault.status_code, 200)
            self.assertEqual(r_vault.json()["total_chapters"], 40)


if __name__ == "__main__":
    unittest.main()
