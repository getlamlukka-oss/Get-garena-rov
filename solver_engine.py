import asyncio
import html
import inspect
import json
import logging
import re
from itertools import product
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from config import (
    ANSWERS_CACHE_PATH,
    extract_clean_jwt,
    get_rov_base_url,
    inspect_jwt,
    save_session,
)

logger = logging.getLogger("rov-solver-engine")

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


def strip_html(raw: Optional[str]) -> str:
    if not raw:
        return ""
    text = re.sub(r"<br\s*/?>", "\n", str(raw), flags=re.IGNORECASE)
    text = re.sub(r"</(p|li|div|h[1-6])>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def norm_text(raw: Optional[str]) -> str:
    if not raw:
        return ""
    return re.sub(r"\s+", " ", strip_html(str(raw))).strip()


def load_answers_vault(cache_path: Optional[Path] = None) -> Dict[str, Any]:
    target = Path(cache_path) if cache_path is not None else ANSWERS_CACHE_PATH
    if not target.exists():
        return {}
    try:
        parsed = json.loads(target.read_text(encoding="utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def save_answers_vault(vault: Dict[str, Any], cache_path: Optional[Path] = None) -> None:
    target = Path(cache_path) if cache_path is not None else ANSWERS_CACHE_PATH
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(vault, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning(f"Failed to save answers vault: {exc}")


class LocalAdaptiveSolver:
    def __init__(
        self,
        jwt_token: str,
        csrf_token: Optional[str] = None,
        garena_id: Optional[str] = None,
        base_url: Optional[str] = None,
        answers_cache_path: Optional[Path] = None,
        persist_session: bool = True,
        max_http_retries: int = 3,
        retry_backoff_sec: float = 0.35,
        log_fn: Optional[Callable[..., Any]] = None,
        progress_fn: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> None:
        self.jwt_token = extract_clean_jwt(jwt_token)
        self.csrf_token = (csrf_token or "").strip() or None
        self.garena_id = (garena_id or "").strip() or None
        self.base_url = get_rov_base_url(base_url)
        self.answers_cache_path = Path(answers_cache_path) if answers_cache_path is not None else ANSWERS_CACHE_PATH
        self.persist_session = bool(persist_session)
        self.max_http_retries = max(0, int(max_http_retries))
        self.retry_backoff_sec = max(0.0, float(retry_backoff_sec))
        self._log_fn = log_fn
        self._progress_fn = progress_fn
        self._auth_error: Optional[str] = None

    async def log(self, message: str, level: str = "info", phase: str = "solver") -> None:
        if not self._log_fn:
            return
        try:
            res = self._log_fn(message, level, phase)
            if inspect.isawaitable(res):
                await res
        except TypeError:
            try:
                res = self._log_fn(message, level)
                if inspect.isawaitable(res):
                    await res
            except Exception:
                pass
        except Exception:
            pass

    async def emit_progress(self, stats: Dict[str, Any]) -> None:
        if not self._progress_fn:
            return
        try:
            res = self._progress_fn(dict(stats))
            if inspect.isawaitable(res):
                await res
        except Exception:
            pass

    def _headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/",
            "Authorization": f"Bearer {self.jwt_token}",
        }
        if self.csrf_token:
            headers["X-CSRF-TOKEN"] = self.csrf_token
        return headers

    def _cookies(self) -> Dict[str, str]:
        cookies = {"jwt_token": self.jwt_token}
        if self.csrf_token:
            cookies["csrf_token"] = self.csrf_token
        return cookies

    def _sync_csrf(self, resp: httpx.Response, client: Optional[httpx.AsyncClient] = None) -> None:
        new_csrf: Optional[str] = None
        try:
            new_csrf = resp.cookies.get("csrf_token")
        except Exception:
            for k, v in resp.cookies.items():
                if k == "csrf_token" and v:
                    new_csrf = v
                    break
        if not new_csrf:
            new_csrf = resp.headers.get("x-csrf-token")
        if not new_csrf and client is not None:
            try:
                new_csrf = client.cookies.get("csrf_token")
            except Exception:
                for c in client.cookies.jar:
                    if c.name == "csrf_token" and c.value:
                        new_csrf = c.value
                        break
        if new_csrf and str(new_csrf).strip():
            cleaned = str(new_csrf).strip()
            self.csrf_token = cleaned
            if client is not None:
                try:
                    client.cookies.delete("csrf_token")
                except Exception:
                    pass
                client.cookies.set("csrf_token", cleaned)

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> httpx.Response:
        url = path if path.startswith(("http://", "https://")) else f"{self.base_url}{path}"
        total_attempts = 1 + self.max_http_retries
        last_exc: Optional[Exception] = None

        for attempt in range(total_attempts):
            req_headers = dict(headers) if headers is not None else self._headers()
            try:
                resp = await client.request(method.upper(), url, headers=req_headers, **kwargs)
                self._sync_csrf(resp, client)
                if resp.status_code == 401:
                    return resp
                if resp.status_code in RETRYABLE_STATUS_CODES and attempt < total_attempts - 1:
                    delay = self.retry_backoff_sec * (2 ** attempt)
                    await self.log(
                        f"⚠️ {method.upper()} {path} ได้รับ HTTP {resp.status_code} — ลองใหม่อีกครั้ง ({attempt + 1}/{self.max_http_retries})...",
                        "warning",
                        phase="network",
                    )
                    if delay > 0:
                        await asyncio.sleep(delay)
                    continue
                return resp
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < total_attempts - 1:
                    delay = self.retry_backoff_sec * (2 ** attempt)
                    if delay > 0:
                        await asyncio.sleep(delay)
                    continue
                raise

        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"Request retry loop exited unexpectedly for {method} {path}")

    async def verify_user(self, client: httpx.AsyncClient) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        if not self.jwt_token:
            return False, None, "ไม่พบ Token สำหรับเข้าสู่ระบบ"
        claims = inspect_jwt(self.jwt_token)
        if not claims.get("valid_structure"):
            return False, None, "รูปแบบ JWT Token ไม่ถูกต้อง"
        if claims.get("is_expired"):
            return False, None, "JWT Token หมดอายุแล้ว กรุณาล็อกอินใหม่"

        try:
            if not self.csrf_token:
                await self._request(client, "GET", "/", headers={"User-Agent": USER_AGENT})
            resp = await self._request(client, "GET", "/api/user")
            if resp.status_code == 200:
                payload = resp.json()
                if isinstance(payload, dict) and payload.get("status") == "OK" and payload.get("data"):
                    return True, payload["data"], "ok"
                return False, None, f"API ตอบกลับไม่ปกติ: {payload}"
            if resp.status_code == 401:
                return False, None, "เซสชันหมดอายุหรือไม่ถูกต้อง (401 Unauthorized)"
            return False, None, f"HTTP {resp.status_code}: {resp.text[:180]}"
        except Exception as exc:
            return False, None, f"เชื่อมต่อ RoV Academy ไม่ได้: {exc}"

    @staticmethod
    def _build_lesson_text(chapter_obj: Dict[str, Any]) -> str:
        parts = [
            strip_html(chapter_obj.get("title") or ""),
            strip_html(chapter_obj.get("description") or ""),
        ]
        for sec in chapter_obj.get("content") or []:
            parts.append(strip_html(sec.get("section") or ""))
            parts.append(strip_html(sec.get("description") or ""))
        return "\n".join(p for p in parts if p)

    @staticmethod
    def _lookup_candidates(ch_cache: Dict[str, Any], q_txt: str) -> List[str]:
        if not isinstance(ch_cache, dict) or not q_txt:
            return []
        raw_val = ch_cache.get(q_txt)
        if raw_val is None:
            q_norm = norm_text(q_txt)
            for k, v in ch_cache.items():
                if norm_text(k) == q_norm:
                    raw_val = v
                    break
        if raw_val is None:
            return []
        if isinstance(raw_val, list):
            return [str(x) for x in raw_val if x]
        if isinstance(raw_val, str) and raw_val.strip():
            return [raw_val]
        return []

    def _rank_choices(
        self,
        q_item: Dict[str, Any],
        ch_obj: Dict[str, Any],
        ch_cache: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], int]:
        q_txt = strip_html(q_item.get("question"))
        q_norm = norm_text(q_txt)
        choices = list(q_item.get("choice") or [])
        if not choices:
            return [], 0

        candidates = self._lookup_candidates(ch_cache, q_txt)
        lesson_low = self._build_lesson_text(ch_obj).lower()
        is_neg = any(
            kw in q_norm
            for kw in ("ไม่ใช่", "ไม่ถูกต้อง", "ไม่ควร", "ไม่สามารถ", "ไม่เหมาะ", "ไม่นิยม", "น้อยที่สุด", "ข้อใดผิด")
        )

        scored: List[Tuple[float, int, Dict[str, Any]]] = []
        cache_matches = 0
        for idx, c in enumerate(choices):
            c_txt = strip_html(str(c.get("text") or ""))
            c_norm = norm_text(c_txt)
            c_low = c_norm.lower()
            score = 0.0

            for rank_idx, cand in enumerate(candidates):
                if c_txt == cand or c_norm == norm_text(cand):
                    score += 1000.0 - (rank_idx * 120.0)
                    cache_matches += 1
                    break

            tokens = [t for t in re.findall(r"[ก-๙a-zA-Z0-9\.]+", c_low) if len(t) >= 2]
            if tokens and lesson_low:
                hits = sum(1 for t in tokens if t in lesson_low)
                ratio = hits / max(1, len(tokens))
                exact_hit = 1.0 if (len(c_low) >= 3 and c_low in lesson_low) else 0.0
                overlap = (ratio * 30.0) + (exact_hit * 25.0)
                score += (-overlap if is_neg else overlap)

            if any(p in c_norm for p in ("ถูกทุกข้อ", "ถูกทั้ง", "ข้อ 1 และ 2 ถูก", "ผิดทุกข้อ", "ไม่มีข้อใดถูก")):
                score += 18.0

            scored.append((score, -idx, c))

        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [item[2] for item in scored], cache_matches

    async def _submit_vector(
        self,
        client: httpx.AsyncClient,
        cid: int,
        ch_title: str,
        ch_obj: Dict[str, Any],
        quiz_list: List[Dict[str, Any]],
        choice_vec: List[Dict[str, Any]],
        method_label: str,
        vault: Dict[str, Any],
        stats: Dict[str, Any],
        chapter_results: List[Dict[str, Any]],
    ) -> bool:
        chosen_ids = [c["id"] for c in choice_vec]
        try:
            ans_resp = await self._request(
                client,
                "POST",
                "/api/answer",
                json={"id": cid, "answers": chosen_ids},
            )
        except httpx.HTTPError as exc:
            await self.log(f"⚠️ ส่งคำตอบบทที่ {cid} ไม่สำเร็จ ({exc})", "warning", phase="answer")
            return False

        if ans_resp.status_code == 401:
            self._auth_error = "เซสชันหมดอายุระหว่างส่งคำตอบ (401 Unauthorized)"
            return False

        try:
            ans_json = ans_resp.json()
        except Exception:
            ans_json = {}
        ans_data = ans_json.get("data") if isinstance(ans_json.get("data"), dict) else {}

        if ans_resp.status_code == 200 and bool(ans_data.get("quiz_status")):
            new_ch_cache: Dict[str, Any] = {}
            qa_pairs: List[Dict[str, str]] = []
            for q_item, c_obj in zip(quiz_list, choice_vec):
                q_clean = strip_html(q_item.get("question"))
                a_clean = strip_html(str(c_obj.get("text") or ""))
                qa_pairs.append({"question": q_clean, "answer": a_clean})
                if not q_clean or not a_clean:
                    continue
                if q_clean in new_ch_cache and new_ch_cache[q_clean] != a_clean:
                    prev = new_ch_cache[q_clean]
                    if isinstance(prev, list):
                        if a_clean not in prev:
                            prev.append(a_clean)
                    else:
                        new_ch_cache[q_clean] = [prev, a_clean]
                else:
                    new_ch_cache[q_clean] = a_clean

            if new_ch_cache:
                vault[str(cid)] = new_ch_cache
                save_answers_vault(vault, self.answers_cache_path)

            raw_gold = ans_data.get("gold")
            raw_silver = ans_data.get("silver")
            g_add = int(raw_gold if raw_gold is not None else (ch_obj.get("gold", 0) or 0))
            s_add = int(raw_silver if raw_silver is not None else (ch_obj.get("silver", 0) or 0))

            stats["passed"] += 1
            stats["gold_earned"] += g_add
            stats["silver_earned"] += s_add
            stats["user_gold"] = stats["initial_gold"] + stats["gold_earned"]
            stats["user_silver"] = stats["initial_silver"] + stats["silver_earned"]
            stats["remaining"] = max(0, stats["total"] - stats["already_done"] - stats["passed"] - stats["failed"])
            stats["phase"] = "answer"
            stats["current_chapter"] = f"✅ บทที่ {cid}: {ch_title} (+{g_add} Gold, +{s_add} Silver)"

            ch_record = {
                "chapter_id": cid,
                "title": ch_title,
                "status": "passed",
                "method": method_label,
                "gold": g_add,
                "silver": s_add,
                "questions_count": len(quiz_list),
                "qa": qa_pairs,
            }
            chapter_results.append(ch_record)
            stats["latest_chapter"] = ch_record
            await self.emit_progress(stats)
            await self.log(
                f"✅ ผ่านบทที่ {cid} ({ch_title}) [{method_label}] รับ +{g_add} Gold, +{s_add} Silver",
                "success",
                phase="answer",
            )
            return True

        return False

    async def _solve_single_chapter(
        self,
        client: httpx.AsyncClient,
        cid: int,
        ch_title: str,
        ch_obj: Dict[str, Any],
        quiz_list: List[Dict[str, Any]],
        vault: Dict[str, Any],
        stats: Dict[str, Any],
        chapter_results: List[Dict[str, Any]],
    ) -> bool:
        ch_cache = vault.get(str(cid))
        if not isinstance(ch_cache, dict):
            default_vault = load_answers_vault(ANSWERS_CACHE_PATH)
            ch_cache = default_vault.get(str(cid)) if isinstance(default_vault.get(str(cid)), dict) else {}

        ranked_per_q: List[List[Dict[str, Any]]] = []
        cache_match_counts: List[int] = []
        for q_item in quiz_list:
            ranked, m_cnt = self._rank_choices(q_item, ch_obj, ch_cache)
            if not ranked:
                return False
            ranked_per_q.append(ranked)
            cache_match_counts.append(m_cnt)

        tried_keys = set()

        async def _try(vec: List[Dict[str, Any]], label: str) -> bool:
            key = tuple(str(c["id"]) for c in vec)
            if key in tried_keys:
                return False
            tried_keys.add(key)
            return await self._submit_vector(
                client, cid, ch_title, ch_obj, quiz_list, vec, label, vault, stats, chapter_results
            )

        base_vec = [r[0] for r in ranked_per_q]
        all_cached = all(cnt >= 1 for cnt in cache_match_counts)
        if await _try(base_vec, "คลังเฉลย 100% ⚡" if all_cached else "Local Solver 🧠"):
            return True
        if self._auth_error:
            return False

        multi_qis = [qi for qi, cnt in enumerate(cache_match_counts) if cnt >= 2 and len(ranked_per_q[qi]) >= 2]
        if multi_qis:
            ranges = [range(min(cache_match_counts[qi], len(ranked_per_q[qi]), 3)) for qi in multi_qis]
            for combo in product(*ranges):
                vec = list(base_vec)
                for qi, r_idx in zip(multi_qis, combo):
                    vec[qi] = ranked_per_q[qi][r_idx]
                if await _try(vec, "Local Solver 🧠"):
                    return True
                if self._auth_error:
                    return False

        q_order = sorted(range(len(quiz_list)), key=lambda qi: (0 if cache_match_counts[qi] != 1 else 1, qi))
        for alt_rank in (1, 2, 3):
            for qi in q_order:
                if alt_rank < len(ranked_per_q[qi]):
                    vec = list(base_vec)
                    vec[qi] = ranked_per_q[qi][alt_rank]
                    if await _try(vec, "Local Solver 🧠"):
                        return True
                    if self._auth_error:
                        return False

        uncertain_qis = [qi for qi in q_order if len(ranked_per_q[qi]) >= 2][:6]
        for i_idx in range(len(uncertain_qis)):
            for j_idx in range(i_idx + 1, len(uncertain_qis)):
                q1, q2 = uncertain_qis[i_idx], uncertain_qis[j_idx]
                for r1 in range(1, min(3, len(ranked_per_q[q1]))):
                    for r2 in range(1, min(3, len(ranked_per_q[q2]))):
                        vec = list(base_vec)
                        vec[q1] = ranked_per_q[q1][r1]
                        vec[q2] = ranked_per_q[q2][r2]
                        if await _try(vec, "Local Solver 🧠"):
                            return True
                        if self._auth_error:
                            return False

        return False

    async def run(self) -> Dict[str, Any]:
        self._auth_error = None
        vault = load_answers_vault(self.answers_cache_path)
        chapter_results: List[Dict[str, Any]] = []
        stats: Dict[str, Any] = {
            "phase": "auth",
            "total": 0,
            "already_done": 0,
            "passed": 0,
            "failed": 0,
            "remaining": 0,
            "initial_gold": 0,
            "initial_silver": 0,
            "gold_earned": 0,
            "silver_earned": 0,
            "user_gold": 0,
            "user_silver": 0,
            "current_chapter": "กำลังตรวจสอบบัญชี RoV Academy...",
            "latest_chapter": None,
            "garena_id": self.garena_id or "ผู้เล่น RoV",
        }
        await self.emit_progress(stats)

        async with httpx.AsyncClient(timeout=30.0, cookies=self._cookies(), follow_redirects=True) as client:
            await self.log("🔐 กำลังยืนยันตัวตนกับ RoV Academy (/api/user)...", "info", phase="auth")
            ok, user_data, err_msg = await self.verify_user(client)
            if not ok or user_data is None:
                return {"success": False, "error": err_msg, "stats": stats, "chapters": chapter_results}

            if self.persist_session:
                save_session(self.jwt_token, self.csrf_token, garena_id=self.garena_id)

            completed_set = {int(x) for x in (user_data.get("chapter_completed") or []) if str(x).isdigit()}
            visited_map = user_data.get("chapter_visited") or {}
            init_gold = int(user_data.get("gold", 0) or 0)
            init_silver = int(user_data.get("silver", 0) or 0)
            stats["initial_gold"] = init_gold
            stats["initial_silver"] = init_silver
            stats["user_gold"] = init_gold
            stats["user_silver"] = init_silver

            await self.log(
                f"✅ ยืนยันตัวตนสำเร็จ! (Gold ปัจจุบัน: {init_gold}, Silver ปัจจุบัน: {init_silver}, ผ่านแล้ว {len(completed_set)} บท)",
                "success",
                phase="auth",
            )

            stats["phase"] = "info"
            stats["current_chapter"] = "กำลังดึงรายการบทเรียนทั้งหมด (/api/info)..."
            await self.emit_progress(stats)

            info_resp = await self._request(client, "GET", "/api/info")
            if info_resp.status_code != 200:
                return {
                    "success": False,
                    "error": f"ดึงข้อมูลบทเรียน /api/info ไม่สำเร็จ (HTTP {info_resp.status_code})",
                    "stats": stats,
                    "chapters": chapter_results,
                }

            topics = (info_resp.json().get("data") or {}).get("topics") or []
            chapter_order: List[Tuple[int, str, int]] = []
            for t in topics:
                tid = int(t["id"])
                ttitle = str(t.get("title") or f"Topic {tid}").strip()
                for cid in t.get("chapters") or []:
                    chapter_order.append((tid, ttitle, int(cid)))

            pending = [(tid, tt, cid) for (tid, tt, cid) in chapter_order if cid not in completed_set]
            stats["total"] = len(chapter_order)
            stats["already_done"] = len(chapter_order) - len(pending)
            stats["remaining"] = len(pending)
            await self.emit_progress(stats)

            await self.log(
                f"📚 พบทั้งหมด {stats['total']} บท (ผ่านแล้ว {stats['already_done']} บท · รอทำ {len(pending)} บท · คลังเฉลยพร้อม {len(vault)} บท)",
                "info",
                phase="info",
            )

            if not pending:
                stats["phase"] = "completed"
                stats["current_chapter"] = "🎉 บัญชีนี้ผ่านครบทั้ง 40 บทเรียนเรียบร้อยแล้ว!"
                await self.emit_progress(stats)
                await self.log("🏁 บัญชีนี้ทำข้อสอบผ่านครบทุกบทแล้ว!", "success", phase="completed")
                return {"success": True, "error": None, "stats": stats, "chapters": chapter_results}

            all_cids = [cid for (_, _, cid) in pending]
            stats["phase"] = "chapters"
            stats["current_chapter"] = f"กำลังโหลดข้อมูลบทเรียน {len(all_cids)} บท..."
            await self.emit_progress(stats)

            ch_resp = await self._request(client, "POST", "/api/chapters", json={"chapter_id_list": all_cids})
            chapters_map: Dict[str, Any] = {}
            if ch_resp.status_code == 200:
                try:
                    chapters_map = (ch_resp.json().get("data") or {}).get("chapters") or {}
                except Exception:
                    chapters_map = {}

            for tid, ttitle, cid in pending:
                ch_obj = chapters_map.get(str(cid)) or {}
                ch_title = ch_obj.get("title") or f"บทที่ {cid}"

                if str(cid) not in visited_map and cid not in visited_map:
                    try:
                        lr = await self._request(client, "POST", "/api/learned", json={"id": cid})
                        if lr.status_code == 401:
                            return {
                                "success": False,
                                "error": "เซสชันหมดอายุขณะบันทึกการเข้าเรียน (401)",
                                "stats": stats,
                                "chapters": chapter_results,
                            }
                    except Exception:
                        pass

                stats["phase"] = "quiz"
                stats["current_chapter"] = f"กำลังส่งคำตอบบทที่ {cid}: {ch_title}..."
                await self.emit_progress(stats)

                try:
                    qz_resp = await self._request(client, "POST", "/api/quiz", json={"id": cid})
                except httpx.HTTPError as exc:
                    await self.log(f"⚠️ โหลดข้อสอบบทที่ {cid} ไม่สำเร็จ ({exc})", "warning", phase="quiz")
                    stats["failed"] += 1
                    stats["remaining"] = max(0, stats["total"] - stats["already_done"] - stats["passed"] - stats["failed"])
                    await self.emit_progress(stats)
                    continue

                if qz_resp.status_code == 401:
                    return {
                        "success": False,
                        "error": "เซสชันหมดอายุขณะดึงข้อสอบ (401)",
                        "stats": stats,
                        "chapters": chapter_results,
                    }
                if qz_resp.status_code != 200:
                    stats["failed"] += 1
                    stats["remaining"] = max(0, stats["total"] - stats["already_done"] - stats["passed"] - stats["failed"])
                    await self.emit_progress(stats)
                    continue

                qz_data = qz_resp.json().get("data")
                quiz_list = (
                    (qz_data.get("quiz") or qz_data.get("questions") or [])
                    if isinstance(qz_data, dict)
                    else (qz_data if isinstance(qz_data, list) else [])
                )
                if not quiz_list:
                    continue

                passed_ok = await self._solve_single_chapter(
                    client, cid, ch_title, ch_obj, quiz_list, vault, stats, chapter_results
                )
                if self._auth_error:
                    return {
                        "success": False,
                        "error": self._auth_error,
                        "stats": stats,
                        "chapters": chapter_results,
                    }
                if not passed_ok:
                    stats["failed"] += 1
                    stats["remaining"] = max(0, stats["total"] - stats["already_done"] - stats["passed"] - stats["failed"])
                    chapter_results.append({
                        "chapter_id": cid,
                        "title": ch_title,
                        "status": "failed",
                        "method": "Local Solver",
                        "gold": 0,
                        "silver": 0,
                        "questions_count": len(quiz_list),
                        "qa": [],
                    })
                    await self.emit_progress(stats)
                    await self.log(f"❌ บทที่ {cid} ({ch_title}) ส่งคำตอบไม่ผ่าน", "warning", phase="answer")

            stats["phase"] = "completed"
            stats["remaining"] = max(0, stats["total"] - stats["already_done"] - stats["passed"] - stats["failed"])
            stats["current_chapter"] = (
                f"🎉 เสร็จสมบูรณ์! ผ่านเพิ่ม {stats['passed']} บท (+{stats['gold_earned']} Gold, +{stats['silver_earned']} Silver)"
            )
            await self.emit_progress(stats)
            await self.log(
                f"🏁 สรุปผล: ทำผ่านเพิ่ม {stats['passed']} บท | รับรางวัล +{stats['gold_earned']} Gold, +{stats['silver_earned']} Silver "
                f"(รวมในบัญชี: {stats['user_gold']} Gold, {stats['user_silver']} Silver)",
                "success",
                phase="completed",
            )
            return {"success": True, "error": None, "stats": stats, "chapters": chapter_results}
