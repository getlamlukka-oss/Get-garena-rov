import asyncio
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auth_engine import authenticate_garena_background
from config import (
    ANSWERS_CACHE_PATH,
    BASE_DIR,
    append_run_history,
    clear_sessions,
    ensure_dirs,
    extract_clean_jwt,
    get_rov_base_url,
    inspect_jwt,
    list_saved_accounts,
    load_run_history,
    load_session,
    save_session,
)
from solver_engine import LocalAdaptiveSolver, load_answers_vault

ensure_dirs()

app = FastAPI(
    title="Get-garena-rov — RoV Academy Auto Solver",
    description="Zero-AI 100% Verified 40-Chapter RoV Academy Auto-Solver with Background Garena Login",
    version="2.0.0",
)

STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

TASKS: Dict[str, Dict[str, Any]] = {}
WS_SUBSCRIBERS: Dict[str, Set[WebSocket]] = {}


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Any) -> Any:
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp


class RunSolverRequest(BaseModel):
    garena_id: Optional[str] = None
    garena_password: Optional[str] = None
    jwt_token: Optional[str] = None
    csrf_token: Optional[str] = None
    base_url: Optional[str] = None


class InspectJwtRequest(BaseModel):
    token: Optional[str] = None


async def _broadcast_ws(task_id: str, event_type: str, data: Dict[str, Any]) -> None:
    task = TASKS.get(task_id)
    if not task:
        return
    task["seq"] = int(task.get("seq", 0)) + 1
    envelope = {
        "type": event_type,
        "task_id": task_id,
        "seq": task["seq"],
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "data": data,
    }
    subs = list(WS_SUBSCRIBERS.get(task_id) or [])
    dead: List[WebSocket] = []
    for ws in subs:
        try:
            await ws.send_json(envelope)
        except Exception:
            dead.append(ws)
    for ws in dead:
        WS_SUBSCRIBERS.get(task_id, set()).discard(ws)


async def _run_solver_task(task_id: str, req: RunSolverRequest) -> None:
    task = TASKS[task_id]

    async def on_log(message: str, level: str = "info", phase: str = "solver") -> None:
        entry = {
            "index": len(task["logs"]),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "phase": phase,
            "message": message,
        }
        task["logs"].append(entry)
        await _broadcast_ws(task_id, "log", entry)

    async def on_progress(stats: Dict[str, Any]) -> None:
        task["progress"] = dict(stats)
        await _broadcast_ws(task_id, "progress", dict(stats))

    try:
        auth_res = await authenticate_garena_background(
            garena_id=req.garena_id,
            garena_password=req.garena_password,
            jwt_token=req.jwt_token,
            csrf_token=req.csrf_token,
            base_url=req.base_url,
            log_fn=on_log,
        )
        if not auth_res.get("success") or not auth_res.get("jwt_token"):
            err_msg = auth_res.get("error") or "เข้าสู่ระบบไม่สำเร็จ"
            await on_log(f"❌ {err_msg}", "error", "auth")
            task["status"] = "failed"
            task["error"] = err_msg
            task["result"] = {"success": False, "error": err_msg}
            await _broadcast_ws(task_id, "failed", {"error": err_msg, "result": task["result"]})
            return

        jwt_tok = auth_res["jwt_token"]
        csrf_tok = auth_res.get("csrf_token")
        effective_id = auth_res.get("garena_id") or req.garena_id or "ผู้เล่น RoV"

        solver = LocalAdaptiveSolver(
            jwt_token=jwt_tok,
            csrf_token=csrf_tok,
            garena_id=effective_id,
            base_url=req.base_url,
            log_fn=on_log,
            progress_fn=on_progress,
        )
        solve_res = await solver.run()
        if not solve_res.get("success"):
            err_msg = solve_res.get("error") or "ส่งคำตอบไม่สำเร็จ"
            await on_log(f"❌ {err_msg}", "error", "solver")
            task["status"] = "failed"
            task["error"] = err_msg
            task["result"] = solve_res
            await _broadcast_ws(task_id, "failed", {"error": err_msg, "result": solve_res})
            return

        stats = solve_res.get("stats") or {}
        history_record = {
            "task_id": task_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "garena_id": effective_id,
            "auth_source": auth_res.get("source", "session"),
            "total": stats.get("total", 40),
            "already_done": stats.get("already_done", 0),
            "passed": stats.get("passed", 0),
            "failed": stats.get("failed", 0),
            "gold_earned": stats.get("gold_earned", 0),
            "silver_earned": stats.get("silver_earned", 0),
            "user_gold": stats.get("user_gold", 0),
            "user_silver": stats.get("user_silver", 0),
            "chapters": solve_res.get("chapters") or [],
        }
        append_run_history(history_record)

        task["status"] = "completed"
        task["result"] = {
            "success": True,
            "garena_id": effective_id,
            "auth_source": auth_res.get("source"),
            "stats": stats,
            "chapters": solve_res.get("chapters") or [],
        }
        await _broadcast_ws(task_id, "completed", {"result": task["result"], "progress": task["progress"]})
    except Exception as exc:
        err_msg = f"เกิดข้อผิดพลาดในระบบ: {exc}"
        await on_log(f"❌ {err_msg}", "error", "system")
        task["status"] = "failed"
        task["error"] = err_msg
        task["result"] = {"success": False, "error": err_msg}
        await _broadcast_ws(task_id, "failed", {"error": err_msg, "result": task["result"]})


@app.get("/")
async def index_page() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    vault = load_answers_vault(ANSWERS_CACHE_PATH)
    return {
        "status": "ok",
        "engine": "Zero-AI Local Adaptive Solver v2.0",
        "verified_chapters": len(vault),
        "timestamp": int(time.time()),
    }


@app.get("/api/session")
async def get_session_status(garena_id: Optional[str] = None) -> Dict[str, Any]:
    jwt_tok, _csrf, saved_id = load_session(garena_id)
    claims = inspect_jwt(jwt_tok) if jwt_tok else {"valid_structure": False, "is_expired": False}
    vault = load_answers_vault(ANSWERS_CACHE_PATH)
    return {
        "has_session": bool(jwt_tok),
        "garena_id": saved_id,
        "preview": claims.get("preview"),
        "remaining_seconds": claims.get("remaining_seconds"),
        "saved_accounts": list_saved_accounts(),
        "verified_chapters_count": len(vault),
        "rov_base_url": get_rov_base_url(),
    }


@app.delete("/api/session")
async def delete_session_endpoint() -> Dict[str, Any]:
    clear_sessions()
    return {"success": True, "message": "ล้างเซสชันที่บันทึกไว้เรียบร้อยแล้ว"}


@app.post("/api/inspect-jwt")
async def inspect_jwt_endpoint(payload: InspectJwtRequest) -> Dict[str, Any]:
    return inspect_jwt(payload.token)


@app.post("/api/run")
async def start_solver_run(req: RunSolverRequest) -> JSONResponse:
    if req.jwt_token:
        clean_tok = extract_clean_jwt(req.jwt_token)
        if inspect_jwt(clean_tok).get("valid_structure") and not inspect_jwt(clean_tok).get("is_expired"):
            save_session(clean_tok, req.csrf_token, garena_id=req.garena_id)

    task_id = uuid.uuid4().hex[:12]
    TASKS[task_id] = {
        "task_id": task_id,
        "status": "running",
        "created_at": int(time.time()),
        "seq": 0,
        "logs": [],
        "progress": {
            "phase": "auth",
            "total": 40,
            "already_done": 0,
            "passed": 0,
            "failed": 0,
            "remaining": 40,
            "gold_earned": 0,
            "silver_earned": 0,
            "user_gold": 0,
            "user_silver": 0,
            "current_chapter": "กำลังเริ่มต้นระบบล็อกอินเบื้องหลัง...",
        },
        "result": None,
        "error": None,
    }
    WS_SUBSCRIBERS[task_id] = set()
    asyncio.create_task(_run_solver_task(task_id, req))
    return JSONResponse(
        status_code=202,
        content={
            "task_id": task_id,
            "status": "running",
            "ws_url": f"/ws/tasks/{task_id}",
        },
    )


@app.get("/api/status/{task_id}")
async def get_task_status(task_id: str) -> Dict[str, Any]:
    task = TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="ไม่พบรหัสงานนี้")
    return {
        "task_id": task_id,
        "status": task["status"],
        "progress": task["progress"],
        "logs": task["logs"],
        "result": task["result"],
        "error": task["error"],
    }


@app.get("/api/vault")
async def get_answers_vault() -> Dict[str, Any]:
    vault = load_answers_vault(ANSWERS_CACHE_PATH)
    chapters_list: List[Dict[str, Any]] = []
    for cid_str in sorted(vault.keys(), key=lambda x: int(x) if str(x).isdigit() else 999):
        q_map = vault[cid_str]
        if not isinstance(q_map, dict):
            continue
        qa_list = []
        for q_txt, ans_val in q_map.items():
            if isinstance(ans_val, list):
                for idx, a_item in enumerate(ans_val, 1):
                    qa_list.append({"question": f"{q_txt} (รูปแบบที่ {idx})", "answer": str(a_item)})
            else:
                qa_list.append({"question": q_txt, "answer": str(ans_val)})
        chapters_list.append({
            "chapter_id": int(cid_str) if str(cid_str).isdigit() else cid_str,
            "questions_count": len(qa_list),
            "qa": qa_list,
        })
    return {
        "total_chapters": len(chapters_list),
        "total_questions": sum(c["questions_count"] for c in chapters_list),
        "chapters": chapters_list,
    }


@app.get("/api/history")
async def get_run_history() -> Dict[str, Any]:
    return {"history": load_run_history()}


@app.get("/api/export/system-csv")
async def export_system_blueprint_csv() -> FileResponse:
    csv_path = BASE_DIR / "system_blueprint.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="ไม่พบไฟล์ system_blueprint.csv")
    return FileResponse(
        path=str(csv_path),
        media_type="text/csv; charset=utf-8",
        filename="Get-garena-rov-system-blueprint.csv",
    )


@app.get("/api/export/answers-csv")
async def export_answers_csv() -> FileResponse:
    csv_path = BASE_DIR / "rov_academy_40_chapters_answers.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="ไม่พบไฟล์ rov_academy_40_chapters_answers.csv")
    return FileResponse(
        path=str(csv_path),
        media_type="text/csv; charset=utf-8",
        filename="Get-garena-rov-40-chapters-answers.csv",
    )


@app.websocket("/ws/tasks/{task_id}")
async def task_websocket(websocket: WebSocket, task_id: str) -> None:
    await websocket.accept()
    task = TASKS.get(task_id)
    if not task:
        await websocket.close(code=4404)
        return

    WS_SUBSCRIBERS.setdefault(task_id, set()).add(websocket)
    try:
        await websocket.send_json({
            "type": "snapshot",
            "task_id": task_id,
            "seq": task.get("seq", 0),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "data": {
                "status": task["status"],
                "progress": task["progress"],
                "logs": task["logs"],
                "result": task["result"],
                "error": task["error"],
            },
        })
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        WS_SUBSCRIBERS.get(task_id, set()).discard(websocket)
