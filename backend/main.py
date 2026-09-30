"""Passive, scoped PCAP assessment API with separately authenticated response."""
import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

BASE_DIR = Path(__file__).resolve().parent
try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env", override=False)
except ImportError:
    pass

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
import api_auth
import database
import ips_engine
import report_generator
import risk_engine

MAX_PCAP_SIZE = int(os.getenv("MAX_PCAP_SIZE", str(50 * 1024 * 1024)))
MAX_SESSIONS = 10000
PARSER_TIMEOUT = int(os.getenv("PARSER_TIMEOUT", "120"))
MAX_PARSER_OUTPUT = 32 * 1024 * 1024
MAX_WS_CLIENTS = 32
WS_QUEUE_MAX = 128
INGRESS_DIR = Path(os.getenv("INGRESS_DIR", str(BASE_DIR / "ingress_pcap")))
PROCESSED_DIR = Path(os.getenv("PROCESSED_DIR", str(BASE_DIR / "processed_pcap")))
FAILED_DIR = Path(os.getenv("FAILED_DIR", str(BASE_DIR / "failed_pcap")))
_last_analysis = []  # Compatibility cache only; never used to choose report scope.
active_websockets = {}
live_capture_active = False
live_capture_task = None
capture_state = {"state": "unavailable", "reason": "Continuity-safe live capture is not implemented; upload a completed capture."}
_ingestion_slots = asyncio.Semaphore(2)
_response_lock = asyncio.Lock()
_background_tasks = []


@asynccontextmanager
async def lifespan(app):
    await asyncio.to_thread(database.init_db)
    if os.getenv("ENABLE_BULK_INGEST", "0") == "1":
        _background_tasks.append(asyncio.create_task(bulk_pcap_watchdog()))
    yield
    for task in _background_tasks:
        task.cancel()
    for task in _background_tasks:
        with suppress(asyncio.CancelledError):
            await task
    _background_tasks.clear()
    for ws in tuple(active_websockets):
        with suppress(Exception):
            await ws.close(code=1001)
    active_websockets.clear()


app = FastAPI(title="SecureMailScope", version="2.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=api_auth.allowed_origins(),
                   allow_credentials=False, allow_methods=["GET", "POST", "DELETE"],
                   allow_headers=["Authorization", "Content-Type"])


class BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Cap the incoming multipart body before Starlette spools the entire upload."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        total = 0
        limit = MAX_PCAP_SIZE + 1024 * 1024  # bounded multipart overhead
        async def limited_receive():
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > limit:
                raise BodyTooLarge()
            return message
        try:
            await self.app(scope, limited_receive, send)
        except BodyTooLarge:
            await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)


app.add_middleware(BodyLimitMiddleware)


@app.middleware("http")
async def authenticate_http(request: Request, call_next):
    try:
        dangerous = request.url.path.startswith(("/api/capture/", "/api/pcap/sniff/", "/api/soar/")) or request.url.path == "/api/sessions/flush"
        # Preflight has no operation; validate its Origin without demanding a bearer.
        if request.method == "OPTIONS":
            if not api_auth.origin_allowed(request.headers.get("origin")):
                raise HTTPException(403, "Origin is not permitted")
        else:
            api_auth.authorize(request.client.host if request.client else "", request.headers.get("origin"),
                               api_auth.http_token(request.headers.get("authorization")), dangerous)
        size = request.headers.get("content-length")
        if size and (not size.isdecimal() or int(size) > MAX_PCAP_SIZE + 1024 * 1024):
            raise HTTPException(413, "Request body too large")
    except HTTPException as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return await call_next(request)


def map_risk_to_frontend_format(result):
    """One lossless raw+alias representation for upload, history and WebSocket."""
    data = dict(result)
    data.update(id=result.get("session_id"), src=result.get("src_ip"), dst=result.get("dst_ip"),
                protocol=result.get("email_protocol", "UNKNOWN"), score=result.get("score"),
                status=result.get("status", "unknown"),
                reason=next(iter(result.get("risk_factors") or []), "No assessed finding; consult evidence coverage"))
    # Old mitigation flags lack independently verified scope and must not hide findings.
    data["is_mitigated"] = False
    if result.get("is_mitigated"):
        data["legacy_mitigation_claim"] = True
    return data


def _map_row(row):
    data = json.loads(row["full_json"])
    data["analysis_id"] = row.get("analysis_id") or f"legacy-{row['id']}"
    data["session_id"] = row.get("session_id") or f"legacy-session-{row['id']}"
    data.setdefault("timestamp", str(row["timestamp"]))
    if not row.get("analysis_id"):
        data.setdefault("provenance", {"status": "legacy_capture_identity_unavailable"})
    return map_risk_to_frontend_format(data)


async def broadcast_message(message):
    for ws, queue in tuple(active_websockets.items()):
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            active_websockets.pop(ws, None)
            with suppress(Exception):
                await asyncio.wait_for(ws.close(code=1013), 1)


@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    if not api_auth.origin_allowed(websocket.headers.get("origin")) or len(active_websockets) >= MAX_WS_CLIENTS:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    sender = None
    async def send_queued(queue):
        while True:
            await asyncio.wait_for(websocket.send_text(await queue.get()), 10)
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), 5)
        if len(raw) > 8192:
            raise ValueError("Oversize authentication frame")
        frame = json.loads(raw)
        if frame.get("type") != "authenticate" or not isinstance(frame.get("token", ""), str):
            raise ValueError("Authentication frame required")
        api_auth.authorize(websocket.client.host if websocket.client else "", websocket.headers.get("origin"), frame.get("token", ""))
        queue = asyncio.Queue(maxsize=WS_QUEUE_MAX)
        active_websockets[websocket] = queue
        rows = await asyncio.to_thread(database.get_recent_sessions, 200)
        # Replays use the same immutable session_id as history; clients upsert by id.
        await asyncio.wait_for(websocket.send_json({"type": "snapshot", "sessions": [_map_row(row) for row in rows]}), 10)
        sender = asyncio.create_task(send_queued(queue))
        while True:
            receiver = asyncio.create_task(websocket.receive_text())
            done, _ = await asyncio.wait([receiver, sender], return_when=asyncio.FIRST_COMPLETED)
            if sender in done:
                receiver.cancel()
                with suppress(asyncio.CancelledError):
                    await receiver
                sender.result()
            if len(receiver.result()) > 8192:
                raise ValueError("Oversize frame")
    except (WebSocketDisconnect, HTTPException, ValueError, asyncio.TimeoutError, RuntimeError):
        pass
    finally:
        active_websockets.pop(websocket, None)
        if sender:
            sender.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await sender
        with suppress(Exception):
            await websocket.close(code=1008)


class ParserFailure(Exception):
    def __init__(self, code, status=422):
        self.code, self.status = code, status
        super().__init__(code)


def _terminate_parser(proc):
    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    elif proc.poll() is None:
        # Kill the worker's TShark child too; never leave a timed-out capture reader.
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=10)
    proc.wait(timeout=10)


def parse_capture(path):
    """Single isolated worker contract: exact JSON array, or structured stderr/nonzero."""
    path = Path(path).resolve(strict=True)
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen([sys.executable, str(BASE_DIR / "pcap_parser.py"), str(path)],
                                cwd=str(BASE_DIR), stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                start_new_session=os.name == "posix")
        deadline = time.monotonic() + PARSER_TIMEOUT
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    raise ParserFailure("PARSER_TIMEOUT", 504)
                if os.fstat(output.fileno()).st_size > MAX_PARSER_OUTPUT or os.fstat(errors.fileno()).st_size > 1024 * 1024:
                    raise ParserFailure("PARSER_RESOURCE_LIMIT", 413)
                time.sleep(0.05)
            if os.fstat(output.fileno()).st_size > MAX_PARSER_OUTPUT:
                raise ParserFailure("PARSER_RESOURCE_LIMIT", 413)
            if proc.returncode:
                errors.seek(0)
                # Preserve the machine-readable code, never arbitrary stderr/configuration.
                code = "PARSER_FAILED"
                try:
                    error = json.loads(errors.read(65536))
                    candidate = error.get("code") or error.get("error")
                    if isinstance(candidate, dict):
                        candidate = candidate.get("code")
                    if isinstance(candidate, str) and candidate.replace("_", "").isalnum() and len(candidate) < 80:
                        code = candidate
                except (ValueError, AttributeError):
                    pass
                raise ParserFailure(code, 503 if "UNAVAILABLE" in code.upper() else 422)
            output.seek(0)
            try:
                sessions = json.load(output)
            except (ValueError, UnicodeError):
                raise ParserFailure("INVALID_PARSER_OUTPUT", 502)
            if not isinstance(sessions, list) or len(sessions) > MAX_SESSIONS or any(not isinstance(s, dict) for s in sessions):
                raise ParserFailure("INVALID_PARSER_OUTPUT", 502)
            return sessions
        finally:
            if proc.poll() is None:
                _terminate_parser(proc)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _analyze_sync(path, source):
    digest = _sha256(path)
    sessions = parse_capture(path)
    analysis_id = str(uuid.uuid4())
    provenance = {"capture_source": source, "capture_sha256": digest, "analysis_id": analysis_id,
                  "analysis_time": datetime.now(timezone.utc).isoformat(), "python": sys.version.split()[0],
                  "source_sha256": {name: _sha256(BASE_DIR / name) for name in
                                    ("pcap_parser.py", "risk_engine.py", "certificate_analyzer.py")}}
    provenance["packages"] = {}
    for package in ("pyshark", "cryptography", "scikit-learn"):
        with suppress(importlib.metadata.PackageNotFoundError):
            provenance["packages"][package] = importlib.metadata.version(package)
    evaluated = []
    for index, session in enumerate(sessions):
        result = {**session, **risk_engine.evaluate_session_risk(session)}
        result.update(analysis_id=analysis_id, session_id=f"{analysis_id}:{index}", capture_sha256=digest,
                      provenance=provenance, is_mitigated=False)
        evaluated.append(map_risk_to_frontend_format(result))
    database.save_analysis(analysis_id, digest, source, evaluated, provenance)
    return analysis_id, digest, evaluated


async def analyze_capture(path, source):
    global _last_analysis
    try:
        await asyncio.wait_for(_ingestion_slots.acquire(), timeout=0.1)
    except asyncio.TimeoutError:
        raise HTTPException(429, "Analysis workers busy; retry later")
    try:
        worker = asyncio.create_task(asyncio.to_thread(_analyze_sync, path, source))
        try:
            analysis_id, digest, evaluated = await asyncio.shield(worker)
        except asyncio.CancelledError:
            # Keep the worker slot and input file until the bounded worker has stopped.
            with suppress(Exception):
                await worker
            raise
    except ParserFailure as exc:
        raise HTTPException(exc.status, {"code": exc.code, "message": "Capture analysis did not complete"})
    finally:
        _ingestion_slots.release()
    _last_analysis = evaluated[-500:]
    for result in evaluated:
        await broadcast_message(json.dumps(result, default=str))
    scores = [r["score"] for r in evaluated if isinstance(r.get("score"), (int, float))]
    return {"status": "success" if evaluated else "no_sessions", "analysis_id": analysis_id,
            "capture_sha256": digest, "summary": {"streams_analyzed": len(evaluated),
            "average_score": round(sum(scores) / len(scores), 1) if scores else None,
            "critical": sum(r.get("status") == "critical" for r in evaluated),
            "high": sum(r.get("status") == "high" for r in evaluated)}, "results": evaluated}


@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in (".pcap", ".pcapng"):
        raise HTTPException(400, "Only .pcap and .pcapng files are accepted")
    path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            path = tmp.name
            total = 0
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_PCAP_SIZE:
                    raise HTTPException(413, "Capture exceeds size limit")
                await asyncio.to_thread(tmp.write, chunk)
        if not total:
            raise HTTPException(400, "Capture is empty")
        result = await analyze_capture(path, "upload")
        result["filename"] = Path(file.filename).name
        return result
    finally:
        await file.close()
        if path:
            with suppress(FileNotFoundError):
                os.unlink(path)


@app.post("/api/pcap/demo")
async def run_demo_simulation():
    # Do not regenerate or overwrite the user's packaged capture.
    path = BASE_DIR / "SIH_Final_Demo.pcap"
    if not path.is_file():
        raise HTTPException(404, "Synthetic demo capture is not installed")
    result = await analyze_capture(path, "synthetic_demo_not_validation_baseline")
    result["synthetic"] = True
    return result


async def bulk_pcap_watchdog():
    """Only finalized *.ready capture names are eligible; producers rename atomically."""
    for directory in (INGRESS_DIR, PROCESSED_DIR, FAILED_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    seen = {}
    while True:
        for path in list(INGRESS_DIR.iterdir())[:100]:
            if path.is_symlink() or not path.is_file() or not path.name.lower().endswith((".pcap.ready", ".pcapng.ready")):
                continue
            stat = path.stat()
            identity = (stat.st_size, stat.st_mtime_ns)
            if seen.get(path) != identity:
                seen[path] = identity
                continue
            claimed = path.with_name(path.name + ".processing")
            try:
                path.rename(claimed)
            except OSError:
                continue
            destination = PROCESSED_DIR
            try:
                if not 0 < stat.st_size <= MAX_PCAP_SIZE:
                    raise HTTPException(413, "Invalid capture size")
                await analyze_capture(claimed, "bulk_finalized_file")
            except HTTPException as exc:
                if exc.status_code == 429:
                    claimed.rename(path)
                    continue
                destination = FAILED_DIR
            except Exception:
                destination = FAILED_DIR
            finally:
                seen.pop(path, None)
            if claimed.exists():
                await asyncio.to_thread(shutil.move, str(claimed), str(destination / (uuid.uuid4().hex + "-" + path.name)))
        seen = {p: identity for p, identity in seen.items() if p.exists()}
        await asyncio.sleep(5)


class CaptureConfig(BaseModel):
    interface: str = ""


@app.post("/api/capture/start")
@app.post("/api/pcap/sniff/start")
async def start_capture(config: CaptureConfig = CaptureConfig()):
    raise HTTPException(503, capture_state)


@app.post("/api/capture/stop")
@app.post("/api/pcap/sniff/stop")
async def stop_capture():
    return {**capture_state, "active": False}


@app.get("/api/sessions/history")
async def get_history(limit: int = Query(200, ge=1, le=10000), analysis_id: str | None = None):
    return [_map_row(row) for row in await asyncio.to_thread(database.get_recent_sessions, limit, analysis_id)]


class SOARRequest(BaseModel):
    ips: list[str] = Field(min_length=1, max_length=100)
    analysis_id: str
    confirm: bool = False
    scope: str = "host_input"


async def _response(req, rollback=False):
    if not req.confirm or req.scope != "host_input":
        raise HTTPException(400, "Explicit confirm=true and scope=host_input required")
    try:
        ips = list(dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in req.ips))
    except ValueError:
        raise HTTPException(422, "Every target must be a valid IP address")
    rows = await get_history(10000, req.analysis_id)
    endpoints = {r.get(key) for r in rows for key in ("src_ip", "dst_ip")}
    if not rows or any(ip not in endpoints for ip in ips):
        raise HTTPException(400, "Targets must be observed endpoints in the selected analysis")
    outcomes = {}
    async with _response_lock:
        for ip in ips:
            action = ips_engine.rollback_ip if rollback else ips_engine.block_ip
            outcome = await asyncio.to_thread(action, ip)
            # Host INPUT enforcement is not evidence of protection for the captured remote flow.
            outcome["is_mitigated"] = False
            outcome["analysis_scope_verified"] = False
            await asyncio.to_thread(database.record_response, req.analysis_id, ip, "rollback" if rollback else "block", outcome)
            outcomes[ip] = outcome
    await broadcast_message(json.dumps({"type": "response_outcomes", "analysis_id": req.analysis_id, "ips_results": outcomes}))
    statuses = {outcome["status"] for outcome in outcomes.values()}
    status = next(iter(statuses)) if len(statuses) == 1 else "PARTIAL_RESPONSE"
    return {"status": status, "ips_results": outcomes, "message": "Per-IP host firewall outcomes; captured sessions are not marked mitigated."}


@app.post("/api/soar/deploy")
async def deploy_soar_playbook(req: SOARRequest):
    return await _response(req)


@app.post("/api/soar/rollback")
async def rollback_soar_playbook(req: SOARRequest):
    return await _response(req, rollback=True)


@app.get("/api/report/{kind}")
async def export_report(kind: str, analysis_id: str = Query(..., min_length=1, max_length=100)):
    generators = {"json": (report_generator.generate_json_report, "application/json"),
                  "html": (report_generator.generate_html_report, "text/html"),
                  "pdf": (report_generator.generate_pdf_report, "application/pdf"),
                  "ids": (report_generator.generate_suricata_rules, "text/plain"),
                  "stix": (report_generator.generate_stix_bundle, "application/json")}
    if kind not in generators:
        raise HTTPException(404, "Unknown report format")
    rows = await get_history(MAX_SESSIONS, analysis_id)
    if not rows and not await asyncio.to_thread(database.analysis_exists, analysis_id):
        raise HTTPException(404, "Analysis not found")
    generator, media_type = generators[kind]
    content = await asyncio.to_thread(generator, rows)
    return Response(content=content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="securemailscope_report.{kind}"',
                             "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})


@app.delete("/api/sessions/flush")
async def flush_database():
    global _last_analysis
    await asyncio.to_thread(database.flush_sessions)
    _last_analysis = []
    await broadcast_message(json.dumps({"type": "snapshot", "sessions": []}))
    return {"status": "success", "message": "Analysis history removed; response audit retained"}


@app.get("/api/health")
async def health():
    db = await asyncio.to_thread(database.readiness)
    tshark = os.getenv("TSHARK_PATH") or shutil.which("tshark")
    parser_ready = bool(tshark and Path(tshark).is_file() and importlib.util.find_spec("pyshark"))
    detector = getattr(risk_engine, "_anomaly_detector", None) or getattr(risk_engine, "detector", None)
    return {"status": "ready_for_passive_analysis" if parser_ready and db == "ready" else "degraded",
            "version": "2.1.0", "database": db, "parser": "available_not_self_tested" if parser_ready else "unavailable",
            "ml": "loaded_not_validated" if getattr(detector, "is_fitted", False) else "unavailable_or_not_loaded",
            "yara": "installed_not_self_tested" if importlib.util.find_spec("yara") else "unavailable",
            "live_capture_active": False, "capture": capture_state, "ips_dry_run": ips_engine.IPS_DRY_RUN_DEFAULT,
            "response_enabled": os.getenv("ENABLE_ACTIVE_RESPONSE", "0") == "1",
            "bulk_ingest": "running" if any(not t.done() for t in _background_tasks) else "disabled",
            "ingress_path": str(INGRESS_DIR), "bulk_file_contract": "atomic rename to *.pcap.ready or *.pcapng.ready"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")),
                reload=False, proxy_headers=False, ws_max_size=8192, ws_max_queue=16)
