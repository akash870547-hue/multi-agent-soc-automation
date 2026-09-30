from datetime import datetime, timezone
import ipaddress
import json
import os
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
from collections import defaultdict, deque

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from .correlation import correlate_event
from .models import SecurityEvent
from .pipeline import process_event
from .threat_intel import enrich_indicator

app = FastAPI(title="Multi-Agent SOC Automation API", version="0.5.0")

_cors_origins = [
    origin.strip()
    for origin in os.getenv("SOC_CORS_ORIGINS", "https://akash870547-hue.github.io").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Actor"],
)

DB_PATH = os.getenv("SOC_DB_PATH", "soc_automation.db")
API_KEY = os.getenv("SOC_API_KEY")
ROLE_KEYS = {
    "analyst": os.getenv("SOC_ANALYST_KEY"),
    "responder": os.getenv("SOC_RESPONDER_KEY"),
    "admin": os.getenv("SOC_ADMIN_KEY"),
}
RATE_LIMIT = int(os.getenv("SOC_RATE_LIMIT", "60"))
RATE_WINDOW = int(os.getenv("SOC_RATE_WINDOW_SECONDS", "60"))
MONITOR_INTERVAL = int(os.getenv("SOC_MONITOR_INTERVAL_SECONDS", "300"))
_request_log: dict[str, deque[float]] = defaultdict(deque)


class MonitorTarget(BaseModel):
    url: HttpUrl
    name: str | None = None


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with db() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
            resource_id TEXT, actor TEXT NOT NULL, created_at TEXT NOT NULL)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS monitor_targets (
            target_id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, name TEXT,
            status TEXT NOT NULL, status_code INTEGER, response_ms REAL,
            last_checked TEXT, last_error TEXT)""")


init_db()


def save_event(event: SecurityEvent):
    with db() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO events(event_id, payload, created_at) VALUES (?, ?, ?)",
            (event.event_id, json.dumps(event.model_dump(mode="json")), iso_now()),
        )


def save_incident(incident: dict):
    with db() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO incidents(incident_id, payload, updated_at) VALUES (?, ?, ?)",
            (incident["incident_id"], json.dumps(incident), iso_now()),
        )


def audit(action: str, resource_id: str | None, actor: str):
    with db() as connection:
        connection.execute(
            "INSERT INTO audit_logs(action, resource_id, actor, created_at) VALUES (?, ?, ?, ?)",
            (action, resource_id, actor, iso_now()),
        )


def load_incidents() -> list[dict]:
    with db() as connection:
        rows = connection.execute("SELECT payload FROM incidents ORDER BY updated_at ASC").fetchall()
    return [json.loads(row["payload"]) for row in rows]


def load_events() -> list[dict]:
    with db() as connection:
        rows = connection.execute("SELECT payload FROM events ORDER BY created_at ASC").fetchall()
    return [json.loads(row["payload"]) for row in rows]


def find_event(event_id: str) -> dict | None:
    with db() as connection:
        row = connection.execute("SELECT payload FROM events WHERE event_id = ?", (event_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


def get_incident_or_404(incident_id: str) -> dict:
    with db() as connection:
        row = connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return json.loads(row["payload"])


def rate_limit(client_key: str):
    now = time.time()
    bucket = _request_log[client_key]
    while bucket and now - bucket[0] > RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)


def authenticate(x_api_key: str | None) -> tuple[str, str]:
    if not (API_KEY or any(ROLE_KEYS.values())):
        return "local", "admin"
    if API_KEY and x_api_key == API_KEY:
        return "api-client", "admin"
    for role, key in ROLE_KEYS.items():
        if key and x_api_key == key:
            return role, role
    raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_role(x_api_key: str | None, allowed_roles: set[str]) -> tuple[str, str]:
    actor, role = authenticate(x_api_key)
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient role permissions")
    return actor, role


def safe_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Only HTTPS monitoring targets are allowed")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid monitoring target")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail=f"DNS resolution failed: {exc}")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise HTTPException(status_code=400, detail="Private or local network targets are not allowed")


def check_target(target_id: str, url: str, name: str | None = None, actor: str = "monitor"):
    safe_public_url(url)
    started = time.perf_counter()
    status = "up"
    status_code = None
    error = None
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Multi-Agent-SOC-Monitor/0.5"})
        with urllib.request.urlopen(request, timeout=10) as response:
            status_code = response.status
            response.read(64)
            if status_code >= 400:
                status = "degraded"
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        status = "degraded" if exc.code < 500 else "down"
        error = str(exc)
    except Exception as exc:
        status = "down"
        error = str(exc)
    response_ms = round((time.perf_counter() - started) * 1000, 2)
    previous = None
    with db() as connection:
        row = connection.execute(
            "SELECT status FROM monitor_targets WHERE target_id = ?", (target_id,)
        ).fetchone()
        previous = row["status"] if row else None
        connection.execute(
            """UPDATE monitor_targets SET status=?, status_code=?, response_ms=?,
               last_checked=?, last_error=?, name=? WHERE target_id=?""",
            (status, status_code, response_ms, iso_now(), error, name, target_id),
        )
    if previous and previous != status and status in {"down", "degraded"}:
        event = SecurityEvent(
            event_id=f"WEB-{int(time.time()*1000)}",
            source="website-monitor",
            event_type="availability",
            source_ip="0.0.0.0",
            destination_ip="0.0.0.0",
            message=f"Website monitor: {name or url} changed from {previous} to {status}. HTTP={status_code}.",
        )
        save_event(event)
        result = process_event(event)
        if result:
            result["findings"].append(f"Website monitoring detected a state transition for {url}.")
            save_incident(result)
        audit("website_state_change", target_id, actor)
    return {"target_id": target_id, "url": url, "name": name, "status": status,
            "status_code": status_code, "response_ms": response_ms,
            "last_checked": iso_now(), "last_error": error}


@app.get("/health")
def health():
    return {"status": "ok", "service": "multi-agent-soc", "storage": "sqlite", "version": "0.5.0"}


@app.get("/ready")
def ready():
    try:
        with db() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ready", "storage": "sqlite"}
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {exc}")


@app.get("/api/me")
def me(x_api_key: str | None = Header(default=None)):
    actor, role = authenticate(x_api_key)
    return {"actor": actor, "role": role, "permissions": {
        "ingest": role in {"admin", "responder", "analyst"},
        "acknowledge": role in {"admin", "responder", "analyst"},
        "approve": role in {"admin", "responder"},
        "resolve": role in {"admin", "responder"},
        "audit_logs": role == "admin",
        "website_monitor": role == "admin",
        "monitor_check": role in {"admin", "responder", "analyst"},
    }}


@app.get("/api/agents")
def agents():
    return {"agents": [
        {"name": "Triage Agent", "status": "ready"},
        {"name": "Threat Intelligence Agent", "status": "ready"},
        {"name": "Investigation Agent", "status": "ready"},
        {"name": "Response Agent", "status": "approval_required"},
        {"name": "Reporting Agent", "status": "ready"},
    ]}


@app.get("/api/incidents")
def list_incidents():
    return load_incidents()


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    return get_incident_or_404(incident_id)


@app.post("/api/incidents/{incident_id}/approve")
def approve_incident(incident_id: str, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin", "responder"})
    incident = get_incident_or_404(incident_id)
    incident["governance"]["approved"] = True
    incident["governance"]["approved_at"] = iso_now()
    incident["approved_actions"] = incident["recommendations"]
    save_incident(incident)
    audit("approve_incident", incident_id, x_actor or actor)
    return incident


@app.post("/api/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: str, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin", "responder", "analyst"})
    incident = get_incident_or_404(incident_id)
    if not incident.get("acknowledged_at"):
        incident["acknowledged_at"] = iso_now()
    if incident["status"] == "open":
        incident["status"] = "investigating"
    save_incident(incident)
    audit("acknowledge_incident", incident_id, x_actor or actor)
    return incident


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin", "responder"})
    incident = get_incident_or_404(incident_id)
    if not incident.get("acknowledged_at"):
        incident["acknowledged_at"] = iso_now()
    incident["resolved_at"] = iso_now()
    incident["status"] = "resolved"
    save_incident(incident)
    audit("resolve_incident", incident_id, x_actor or actor)
    return incident


@app.post("/api/events")
def ingest_event(event: SecurityEvent, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin", "responder", "analyst"})
    rate_limit(x_api_key or "anonymous")
    prior_events = load_events()
    save_event(event)
    result = process_event(event)
    if result:
        result["correlation"] = correlate_event(event, prior_events)
        if result["correlation"]["matched"]:
            result["findings"].append(f"Correlated with {len(result['correlation']['related_events'])} recent event(s) using shared security pivots.")
        save_incident(result)
    audit("ingest_event", event.event_id, x_actor or actor)
    return {"detected": result is not None, "incident": result}


@app.get("/api/threat-intel/{indicator}")
def threat_intel(indicator: str):
    return enrich_indicator(indicator)


@app.get("/api/audit-logs")
def audit_logs(limit: int = 50, x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin"})
    limit = max(1, min(limit, 200))
    with db() as connection:
        rows = connection.execute("SELECT action, resource_id, actor, created_at FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/monitor/targets")
def monitor_targets(x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin", "responder", "analyst"})
    with db() as connection:
        rows = connection.execute("SELECT * FROM monitor_targets ORDER BY name, url").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/monitor/targets")
def add_monitor_target(target: MonitorTarget, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin"})
    url = str(target.url)
    safe_public_url(url)
    target_id = f"WEB-{abs(hash(url))}"
    try:
        with db() as connection:
            connection.execute(
                "INSERT INTO monitor_targets(target_id,url,name,status) VALUES (?,?,?,?)",
                (target_id, url, target.name or url, "unknown"),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Monitoring target already exists")
    audit("add_monitor_target", target_id, x_actor or actor)
    return check_target(target_id, url, target.name or url, x_actor or actor)


@app.post("/api/monitor/targets/{target_id}/check")
def monitor_target_check(target_id: str, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin", "responder", "analyst"})
    with db() as connection:
        row = connection.execute("SELECT * FROM monitor_targets WHERE target_id=?", (target_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Monitoring target not found")
    return check_target(target_id, row["url"], row["name"], x_actor or actor)


@app.get("/api/metrics")
def metrics():
    values = load_incidents()
    mttd_values, mttr_values = [], []
    for incident in values:
        event = find_event(incident["alert"]["event_id"])
        if not event:
            continue
        try:
            event_time = datetime.fromisoformat(event["timestamp"])
            detected_time = datetime.fromisoformat(incident["detected_at"])
            mttd_values.append(max(0.0, (detected_time - event_time).total_seconds()))
            if incident.get("resolved_at"):
                start = datetime.fromisoformat(incident.get("acknowledged_at") or incident["detected_at"])
                resolved = datetime.fromisoformat(incident["resolved_at"])
                mttr_values.append(max(0.0, (resolved - start).total_seconds()))
        except (KeyError, TypeError, ValueError):
            continue
    return {
        "active_alerts": sum(1 for x in values if x["status"] == "open"),
        "critical": sum(1 for x in values if x["alert"]["severity"] == "critical"),
        "investigating": sum(1 for x in values if x["status"] == "investigating"),
        "resolved": sum(1 for x in values if x["status"] == "resolved"),
        "events_ingested": len(load_events()),
        "mttd_seconds": round(sum(mttd_values)/len(mttd_values), 2) if mttd_values else None,
        "mttr_seconds": round(sum(mttr_values)/len(mttr_values), 2) if mttr_values else None,
    }


def monitor_loop():
    while True:
        try:
            with db() as connection:
                rows = connection.execute("SELECT target_id,url,name FROM monitor_targets").fetchall()
            for row in rows:
                try:
                    check_target(row["target_id"], row["url"], row["name"])
                except Exception:
                    pass
        finally:
            time.sleep(max(60, MONITOR_INTERVAL))


if os.getenv("SOC_ENABLE_WEBSITE_MONITOR", "true").lower() == "true":
    threading.Thread(target=monitor_loop, daemon=True, name="website-monitor").start()
