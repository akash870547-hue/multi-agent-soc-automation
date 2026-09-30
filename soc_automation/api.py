from datetime import datetime, timezone
import ipaddress
import json
import os
import hashlib
import hmac
import secrets
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import ssl
from urllib.parse import urlparse
from collections import defaultdict, deque

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from .correlation import correlate_event
from .models import SecurityEvent
from .pipeline import process_event
from .threat_intel import enrich_indicator

app = FastAPI(title="Multi-Agent SOC Automation API", version="0.6.0")

_cors_origins = [
    origin.strip()
    for origin in os.getenv("SOC_CORS_ORIGINS", "https://akash870547-hue.github.io").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
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


class ApiKeyCreate(BaseModel):
    role: str
    name: str


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
        connection.execute("""CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL,
            key_hash TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS monitor_targets (
            target_id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, name TEXT,
            status TEXT NOT NULL, status_code INTEGER, response_ms REAL,
            last_checked TEXT, last_error TEXT,
            security_headers TEXT, tls_info TEXT, redirect_chain TEXT,
            content_hash TEXT, content_checked INTEGER DEFAULT 1,
            findings TEXT)""")
        columns = {row[1] for row in connection.execute("PRAGMA table_info(monitor_targets)").fetchall()}
        migrations = {
            "security_headers": "TEXT",
            "tls_info": "TEXT",
            "redirect_chain": "TEXT",
            "content_hash": "TEXT",
            "content_checked": "INTEGER DEFAULT 1",
            "findings": "TEXT",
        }
        for column, definition in migrations.items():
            if column not in columns:
                connection.execute(f"ALTER TABLE monitor_targets ADD COLUMN {column} {definition}")
        connection.execute("""CREATE TABLE IF NOT EXISTS monitor_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            status TEXT NOT NULL,
            status_code INTEGER,
            response_ms REAL,
            findings TEXT NOT NULL)""")


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


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def authenticate(x_api_key: str | None) -> tuple[str, str]:
    if not (API_KEY or any(ROLE_KEYS.values())):
        return "local", "admin"
    if API_KEY and x_api_key == API_KEY:
        return "api-client", "admin"
    for role, key in ROLE_KEYS.items():
        if key and x_api_key == key:
            return role, role
    if x_api_key:
        digest = hash_api_key(x_api_key)
        with db() as connection:
            rows = connection.execute("SELECT key_id, role, key_hash FROM api_keys WHERE revoked_at IS NULL").fetchall()
        for row in rows:
            if hmac.compare_digest(digest, row["key_hash"]):
                return row["key_id"], row["role"]
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


REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


class RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"from": req.full_url, "to": newurl, "status_code": code})
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_301(self, req, fp, code, msg, headers):
        return self._record(req, fp, code, msg, headers.get("Location"))

    def http_error_302(self, req, fp, code, msg, headers):
        return self._record(req, fp, code, msg, headers.get("Location"))

    def http_error_303(self, req, fp, code, msg, headers):
        return self._record(req, fp, code, msg, headers.get("Location"))

    def http_error_307(self, req, fp, code, msg, headers):
        return self._record(req, fp, code, msg, headers.get("Location"))

    def http_error_308(self, req, fp, code, msg, headers):
        return self._record(req, fp, code, msg, headers.get("Location"))


def get_tls_info(hostname: str) -> dict:
    context = ssl.create_default_context()
    started = time.perf_counter()
    with socket.create_connection((hostname, 443), timeout=10) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            cert = tls_socket.getpeercert()
            cipher = tls_socket.cipher()
            version = tls_socket.version()
    not_after = cert.get("notAfter")
    expiry = None
    days = None
    if not_after:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        expiry = expiry_dt.isoformat()
        days = max(0, (expiry_dt - datetime.now(timezone.utc)).days)
    return {
        "valid": True,
        "expires_at": expiry,
        "days_to_expiry": days,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "check_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def check_target(target_id: str, url: str, name: str | None = None, actor: str = "monitor"):
    safe_public_url(url)
    started = time.perf_counter()
    status = "up"
    status_code = None
    error = None
    final_url = url
    redirect_tracker = RedirectTracker()
    headers_snapshot = {}
    content_hash = None
    tls_info = {"valid": False, "error": "not checked"}
    previous = None
    previous_snapshot = {}

    with db() as connection:
        row = connection.execute("SELECT * FROM monitor_targets WHERE target_id = ?", (target_id,)).fetchone()
        if row:
            previous = row["status"]
            for key in ("security_headers", "tls_info", "redirect_chain", "content_hash", "findings"):
                try:
                    previous_snapshot[key] = json.loads(row[key]) if row[key] else None
                except (TypeError, json.JSONDecodeError):
                    previous_snapshot[key] = row[key]

    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Multi-Agent-SOC-Monitor/0.6"})
        opener = urllib.request.build_opener(redirect_tracker)
        with opener.open(request, timeout=10) as response:
            status_code = response.status
            final_url = response.geturl()
            raw_body = response.read(1024 * 1024)
            content_hash = hashlib.sha256(raw_body).hexdigest()
            headers_snapshot = {str(k).lower(): str(v) for k, v in response.headers.items()}
            if status_code >= 500:
                status = "down"
            elif status_code >= 400:
                status = "degraded"
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        final_url = exc.geturl() or url
        headers_snapshot = {str(k).lower(): str(v) for k, v in exc.headers.items()}
        error = str(exc)
        status = "degraded" if exc.code < 500 else "down"
    except Exception as exc:
        status = "down"
        error = str(exc)

    hostname = urlparse(url).hostname
    try:
        tls_info = get_tls_info(hostname) if hostname else {"valid": False, "error": "missing hostname"}
    except Exception as exc:
        tls_info = {"valid": False, "error": str(exc)}

    response_ms = round((time.perf_counter() - started) * 1000, 2)
    redirect_chain = redirect_tracker.chain
    missing_headers = [label for header, label in REQUIRED_SECURITY_HEADERS.items() if header not in headers_snapshot]
    weak_security_headers = []
    if headers_snapshot.get("x-frame-options", "").upper() == "ALLOWALL":
        weak_security_headers.append("X-Frame-Options allows framing")
    if "strict-transport-security" in headers_snapshot and "max-age=" not in headers_snapshot["strict-transport-security"].lower():
        weak_security_headers.append("HSTS has no max-age directive")
    redirect_findings = []
    if any((item.get("to") or "").lower().startswith("http://") for item in redirect_chain):
        redirect_findings.append("Redirect chain contains an HTTP URL")
    if final_url.lower().startswith("http://"):
        redirect_findings.append("Final destination is HTTP")
    tls_findings = []
    if not tls_info.get("valid"):
        tls_findings.append("TLS certificate validation failed")
    elif tls_info.get("days_to_expiry") is not None:
        if tls_info["days_to_expiry"] <= 30:
            tls_findings.append(f"TLS certificate expires in {tls_info['days_to_expiry']} day(s)")
    findings = []
    findings.extend(f"Missing security header: {item}" for item in missing_headers)
    findings.extend(weak_security_headers)
    findings.extend(redirect_findings)
    findings.extend(tls_findings)
    if error:
        findings.append(f"Availability error: {error}")

    previous_headers = previous_snapshot.get("security_headers") or {}
    previous_tls = previous_snapshot.get("tls_info") or {}
    previous_hash = previous_snapshot.get("content_hash")
    alerts = []

    if previous and previous != status and status in {"down", "degraded"}:
        alerts.append(("availability", f"Website monitor: {name or url} changed from {previous} to {status}. HTTP={status_code}."))
    if previous_headers:
        newly_missing = [label for header, label in REQUIRED_SECURITY_HEADERS.items()
                         if header in previous_headers and header not in headers_snapshot]
        for label in newly_missing:
            alerts.append(("security_header", f"Website monitor: security header {label} was removed from {name or url}."))
    if previous_tls.get("days_to_expiry") is not None and tls_info.get("days_to_expiry") is not None:
        before = previous_tls["days_to_expiry"]
        after = tls_info["days_to_expiry"]
        if before > 30 >= after:
            alerts.append(("tls", f"Website monitor: TLS certificate for {name or url} expires in {after} day(s)."))
    if previous_hash and content_hash and previous_hash != content_hash:
        alerts.append(("content", f"Website monitor: monitored content changed for {name or url}. SHA-256={content_hash}."))
    previous_findings = previous_snapshot.get("findings") or []
    if redirect_findings and redirect_findings != previous_findings:
        alerts.append(("redirect", f"Website monitor: redirect security finding changed for {name or url}."))

    with db() as connection:
        connection.execute(
            """UPDATE monitor_targets SET status=?, status_code=?, response_ms=?,
               last_checked=?, last_error=?, security_headers=?, tls_info=?,
               redirect_chain=?, content_hash=?, findings=? WHERE target_id=?""",
            (status, status_code, response_ms, iso_now(), error,
             json.dumps(headers_snapshot), json.dumps(tls_info),
             json.dumps(redirect_chain), content_hash, json.dumps(findings), target_id),
        )
        connection.execute(
            """INSERT INTO monitor_checks
               (target_id,checked_at,status,status_code,response_ms,findings)
               VALUES (?,?,?,?,?,?)""",
            (target_id, iso_now(), status, status_code, response_ms, json.dumps(findings)),
        )

    for alert_type, message in alerts[:5]:
        event = SecurityEvent(
            event_id=f"WEB-{alert_type.upper()}-{int(time.time()*1000)}",
            source="website-monitor",
            event_type="web_security_monitor",
            source_ip="0.0.0.0",
            destination_ip="0.0.0.0",
            message=message,
        )
        save_event(event)
        result = process_event(event)
        if result:
            result["findings"].append(f"Website monitoring detected {alert_type} anomaly for {url}.")
            result["findings"].extend(findings[:6])
            save_incident(result)
        audit(f"website_{alert_type}_change", target_id, actor)

    return {
        "target_id": target_id,
        "url": url,
        "name": name,
        "status": status,
        "status_code": status_code,
        "response_ms": response_ms,
        "last_checked": iso_now(),
        "last_error": error,
        "final_url": final_url,
        "security_headers": headers_snapshot,
        "missing_security_headers": missing_headers,
        "tls": tls_info,
        "redirect_chain": redirect_chain,
        "content_hash": content_hash,
        "findings": findings,
        "alerts_generated": [item[0] for item in alerts[:5]],
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "multi-agent-soc", "storage": "sqlite", "version": "0.6.0"}


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


@app.get("/api/admin/api-keys")
def list_api_keys(x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin"})
    with db() as connection:
        rows = connection.execute("SELECT key_id,name,role,created_at,revoked_at FROM api_keys ORDER BY created_at DESC").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/admin/api-keys")
def create_api_key(request: ApiKeyCreate, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin"})
    role = request.role.lower().strip()
    if role not in {"analyst", "responder", "admin"}:
        raise HTTPException(status_code=400, detail="Role must be analyst, responder, or admin")
    name = request.name.strip()[:80]
    if not name:
        raise HTTPException(status_code=400, detail="Key name is required")
    raw_key = "soc_" + secrets.token_urlsafe(32)
    key_id = "key_" + secrets.token_hex(8)
    with db() as connection:
        connection.execute("INSERT INTO api_keys(key_id,name,role,key_hash,created_at) VALUES (?,?,?,?,?)",
                           (key_id, name, role, hash_api_key(raw_key), iso_now()))
    audit("create_api_key", key_id, x_actor or actor)
    return {"key_id": key_id, "name": name, "role": role, "api_key": raw_key,
            "warning": "Store this key securely. It will not be shown again."}


@app.post("/api/admin/api-keys/{key_id}/revoke")
def revoke_api_key(key_id: str, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin"})
    with db() as connection:
        row = connection.execute("SELECT key_id FROM api_keys WHERE key_id=?", (key_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="API key not found")
        connection.execute("UPDATE api_keys SET revoked_at=? WHERE key_id=?", (iso_now(), key_id))
    audit("revoke_api_key", key_id, x_actor or actor)
    return {"key_id": key_id, "revoked": True}


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
    output = []
    for row in rows:
        item = dict(row)
        for raw_key, out_key in [
            ("security_headers", "security_headers"),
            ("tls_info", "tls"),
            ("redirect_chain", "redirect_chain"),
            ("findings", "findings"),
        ]:
            raw = item.get(raw_key)
            try:
                item[out_key] = json.loads(raw) if raw else ([] if raw_key in {"redirect_chain", "findings"} else {})
            except (TypeError, json.JSONDecodeError):
                item[out_key] = raw
        headers = item.get("security_headers") or {}
        item["missing_security_headers"] = [
            label for header, label in REQUIRED_SECURITY_HEADERS.items()
            if header not in headers
        ]
        output.append(item)
    return output


@app.post("/api/monitor/targets")
def add_monitor_target(target: MonitorTarget, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin"})
    url = str(target.url)
    safe_public_url(url)
    target_id = "WEB-" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
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


@app.delete("/api/monitor/targets/{target_id}")
def delete_monitor_target(target_id: str, x_api_key: str | None = Header(default=None), x_actor: str | None = Header(default=None)):
    actor, _ = require_role(x_api_key, {"admin"})
    with db() as connection:
        row = connection.execute("SELECT target_id FROM monitor_targets WHERE target_id=?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Monitoring target not found")
        connection.execute("DELETE FROM monitor_checks WHERE target_id=?", (target_id,))
        connection.execute("DELETE FROM monitor_targets WHERE target_id=?", (target_id,))
    audit("delete_monitor_target", target_id, x_actor or actor)
    return {"target_id": target_id, "deleted": True}


@app.get("/api/monitor/targets/{target_id}/history")
def monitor_target_history(target_id: str, limit: int = 30, x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin", "responder", "analyst"})
    limit = max(1, min(limit, 100))
    with db() as connection:
        target = connection.execute("SELECT target_id FROM monitor_targets WHERE target_id=?", (target_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Monitoring target not found")
        rows = connection.execute(
            "SELECT id,target_id,checked_at,status,status_code,response_ms,findings FROM monitor_checks WHERE target_id=? ORDER BY id DESC LIMIT ?",
            (target_id, limit),
        ).fetchall()
    return [
        {
            **{key: row[key] for key in ("id", "target_id", "checked_at", "status", "status_code", "response_ms")},
            "findings": json.loads(row["findings"]) if row["findings"] else [],
        }
        for row in rows
    ]


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
