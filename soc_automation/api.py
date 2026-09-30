from datetime import datetime, timezone, timedelta
import base64
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

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from .correlation import correlate_event
from .models import SecurityEvent
from .pipeline import process_event
from .threat_intel import enrich_indicator

app = FastAPI(title="Multi-Agent SOC Automation API", version="0.12.0")

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
    allow_headers=["Content-Type", "X-API-Key", "X-Actor", "X-Visitor-ID", "X-Visitor-Name"],
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
PUBLIC_TEST_RATE_LIMIT = int(os.getenv("SOC_PUBLIC_TEST_RATE_LIMIT", "10"))
PUBLIC_TEST_RATE_WINDOW = int(os.getenv("SOC_PUBLIC_TEST_RATE_WINDOW_SECONDS", "60"))
PUBLIC_TELEMETRY_RATE_LIMIT = int(os.getenv("SOC_PUBLIC_TELEMETRY_RATE_LIMIT", "120"))
PUBLIC_TELEMETRY_RATE_WINDOW = int(os.getenv("SOC_PUBLIC_TELEMETRY_RATE_WINDOW_SECONDS", "60"))
PUBLIC_MITRE_RATE_LIMIT = int(os.getenv("SOC_PUBLIC_MITRE_RATE_LIMIT", "6"))
PUBLIC_MITRE_RATE_WINDOW = int(os.getenv("SOC_PUBLIC_MITRE_RATE_WINDOW_SECONDS", "60"))
MITRE_ENTERPRISE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"
MITRE_ENTERPRISE_URL = "https://attack.mitre.org/techniques/"
MITRE_CACHE_TTL = int(os.getenv("SOC_MITRE_CACHE_TTL_SECONDS", "86400"))
_mitre_cache = {"expires": 0.0, "payload": None}
_request_log: dict[str, deque[float]] = defaultdict(deque)


class MonitorTarget(BaseModel):
    url: HttpUrl
    name: str | None = None


class ApiKeyCreate(BaseModel):
    role: str
    name: str


class UserGenerate(BaseModel):
    role: str
    username: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class UserRegister(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class PublicTelemetry(BaseModel):
    visitor_id: str
    visitor_name: str
    action: str
    page: str | None = None
    detail: dict | None = None


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

PASSWORD_ITERATIONS = 310000
ALLOWED_USER_ROLES = {"admin", "analyst"}
RESERVED_USER_ROLES = {"super_admin"}


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS, dklen=32)
    return "pbkdf2_sha256$" + str(PASSWORD_ITERATIONS) + "$" +         base64.urlsafe_b64encode(salt).decode().rstrip("=") + "$" +         base64.urlsafe_b64encode(derived).decode().rstrip("=")


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
        expected = base64.urlsafe_b64decode(digest_b64 + "=" * (-len(digest_b64) % 4))
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations), dklen=len(expected))
        return hmac.compare_digest(derived, expected)
    except (ValueError, TypeError):
        return False


def ensure_bootstrap_admin(connection: sqlite3.Connection) -> None:
    username = os.getenv("SOC_BOOTSTRAP_ADMIN_USERNAME", "").strip()
    password_hash = os.getenv("SOC_BOOTSTRAP_ADMIN_PASSWORD_HASH", "").strip()
    if not username or not password_hash:
        return
    row = connection.execute("SELECT user_id FROM users WHERE username=?", (username,)).fetchone()
    if row:
        connection.execute(
            "UPDATE users SET role='admin', password_hash=?, revoked_at=NULL WHERE user_id=?",
            (password_hash, row["user_id"]),
        )
        return
    connection.execute(
        "INSERT INTO users(user_id,username,role,password_hash,created_at) VALUES (?,?,?,?,?)",
        ("usr_" + secrets.token_hex(8), username, "admin", password_hash, iso_now()),
    )


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
        connection.execute("""CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL, password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL, revoked_at TEXT)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT)""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id, created_at DESC)")
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
        connection.execute("""CREATE TABLE IF NOT EXISTS public_visitors (
            visitor_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            referrer TEXT,
            visitor_name TEXT,
            current_page TEXT,
            last_action TEXT,
            total_events INTEGER NOT NULL DEFAULT 0,
            total_tests INTEGER NOT NULL DEFAULT 0)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS public_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            page TEXT,
            detail TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL)""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_public_activity_created ON public_activity(created_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_public_activity_visitor ON public_activity(visitor_id, created_at DESC)")
        columns = {row[1] for row in connection.execute("PRAGMA table_info(public_visitors)").fetchall()}
        if "visitor_name" not in columns:
            connection.execute("ALTER TABLE public_visitors ADD COLUMN visitor_name TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_public_visitors_last_seen ON public_visitors(last_seen DESC)")
        ensure_bootstrap_admin(connection)


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


def rate_limit(client_key: str, limit: int | None = None, window: int | None = None):
    now = time.time()
    effective_limit = limit if limit is not None else RATE_LIMIT
    effective_window = window if window is not None else RATE_WINDOW
    bucket = _request_log[client_key]
    while bucket and now - bucket[0] > effective_window:
        bucket.popleft()
    if len(bucket) >= effective_limit:
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
            rows = connection.execute(
                "SELECT key_id, role, key_hash, name FROM api_keys WHERE revoked_at IS NULL"
            ).fetchall()
            for row in rows:
                if hmac.compare_digest(digest, row["key_hash"]):
                    actor = row["name"].removeprefix("session:")
                    if row["name"].startswith("session:"):
                        user_row = connection.execute(
                            "SELECT revoked_at FROM users WHERE username=?",
                            (actor,),
                        ).fetchone()
                        if not user_row or user_row["revoked_at"]:
                            continue
                    return actor or row["key_id"], row["role"]

    raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_role(x_api_key: str | None, allowed_roles: set[str]) -> tuple[str, str]:
    actor, role = authenticate(x_api_key)
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient role permissions")
    return actor, role


PUBLIC_ACTIONS = {
    "page_view",
    "heartbeat",
    "visibility_change",
    "attack_selected",
    "attack_test",
    "web_test_started",
    "web_test_completed",
    "web_test_failed",
    "mitre_library_opened",
    "mitre_search",
    "mitre_technique_opened",
    "demo_started",
    "demo_step",
    "demo_completed",
    "demo_report_generated",
}

def _public_client_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"

def _clean_public_detail(detail: dict | None) -> dict:
    if not detail:
        return {}
    cleaned = {}
    for key, value in list(detail.items())[:20]:
        key = str(key)[:80]
        if isinstance(value, (str, int, float, bool)) or value is None:
            cleaned[key] = value
        elif isinstance(value, (list, tuple)):
            cleaned[key] = [str(item)[:200] for item in value[:20]]
        else:
            cleaned[key] = str(value)[:500]
    return cleaned

def _public_name(value: str | None) -> str:
    name = " ".join(str(value or "").strip().split())
    if len(name) < 2 or len(name) > 80:
        raise HTTPException(status_code=400, detail="A valid participant name is required")
    return name

def record_public_activity(
    visitor_id: str,
    visitor_name: str,
    action: str,
    request: Request,
    page: str | None = None,
    detail: dict | None = None,
) -> None:
    visitor_id = str(visitor_id or "").strip()
    action = str(action or "").strip().lower()
    name = _public_name(visitor_name)
    if not visitor_id or len(visitor_id) > 80 or action not in PUBLIC_ACTIONS:
        raise HTTPException(status_code=400, detail="Invalid public telemetry payload")
    client_host = _public_client_host(request)
    now = iso_now()
    page_value = str(page or "/")[:240]
    detail_value = _clean_public_detail(detail)
    detail_json = json.dumps(detail_value, separators=(",", ":"), ensure_ascii=True)[:5000]
    user_agent = request.headers.get("user-agent", "")[:300]
    referrer = request.headers.get("referer", "")[:500]
    is_test = action in {"attack_test", "web_test_started", "web_test_completed", "web_test_failed", "demo_report_generated"}
    with db() as connection:
        connection.execute(
            """INSERT INTO public_visitors
               (visitor_id,first_seen,last_seen,ip_address,user_agent,referrer,visitor_name,current_page,last_action,total_events,total_tests)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(visitor_id) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 ip_address=excluded.ip_address,
                 user_agent=excluded.user_agent,
                 referrer=excluded.referrer,
                 visitor_name=excluded.visitor_name,
                 current_page=excluded.current_page,
                 last_action=excluded.last_action,
                 total_events=public_visitors.total_events + 1,
                 total_tests=public_visitors.total_tests + excluded.total_tests""",
            (visitor_id, now, now, client_host, user_agent, referrer, name, page_value, action, 1, 1 if is_test else 0),
        )
        connection.execute(
            """INSERT INTO public_activity
               (visitor_id,action,page,detail,ip_address,user_agent,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (visitor_id, action, page_value, detail_json, client_host, user_agent, now),
        )

def load_mitre_techniques() -> dict:
    now = time.time()
    cached = _mitre_cache.get("payload")
    if cached and _mitre_cache.get("expires", 0) > now:
        return cached
    request = urllib.request.Request(
        MITRE_ENTERPRISE_STIX_URL,
        headers={"User-Agent": "Multi-Agent-SOC-MITRE-Catalog/1.0"},
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        raw = response.read(8 * 1024 * 1024)
    bundle = json.loads(raw.decode("utf-8"))
    techniques = []
    for item in bundle.get("objects", []):
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        external_id = None
        for ref in item.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                break
        if not external_id:
            continue
        attack_path = external_id.replace(".", "/")
        techniques.append({
            "id": external_id,
            "name": item.get("name", ""),
            "description": str(item.get("description", "")).strip(),
            "type": "sub-technique" if "." in external_id else "technique",
            "parent_id": external_id.split(".", 1)[0] if "." in external_id else None,
            "tactics": [str(p.get("phase_name", "")).replace("-", " ").title() for p in item.get("kill_chain_phases", []) if p.get("phase_name")],
            "platforms": item.get("x_mitre_platforms", []) or [],
            "url": f"https://attack.mitre.org/techniques/{attack_path}/",
        })
    techniques.sort(key=lambda row: row["id"])
    payload = {
        "version": "19.2",
        "released": "2026-08-05",
        "source": MITRE_ENTERPRISE_URL,
        "source_data": MITRE_ENTERPRISE_STIX_URL,
        "count": len(techniques),
        "techniques": techniques,
    }
    _mitre_cache["payload"] = payload
    _mitre_cache["expires"] = now + MITRE_CACHE_TTL
    return payload

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
        return self.redirect_request(req, fp, code, msg, headers, headers.get("Location"))

    def http_error_302(self, req, fp, code, msg, headers):
        return self.redirect_request(req, fp, code, msg, headers, headers.get("Location"))

    def http_error_303(self, req, fp, code, msg, headers):
        return self.redirect_request(req, fp, code, msg, headers, headers.get("Location"))

    def http_error_307(self, req, fp, code, msg, headers):
        return self.redirect_request(req, fp, code, msg, headers, headers.get("Location"))

    def http_error_308(self, req, fp, code, msg, headers):
        return self.redirect_request(req, fp, code, msg, headers, headers.get("Location"))


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
    return {"status": "ok", "service": "multi-agent-soc", "storage": "sqlite", "version": "0.12.0"}


@app.get("/ready")
def ready():
    try:
        with db() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ready", "storage": "sqlite"}
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503, detail=f"Storage unavailable: {exc}")


@app.post("/api/auth/register")
def register_user(payload: UserRegister, http_request: Request):
    rate_limit(f"register:{_public_client_host(http_request)}", 5, 600)
    username = payload.username.strip().lower()
    role = payload.role.lower().strip()
    if role != "analyst":
        raise HTTPException(status_code=403, detail="Public registration is limited to Analyst accounts")
    if not username or len(username) > 40 or not username.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Username may contain only letters, numbers, underscores, or hyphens")
    if len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    password_hash = hash_password(payload.password)
    user_id = "usr_" + secrets.token_hex(8)
    try:
        with db() as connection:
            connection.execute(
                "INSERT INTO users(user_id,username,role,password_hash,created_at) VALUES (?,?,?,?,?)",
                (user_id, username, role, password_hash, iso_now()),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    audit("self_register", user_id, "public")
    return {"registered": True, "user_id": user_id, "username": username, "role": role}

@app.post("/api/auth/login")
def login(request: LoginRequest):
    username = request.username.strip()
    if not username or not request.password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    with db() as connection:
        row = connection.execute(
            "SELECT user_id, username, role, password_hash FROM users WHERE username=? AND revoked_at IS NULL",
            (username,),
        ).fetchone()
    if not row or not verify_password(request.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    raw_session = "soc_session_" + secrets.token_urlsafe(36)
    key_id = "sess_" + secrets.token_hex(8)
    with db() as connection:
        connection.execute(
            "INSERT INTO api_keys(key_id,name,role,key_hash,created_at) VALUES (?,?,?,?,?)",
            (key_id, "session:" + row["username"], row["role"], hash_api_key(raw_session), iso_now()),
        )
    return {"session_token": raw_session, "username": row["username"], "role": row["role"], "expires": "session"}


@app.get("/api/auth/users")
def list_users(x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin"})
    with db() as connection:
        rows = connection.execute(
            "SELECT user_id,username,role,created_at,revoked_at FROM users ORDER BY username"
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/auth/users/{user_id}/reset-token")
def create_password_reset(
    user_id: str,
    x_api_key: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
):
    actor, _ = require_role(x_api_key, {"admin"})
    raw_token = secrets.token_urlsafe(24)
    token_hash = hash_api_key(raw_token)
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=15)
    with db() as connection:
        row = connection.execute("SELECT user_id,username,revoked_at FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        if row["revoked_at"]:
            raise HTTPException(status_code=400, detail="Cannot reset a revoked user")
        connection.execute("UPDATE password_resets SET used_at=? WHERE user_id=? AND used_at IS NULL", (iso_now(), user_id))
        connection.execute(
            "INSERT INTO password_resets(user_id,token_hash,created_at,expires_at) VALUES (?,?,?,?)",
            (user_id, token_hash, created, expires),
        )
    audit("create_password_reset", user_id, x_actor or actor)
    return {
        "user_id": user_id,
        "username": row["username"],
        "reset_token": raw_token,
        "expires_at": expires.isoformat(),
        "warning": "This reset token is displayed once and expires in 15 minutes.",
    }


@app.post("/api/auth/users/generate")
def generate_user(
    request: UserGenerate,
    x_api_key: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
):
    actor, _ = require_role(x_api_key, {"admin"})
    role = request.role.lower().strip()
    if role in RESERVED_USER_ROLES or role not in ALLOWED_USER_ROLES:
        raise HTTPException(
            status_code=400,
            detail="Only admin and analyst credentials can be generated. super_admin is reserved for future use.",
        )
    username = (request.username or "").strip().lower()
    if username:
        if not username.replace("_", "").replace("-", "").isalnum():
            raise HTTPException(status_code=400, detail="Username may contain only letters, numbers, underscores, or hyphens")
        username = username[:40]
    else:
        prefix = "admin" if role == "admin" else "analyst"
        username = f"{prefix}_{secrets.token_hex(3)}"
    password = secrets.token_urlsafe(18) + "A1!"
    password_hash = hash_password(password)
    user_id = "usr_" + secrets.token_hex(8)
    try:
        with db() as connection:
            connection.execute(
                "INSERT INTO users(user_id,username,role,password_hash,created_at) VALUES (?,?,?,?,?)",
                (user_id, username, role, password_hash, iso_now()),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    audit("create_user", user_id, x_actor or actor)
    return {
        "user_id": user_id,
        "username": username,
        "role": role,
        "password": password,
        "warning": "Copy the password now. It is not displayed again.",
    }


@app.post("/api/auth/users/{user_id}/revoke")
def revoke_user(
    user_id: str,
    x_api_key: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
):
    actor, _ = require_role(x_api_key, {"admin"})
    with db() as connection:
        row = connection.execute("SELECT username FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        if row["username"] == actor:
            raise HTTPException(status_code=400, detail="You cannot revoke the account currently being used")
        username = row["username"]
        connection.execute("UPDATE users SET revoked_at=? WHERE user_id=?", (iso_now(), user_id))
        connection.execute("UPDATE api_keys SET revoked_at=? WHERE name=?", (iso_now(), "session:" + username))
    audit("revoke_user", user_id, x_actor or actor)
    return {"user_id": user_id, "revoked": True}


@app.post("/api/auth/reset-password")
def reset_password(payload: PasswordResetRequest):
    username = payload.username.strip().lower()
    if not username or len(payload.new_password) < 12:
        raise HTTPException(status_code=400, detail="Username and a password of at least 12 characters are required")
    token_hash = hash_api_key(payload.reset_token.strip())
    now = datetime.now(timezone.utc)
    with db() as connection:
        row = connection.execute(
            """SELECT r.id,r.user_id,r.expires_at,u.username,u.revoked_at
               FROM password_resets r JOIN users u ON u.user_id=r.user_id
               WHERE u.username=? AND r.token_hash=? AND r.used_at IS NULL
               ORDER BY r.id DESC LIMIT 1""",
            (username, token_hash),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid reset token")
        if row["revoked_at"] or expires < now:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        password_hash = hash_password(payload.new_password)
        connection.execute("UPDATE users SET password_hash=?, revoked_at=NULL WHERE user_id=?", (password_hash, row["user_id"]))
        connection.execute("UPDATE password_resets SET used_at=? WHERE id=?", (iso_now(), row["id"]))
        connection.execute("UPDATE api_keys SET revoked_at=? WHERE name=?", (iso_now(), "session:" + username))
    audit("reset_password", row["user_id"], "public")
    return {"reset": True, "username": username}

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
def agents(x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin", "responder", "analyst"})
    return {"agents": [
        {"name": "Triage Agent", "status": "ready"},
        {"name": "Threat Intelligence Agent", "status": "ready"},
        {"name": "Investigation Agent", "status": "ready"},
        {"name": "Response Agent", "status": "approval_required"},
        {"name": "Reporting Agent", "status": "ready"},
    ]}


@app.get("/api/incidents")
def list_incidents(x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin", "responder", "analyst"})
    return load_incidents()


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin", "responder", "analyst"})
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
def threat_intel(indicator: str, x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin", "responder", "analyst"})
    return enrich_indicator(indicator)


@app.get("/api/audit-logs")
def audit_logs(limit: int = 50, x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin"})
    limit = max(1, min(limit, 200))
    with db() as connection:
        rows = connection.execute("SELECT action, resource_id, actor, created_at FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def inspect_public_url(url: str) -> dict:
    """One-time, non-persistent website security inspection for the public test UI."""
    safe_public_url(url)
    started = time.perf_counter()
    status = "up"
    status_code = None
    error = None
    final_url = url
    redirect_tracker = RedirectTracker()
    headers_snapshot = {}
    content_hash = None

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Multi-Agent-SOC-Public-Test/1.0"},
        )
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

    missing_headers = [
        label for header, label in REQUIRED_SECURITY_HEADERS.items()
        if header not in headers_snapshot
    ]
    findings = [f"Missing security header: {item}" for item in missing_headers]
    if headers_snapshot.get("x-frame-options", "").upper() == "ALLOWALL":
        findings.append("X-Frame-Options allows framing")
    if "strict-transport-security" in headers_snapshot and "max-age=" not in headers_snapshot["strict-transport-security"].lower():
        findings.append("HSTS has no max-age directive")
    if any((item.get("to") or "").lower().startswith("http://") for item in redirect_tracker.chain):
        findings.append("Redirect chain contains an HTTP URL")
    if final_url.lower().startswith("http://"):
        findings.append("Final destination is HTTP")
    if not tls_info.get("valid"):
        findings.append("TLS certificate validation failed")
    elif tls_info.get("days_to_expiry") is not None and tls_info["days_to_expiry"] <= 30:
        findings.append(f"TLS certificate expires in {tls_info['days_to_expiry']} day(s)")
    if error:
        findings.append(f"Availability error: {error}")

    return {
        "url": url,
        "status": status,
        "status_code": status_code,
        "response_ms": round((time.perf_counter() - started) * 1000, 2),
        "checked_at": iso_now(),
        "final_url": final_url,
        "tls": tls_info,
        "security_headers": headers_snapshot,
        "missing_security_headers": missing_headers,
        "redirect_chain": redirect_tracker.chain,
        "content_hash": content_hash,
        "findings": findings[:20],
    }


@app.post("/api/public/security-test")
def public_security_test(target: MonitorTarget, request: Request):
    # Public test is intentionally one-time and non-persistent.
    client_host = _public_client_host(request)
    rate_limit(f"public-test:{client_host}", PUBLIC_TEST_RATE_LIMIT, PUBLIC_TEST_RATE_WINDOW)
    result = inspect_public_url(str(target.url))
    visitor_id = request.headers.get("x-visitor-id")
    if visitor_id:
        action = "web_test_completed" if result.get("status") in {"up", "degraded"} else "web_test_failed"
        record_public_activity(
            visitor_id,
            request.headers.get("x-visitor-name", ""),
            action,
            request,
            page="/public.html",
            detail={
                "target": str(target.url),
                "status": result.get("status"),
                "status_code": result.get("status_code"),
                "response_ms": result.get("response_ms"),
                "finding_count": len(result.get("findings") or []),
            },
        )
    return result


@app.post("/api/public/telemetry")
def public_telemetry(payload: PublicTelemetry, request: Request):
    client_host = _public_client_host(request)
    rate_limit(f"public-telemetry:{client_host}", PUBLIC_TELEMETRY_RATE_LIMIT, PUBLIC_TELEMETRY_RATE_WINDOW)
    record_public_activity(payload.visitor_id, payload.visitor_name, payload.action, request, payload.page, payload.detail)
    return {"ok": True, "visitor_id": payload.visitor_id, "server_time": iso_now()}


@app.get("/api/public/mitre/techniques")
def public_mitre_techniques(request: Request):
    client_host = _public_client_host(request)
    rate_limit(f"public-mitre:{client_host}", PUBLIC_MITRE_RATE_LIMIT, PUBLIC_MITRE_RATE_WINDOW)
    try:
        return load_mitre_techniques()
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=503, detail=f"MITRE ATT&CK catalog temporarily unavailable: {exc}")


@app.get("/api/admin/public/summary")
def admin_public_summary(x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin"})
    with db() as connection:
        visitor_rows = connection.execute(
            "SELECT * FROM public_visitors ORDER BY last_seen DESC LIMIT 500"
        ).fetchall()
        today_start = datetime.now(timezone.utc).date().isoformat() + "T00:00:00+00:00"
        activity_today = connection.execute(
            "SELECT COUNT(*) AS count FROM public_activity WHERE created_at >= ?",
            (today_start,),
        ).fetchone()["count"]
        tests_today = connection.execute(
            """SELECT COUNT(*) AS count FROM public_activity
               WHERE created_at >= ?
               AND action IN ('attack_test','web_test_completed','web_test_failed')""",
            (today_start,),
        ).fetchone()["count"]
        page_views_today = connection.execute(
            "SELECT COUNT(*) AS count FROM public_activity WHERE created_at >= ? AND action='page_view'",
            (today_start,),
        ).fetchone()["count"]
    now = datetime.now(timezone.utc)
    active = 0
    for row in visitor_rows:
        try:
            last_seen = datetime.fromisoformat(row["last_seen"])
            if now - last_seen <= timedelta(seconds=75):
                active += 1
        except (TypeError, ValueError):
            pass
    return {
        "active_now": active,
        "visitors_total": len(visitor_rows),
        "events_today": activity_today,
        "tests_today": tests_today,
        "page_views_today": page_views_today,
    }


@app.get("/api/admin/public/visitors")
def admin_public_visitors(limit: int = 100, x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin"})
    limit = max(1, min(limit, 200))
    with db() as connection:
        rows = connection.execute(
            "SELECT * FROM public_visitors ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    now = datetime.now(timezone.utc)
    output = []
    for row in rows:
        item = dict(row)
        try:
            last_seen = datetime.fromisoformat(item["last_seen"])
            item["active"] = (now - last_seen) <= timedelta(seconds=75)
        except (TypeError, ValueError):
            item["active"] = False
        output.append(item)
    return output


@app.get("/api/admin/public/activity")
def admin_public_activity(limit: int = 200, x_api_key: str | None = Header(default=None)):
    require_role(x_api_key, {"admin"})
    limit = max(1, min(limit, 500))
    with db() as connection:
        rows = connection.execute(
            """SELECT a.id,a.visitor_id,v.visitor_name,a.action,a.page,a.detail,a.ip_address,a.user_agent,a.created_at
               FROM public_activity a
               LEFT JOIN public_visitors v ON v.visitor_id=a.visitor_id
               ORDER BY a.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            item["detail"] = json.loads(item["detail"]) if item["detail"] else {}
        except (TypeError, json.JSONDecodeError):
            item["detail"] = {}
        output.append(item)
    return output