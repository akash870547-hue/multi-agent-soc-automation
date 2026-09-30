from datetime import datetime, timezone
import json
import os
import sqlite3

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .correlation import correlate_event
from .models import SecurityEvent
from .pipeline import process_event
from .threat_intel import enrich_indicator

app = FastAPI(title="Multi-Agent SOC Automation API", version="0.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("SOC_DB_PATH", "soc_automation.db")
API_KEY = os.getenv("SOC_API_KEY")


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                resource_id TEXT,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


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
        rows = connection.execute(
            "SELECT payload FROM incidents ORDER BY updated_at ASC"
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def load_events() -> list[dict]:
    with db() as connection:
        rows = connection.execute(
            "SELECT payload FROM events ORDER BY created_at ASC"
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def find_event(event_id: str) -> dict | None:
    with db() as connection:
        row = connection.execute(
            "SELECT payload FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
    return json.loads(row["payload"]) if row else None


def get_incident_or_404(incident_id: str) -> dict:
    with db() as connection:
        row = connection.execute(
            "SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return json.loads(row["payload"])


def require_api_key(x_api_key: str | None):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


@app.get("/health")
def health():
    return {"status": "ok", "service": "multi-agent-soc", "storage": "sqlite", "version": "0.4.0"}


@app.get("/api/agents")
def agents():
    return {
        "agents": [
            {"name": "Triage Agent", "status": "ready"},
            {"name": "Threat Intelligence Agent", "status": "ready"},
            {"name": "Investigation Agent", "status": "ready"},
            {"name": "Response Agent", "status": "approval_required"},
            {"name": "Reporting Agent", "status": "ready"},
        ]
    }


@app.get("/api/incidents")
def list_incidents():
    return load_incidents()


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    return get_incident_or_404(incident_id)


@app.post("/api/incidents/{incident_id}/approve")
def approve_incident(
    incident_id: str,
    x_api_key: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
):
    require_api_key(x_api_key)
    incident = get_incident_or_404(incident_id)
    incident["governance"]["approved"] = True
    incident["governance"]["approved_at"] = iso_now()
    incident["approved_actions"] = incident["recommendations"]
    save_incident(incident)
    audit("approve_incident", incident_id, x_actor or "api-client")
    return incident


@app.post("/api/incidents/{incident_id}/acknowledge")
def acknowledge_incident(
    incident_id: str,
    x_api_key: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
):
    require_api_key(x_api_key)
    incident = get_incident_or_404(incident_id)
    if not incident.get("acknowledged_at"):
        incident["acknowledged_at"] = iso_now()
    if incident["status"] == "open":
        incident["status"] = "investigating"
    save_incident(incident)
    audit("acknowledge_incident", incident_id, x_actor or "api-client")
    return incident


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    x_api_key: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
):
    require_api_key(x_api_key)
    incident = get_incident_or_404(incident_id)
    if not incident.get("acknowledged_at"):
        incident["acknowledged_at"] = iso_now()
    incident["resolved_at"] = iso_now()
    incident["status"] = "resolved"
    save_incident(incident)
    audit("resolve_incident", incident_id, x_actor or "api-client")
    return incident


@app.post("/api/events")
def ingest_event(
    event: SecurityEvent,
    x_api_key: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
):
    require_api_key(x_api_key)
    prior_events = load_events()
    save_event(event)
    result = process_event(event)

    if result:
        result["correlation"] = correlate_event(event, prior_events)
        if result["correlation"]["matched"]:
            result["findings"].append(
                f"Correlated with {len(result['correlation']['related_events'])} "
                "recent event(s) using shared security pivots."
            )
        save_incident(result)

    audit("ingest_event", event.event_id, x_actor or "api-client")
    return {"detected": result is not None, "incident": result}


@app.get("/api/threat-intel/{indicator}")
def threat_intel(indicator: str):
    return enrich_indicator(indicator)


@app.get("/api/audit-logs")
def audit_logs(limit: int = 50):
    limit = max(1, min(limit, 200))
    with db() as connection:
        rows = connection.execute(
            "SELECT action, resource_id, actor, created_at "
            "FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/metrics")
def metrics():
    values = load_incidents()
    mttd_values = []
    mttr_values = []

    for incident in values:
        event = find_event(incident["alert"]["event_id"])
        if not event:
            continue
        try:
            event_time = datetime.fromisoformat(event["timestamp"])
            detected_time = datetime.fromisoformat(incident["detected_at"])
            mttd_values.append(max(0.0, (detected_time - event_time).total_seconds()))
            if incident.get("resolved_at"):
                start = datetime.fromisoformat(
                    incident.get("acknowledged_at") or incident["detected_at"]
                )
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
        "mttd_seconds": round(sum(mttd_values) / len(mttd_values), 2) if mttd_values else None,
        "mttr_seconds": round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else None,
    }
