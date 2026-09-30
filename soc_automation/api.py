from datetime import datetime, timezone
import json
import os
import sqlite3

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .models import SecurityEvent
from .pipeline import process_event

app = FastAPI(title="Multi-Agent SOC Automation API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("SOC_DB_PATH", "soc_automation.db")


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


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


init_db()


def save_event(event: SecurityEvent):
    with db() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO events(event_id, payload, created_at) VALUES (?, ?, ?)",
            (
                event.event_id,
                json.dumps(event.model_dump(mode="json")),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def save_incident(incident: dict):
    with db() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO incidents(incident_id, payload, updated_at) VALUES (?, ?, ?)",
            (
                incident["incident_id"],
                json.dumps(incident),
                datetime.now(timezone.utc).isoformat(),
            ),
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


@app.get("/health")
def health():
    return {"status": "ok", "service": "multi-agent-soc", "storage": "sqlite"}


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
    with db() as connection:
        row = connection.execute(
            "SELECT payload FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return json.loads(row["payload"])


@app.post("/api/incidents/{incident_id}/approve")
def approve_incident(incident_id: str):
    incident = get_incident(incident_id)
    incident["governance"]["approved"] = True
    incident["governance"]["approved_at"] = datetime.now(timezone.utc).isoformat()
    incident["approved_actions"] = incident["recommendations"]
    save_incident(incident)
    return incident


@app.post("/api/events")
def ingest_event(event: SecurityEvent):
    save_event(event)
    result = process_event(event)

    if result:
        prior = [
            item for item in load_events()[:-1]
            if event.source_ip and item.get("source_ip") == event.source_ip
        ]
        if prior:
            result["findings"].append(
                f"Correlated with {len(prior)} earlier event(s) from the same source IP."
            )
        save_incident(result)

    return {"detected": result is not None, "incident": result}


@app.get("/api/metrics")
def metrics():
    values = load_incidents()
    return {
        "active_alerts": sum(1 for x in values if x["status"] == "open"),
        "critical": sum(1 for x in values if x["alert"]["severity"] == "critical"),
        "investigating": sum(1 for x in values if x["status"] == "investigating"),
        "resolved": sum(1 for x in values if x["status"] == "resolved"),
        "events_ingested": len(load_events()),
    }
