from datetime import datetime, timezone\nfrom fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .models import SecurityEvent
from .pipeline import process_event

app = FastAPI(title="Multi-Agent SOC Automation API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

incidents: dict[str, dict] = {}
events: list[dict] = []


@app.get("/health")
def health():
    return {"status": "ok", "service": "multi-agent-soc"}


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
    return list(incidents.values())


@app.post("/api/incidents/{incident_id}/approve")\ndef approve_incident(incident_id: str):\n    incident = incidents.get(incident_id)\n    if not incident:\n        raise HTTPException(status_code=404, detail="Incident not found")\n    incident["governance"]["approved"] = True\n    incident["governance"]["approved_at"] = datetime.now(timezone.utc).isoformat()\n    incident["approved_actions"] = incident["recommendations"]\n    return incident\n\n\n@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    incident = incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/events")
def ingest_event(event: SecurityEvent):
    events.append(event.model_dump(mode="json"))
    result = process_event(event)
    if result:
        incidents[result["incident_id"]] = result
    return {"detected": result is not None, "incident": result}


@app.get("/api/metrics")
def metrics():
    values = list(incidents.values())
    return {
        "active_alerts": sum(1 for x in values if x["status"] == "open"),
        "critical": sum(1 for x in values if x["alert"]["severity"] == "critical"),
        "investigating": sum(1 for x in values if x["status"] == "investigating"),
        "resolved": sum(1 for x in values if x["status"] == "resolved"),
        "events_ingested": len(events),
    }
