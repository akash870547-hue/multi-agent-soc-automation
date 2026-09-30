import json
from .agents import InvestigationAgent, ReportingAgent, ResponseAgent, TriageAgent
from .detection import detect
from .models import Incident, SecurityEvent


def process_event(event: SecurityEvent) -> dict | None:
    alert = detect(event)
    if alert is None:
        return None
    incident = Incident(incident_id=f"INC-{alert.alert_id}", alert=alert)
    incident.findings.extend(TriageAgent().run(alert))
    incident.findings.extend(InvestigationAgent().run(incident))
    incident.recommendations.extend(ResponseAgent().run(incident))
    return ReportingAgent().run(incident)


def run_demo() -> None:
    event = SecurityEvent(
        event_id="EVT-0001", source="demo-firewall", event_type="web_attack",
        source_ip="203.0.113.50", destination_ip="10.0.0.20",
        message="Possible SQL injection detected against web application",
    )
    print(json.dumps(process_event(event), indent=2))
