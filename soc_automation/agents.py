from .models import Incident, Alert


class TriageAgent:
    name = "triage-agent"

    def run(self, alert: Alert) -> list[str]:
        return [
            f"Alert classified as {alert.severity.value.upper()} severity.",
            f"Detection confidence: {alert.confidence:.0%}.",
            alert.reason,
        ]


class InvestigationAgent:
    name = "investigation-agent"

    def run(self, incident: Incident) -> list[str]:
        return [
            "Correlate related events using event ID, source IP, destination IP and username.",
            "Review surrounding authentication, network and endpoint telemetry.",
        ]


class ResponseAgent:
    name = "response-agent"

    def run(self, incident: Incident) -> list[str]:
        return [
            "Preserve relevant logs and evidence.",
            "Validate the finding with a human analyst before containment.",
        ]


class ReportingAgent:
    name = "reporting-agent"

    def run(self, incident: Incident) -> dict:
        return incident.model_dump(mode="json")
