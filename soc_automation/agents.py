from .models import Incident, Alert, SecurityEvent
from .threat_intel import extract_iocs, map_attack_technique


class TriageAgent:
    name = "triage-agent"

    def run(self, alert: Alert) -> list[str]:
        return [
            f"Alert classified as {alert.severity.value.upper()} severity.",
            f"Detection confidence: {alert.confidence:.0%}.",
            alert.reason,
        ]


class ThreatIntelligenceAgent:
    name = "threat-intelligence-agent"

    def run(self, event: SecurityEvent, incident: Incident) -> list[str]:
        incident.iocs = extract_iocs(event)
        incident.mitre = map_attack_technique(event)
        findings = []
        if incident.iocs["ipv4"]:
            findings.append(f"Extracted IPv4 indicators: {', '.join(incident.iocs['ipv4'])}.")
        if incident.iocs["sha256"]:
            findings.append(f"Extracted SHA-256 indicators: {len(incident.iocs['sha256'])} hash(es).")
        if incident.mitre["technique_id"]:
            findings.append(f"Mapped to MITRE ATT&CK {incident.mitre['technique_id']}: {incident.mitre['technique_name']}.")
        return findings


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
