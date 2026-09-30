from .models import Incident


class ReasoningEngine:
    """Provider-agnostic reasoning layer for incident prioritization.

    The default implementation is deterministic so the research prototype
    works without external API keys. A future LLM provider can implement the
    same analyze() contract without changing the pipeline.
    """

    def analyze(self, incident: Incident) -> dict:
        severity = incident.alert.severity.value
        confidence = incident.alert.confidence
        ioc_count = sum(len(values) for values in incident.iocs.values())
        technique = incident.mitre.get("technique_id")

        if severity == "critical":
            priority = "P1"
        elif severity == "high":
            priority = "P2"
        elif severity == "medium":
            priority = "P3"
        else:
            priority = "P4"

        rationale = [
            f"Severity is {severity.upper()} with {confidence:.0%} detection confidence.",
            f"{ioc_count} indicator(s) were extracted from the event.",
        ]
        if technique:
            rationale.append(f"MITRE ATT&CK mapping is {technique}.")

        next_steps = [
            "Validate the alert against surrounding telemetry.",
            "Preserve relevant evidence before containment.",
            "Require human approval before executing response actions.",
        ]
        if severity == "critical":
            next_steps.insert(0, "Escalate to the incident response queue immediately.")

        return {
            "engine": "deterministic-v1",
            "priority": priority,
            "summary": f"{incident.alert.title}: {incident.alert.reason}",
            "rationale": rationale,
            "next_steps": next_steps,
        }
