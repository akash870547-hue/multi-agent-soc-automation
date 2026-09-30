import json
import os
from abc import ABC, abstractmethod

from .models import Incident


class ReasoningProvider(ABC):
    """Contract for pluggable incident-reasoning providers."""
    @abstractmethod
    def analyze(self, incident: Incident) -> dict:
        raise NotImplementedError


class DeterministicReasoningProvider(ReasoningProvider):
    """Offline, reproducible reasoning provider used by default."""
    def analyze(self, incident: Incident) -> dict:
        severity = incident.alert.severity.value
        confidence = incident.alert.confidence
        ioc_count = sum(len(values) for values in incident.iocs.values())
        technique = incident.mitre.get("technique_id")
        if severity == "critical": priority = "P1"
        elif severity == "high": priority = "P2"
        elif severity == "medium": priority = "P3"
        else: priority = "P4"
        rationale = [f"Severity is {severity.upper()} with {confidence:.0%} detection confidence.", f"{ioc_count} indicator(s) were extracted from the event."]
        if technique: rationale.append(f"MITRE ATT&CK mapping is {technique}.")
        next_steps = ["Validate the alert against surrounding telemetry.", "Preserve relevant evidence before containment.", "Require human approval before executing response actions."]
        if severity == "critical": next_steps.insert(0, "Escalate to the incident response queue immediately.")
        return {"engine": "deterministic-v1", "priority": priority, "summary": f"{incident.alert.title}: {incident.alert.reason}", "rationale": rationale, "next_steps": next_steps}


class OpenAIReasoningProvider(ReasoningProvider):
    """Optional OpenAI Responses API provider."""
    def __init__(self, model: str | None = None):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("OpenAI reasoning requires the optional openai package.") from exc
        if not os.getenv("OPENAI_API_KEY"): raise RuntimeError("OPENAI_API_KEY is required for OpenAI reasoning.")
        self.client = OpenAI()
        self.model = model or os.getenv("SOC_REASONING_MODEL", "gpt-5.6-luna")

    def analyze(self, incident: Incident) -> dict:
        payload = {"severity": incident.alert.severity.value, "confidence": incident.alert.confidence, "title": incident.alert.title, "reason": incident.alert.reason, "findings": incident.findings, "iocs": incident.iocs, "mitre": incident.mitre, "recommendations": incident.recommendations}
        prompt = ("You are a defensive SOC incident reasoning engine. Analyze the supplied incident and return ONLY valid JSON with exactly these keys: priority, summary, rationale, next_steps. priority must be P1, P2, P3, or P4. rationale and next_steps must be arrays of concise strings. Do not authorize or execute actions; preserve human approval for response.\n\n" + json.dumps(payload, indent=2))
        response = self.client.responses.create(model=self.model, input=prompt)
        result = json.loads(response.output_text.strip())
        if not isinstance(result.get("rationale"), list) or not isinstance(result.get("next_steps"), list): raise ValueError("LLM reasoning response has an invalid schema.")
        result["engine"] = f"openai:{self.model}"
        return result


class ReasoningEngine:
    """Selects a reasoning provider without changing the SOC pipeline."""
    def __init__(self, provider: ReasoningProvider | None = None):
        if provider is not None: self.provider = provider
        elif os.getenv("SOC_REASONING_PROVIDER", "deterministic").lower() == "openai": self.provider = OpenAIReasoningProvider()
        else: self.provider = DeterministicReasoningProvider()

    def analyze(self, incident: Incident) -> dict:
        return self.provider.analyze(incident)