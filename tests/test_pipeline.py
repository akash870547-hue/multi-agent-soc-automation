from soc_automation.models import SecurityEvent
from soc_automation.pipeline import process_event
from soc_automation.reasoning import DeterministicReasoningProvider, ReasoningEngine


def test_sql_injection_creates_incident():
    event = SecurityEvent(event_id="EVT-TEST-001", source="test", event_type="web_attack", message="SQL injection detected")
    result = process_event(event)
    assert result is not None
    assert result["alert"]["severity"] == "high"
    assert result["incident_id"] == "INC-ALT-EVT-TEST-001"


def test_benign_event_creates_no_alert():
    event = SecurityEvent(event_id="EVT-TEST-002", source="test", event_type="info", message="Normal application startup completed")
    assert process_event(event) is None


def test_threat_intel_extracts_ioc_and_mitre_mapping():
    event = SecurityEvent(event_id="EVT-TEST-003", source="web-gateway", event_type="web_attack", source_ip="203.0.113.50", message="SQL injection detected from 198.51.100.10")
    result = process_event(event)
    assert result is not None
    assert "198.51.100.10" in result["iocs"]["ipv4"]
    assert "203.0.113.50" in result["iocs"]["ipv4"]
    assert result["mitre"]["technique_id"] == "T1190"


def test_ioc_extraction_finds_ip_inside_message():
    event = SecurityEvent(event_id="EVT-TEST-004", source="test", event_type="network", message="Connection from 192.0.2.55 triggered malware detection")
    result = process_event(event)
    assert "192.0.2.55" in result["iocs"]["ipv4"]
    assert result["mitre"]["technique_id"] == "T1204"


def test_reasoning_layer_prioritizes_critical_incident():
    event = SecurityEvent(event_id="EVT-TEST-005", source="endpoint", event_type="malware", message="ransomware activity detected from 203.0.113.77")
    result = process_event(event)
    assert result["reasoning"]["engine"] == "deterministic-v1"
    assert result["reasoning"]["priority"] == "P1"
    assert result["reasoning"]["next_steps"]


def test_incident_contains_lifecycle_timestamp():
    event = SecurityEvent(event_id="EVT-TEST-006", source="endpoint", event_type="malware", message="malware detected")
    result = process_event(event)
    assert result["detected_at"]
    assert result["acknowledged_at"] is None
    assert result["resolved_at"] is None


def test_reasoning_engine_accepts_injected_provider():
    class StubProvider(DeterministicReasoningProvider):
        def analyze(self, incident):
            return {"engine": "stub-v1", "priority": "P3", "summary": "stub", "rationale": [], "next_steps": []}

    event = SecurityEvent(event_id="EVT-TEST-007", source="test", event_type="web_attack", message="SQL injection detected")
    incident = process_event(event)
    assert incident is not None
    engine = ReasoningEngine(provider=StubProvider())
    from soc_automation.models import Incident
    model = Incident.model_validate(incident)
    result = engine.analyze(model)
    assert result["engine"] == "stub-v1"


def test_evaluation_dataset_produces_classification_metrics():
    from experiments.evaluate import evaluate

    result = evaluate()
    assert result["dataset_size"] == 10
    assert 0.0 <= result["accuracy"] <= 1.0
    assert 0.0 <= result["precision"] <= 1.0
    assert 0.0 <= result["recall"] <= 1.0
    assert 0.0 <= result["f1"] <= 1.0
