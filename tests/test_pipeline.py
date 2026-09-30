from soc_automation.models import SecurityEvent
from soc_automation.pipeline import process_event


def test_sql_injection_creates_incident():
    event = SecurityEvent(event_id="EVT-TEST-001", source="test", event_type="web_attack", message="SQL injection detected")
    result = process_event(event)
    assert result is not None
    assert result["alert"]["severity"] == "high"
    assert result["incident_id"] == "INC-ALT-EVT-TEST-001"


def test_benign_event_creates_no_alert():
    event = SecurityEvent(event_id="EVT-TEST-002", source="test", event_type="info", message="Normal application startup completed")
    assert process_event(event) is None
