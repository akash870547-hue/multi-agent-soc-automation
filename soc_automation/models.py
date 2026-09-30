from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str
    event_type: str
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    message: str
    metadata: dict = Field(default_factory=dict)


class Alert(BaseModel):
    alert_id: str
    event_id: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    reason: str


class Incident(BaseModel):
    incident_id: str
    alert: Alert
    status: str = "open"
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    iocs: dict[str, list[str]] = Field(default_factory=lambda: {"ipv4": [], "sha256": []})
    mitre: dict = Field(default_factory=dict)
    approved_actions: list[str] = Field(default_factory=list)
    governance: dict = Field(default_factory=lambda: {"approval_required": True, "approved": False})
