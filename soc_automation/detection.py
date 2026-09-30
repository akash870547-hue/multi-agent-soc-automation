from .models import Alert, SecurityEvent, Severity


def detect(event: SecurityEvent) -> Alert | None:
    message = event.message.lower()
    indicators = {
        "failed login": (Severity.MEDIUM, "Repeated or suspicious authentication failure"),
        "sql injection": (Severity.HIGH, "Potential SQL injection activity detected"),
        "malware": (Severity.CRITICAL, "Potential malware activity detected"),
        "ransomware": (Severity.CRITICAL, "Potential ransomware activity detected"),
    }
    for indicator, (severity, reason) in indicators.items():
        if indicator in message:
            return Alert(
                alert_id=f"ALT-{event.event_id}",
                event_id=event.event_id,
                title=f"Detected: {indicator}",
                severity=severity,
                confidence=0.85,
                reason=reason,
            )
    return None
