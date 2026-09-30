from datetime import datetime, timedelta, timezone

from .models import SecurityEvent


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def correlate_event(
    event: SecurityEvent,
    prior_events: list[dict],
    window_minutes: int = 15,
) -> dict:
    """Correlate an event with recent telemetry using shared security pivots."""
    matches = []

    for item in prior_events:
        if item.get("event_id") == event.event_id:
            continue

        timestamp = item.get("timestamp")
        if not timestamp:
            continue

        try:
            prior_time = _parse_timestamp(timestamp)
        except ValueError:
            continue

        delta = abs((event.timestamp - prior_time).total_seconds())
        if delta > window_minutes * 60:
            continue

        pivots = []
        if event.source_ip and item.get("source_ip") == event.source_ip:
            pivots.append("source_ip")
        if event.destination_ip and item.get("destination_ip") == event.destination_ip:
            pivots.append("destination_ip")
        if event.username and item.get("username") == event.username:
            pivots.append("username")

        if pivots:
            matches.append({
                "event_id": item["event_id"],
                "pivots": pivots,
                "time_delta_seconds": int(delta),
            })

    risk = "low"
    if len(matches) >= 3:
        risk = "high"
    elif matches:
        risk = "medium"

    return {
        "matched": bool(matches),
        "window_minutes": window_minutes,
        "event_count": len(matches) + 1,
        "risk": risk,
        "related_events": matches,
    }
