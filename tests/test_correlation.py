from datetime import datetime, timedelta, timezone

from Backend.correlation import CorrelationContext, correlate_events
from Backend.schemas import SecurityEventCreate


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


def event_payload(
    event_id: int,
    event_type: str,
    *,
    minutes_ago: int = 0,
    source_ip: str = "192.0.2.10",
    username: str | None = "analyst",
    destination_ip: str = "198.51.100.20",
    host: str | None = None,
) -> dict:
    return {
        "id": event_id,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "username": username,
        "host": host,
        "severity": "low",
        "message": "Correlation test event",
        "timestamp": (NOW - timedelta(minutes=minutes_ago)).isoformat(),
    }


def current_event(
    event_type: str,
    *,
    host: str | None = None,
) -> SecurityEventCreate:
    return SecurityEventCreate(
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        event_type=event_type,
        username="analyst",
        host=host,
    )


def correlation_rules(
    event_id: int,
    event_type: str,
    events: list[dict],
    *,
    host: str | None = None,
) -> dict[str, dict]:
    detections = correlate_events(
        event_id,
        current_event(event_type, host=host),
        events,
        CorrelationContext(detected_at=NOW),
    )
    return {detection["rule_id"]: detection for detection in detections}


def test_brute_force_requires_five_related_failures():
    four_failures = [
        event_payload(event_id, "failed_login")
        for event_id in range(1, 5)
    ]
    assert "TG-AUTH-001" not in correlation_rules(
        4,
        "failed_login",
        four_failures,
    )

    five_failures = [*four_failures, event_payload(5, "failed_login")]
    detection = correlation_rules(5, "failed_login", five_failures)["TG-AUTH-001"]
    assert detection["detection_source"] == "correlation"
    assert detection["related_event_ids"] == [1, 2, 3, 4, 5]
    assert detection["evidence"]["failed_login_count"] == 5
    assert detection["mitre_technique_id"] == "T1110"


def test_events_outside_the_failed_login_window_are_ignored():
    events = [
        event_payload(event_id, "failed_login", minutes_ago=6)
        for event_id in range(1, 5)
    ]
    events.append(event_payload(5, "failed_login"))

    assert "TG-AUTH-001" not in correlation_rules(5, "failed_login", events)


def test_reconnaissance_followed_by_login_is_correlated():
    events = [
        event_payload(1, "port_scan", minutes_ago=4),
        event_payload(2, "failed_login"),
    ]

    detection = correlation_rules(2, "failed_login", events)["TG-CORR-001"]
    assert detection["severity"] == "critical"
    assert detection["related_event_ids"] == [1, 2]
    assert detection["evidence"]["event_types"] == ["port_scan", "failed_login"]


def test_repeated_scans_are_grouped_into_one_pattern():
    events = [
        event_payload(1, "port_scan", minutes_ago=2),
        event_payload(2, "port_scan", minutes_ago=1),
        event_payload(3, "port_scan"),
    ]

    detection = correlation_rules(3, "port_scan", events)["TG-CORR-002"]
    assert detection["evidence"]["scan_count"] == 3
    assert detection["related_event_ids"] == [1, 2, 3]
    assert detection["mitre_technique_id"] == "T1046"


def test_suspicious_activity_is_grouped_by_host():
    events = [
        event_payload(1, "port_scan", host="server-01", minutes_ago=2),
        event_payload(2, "unauthorized_access", host="server-01", minutes_ago=1),
        event_payload(3, "malware_detected", host="server-01"),
    ]

    detection = correlation_rules(
        3,
        "malware_detected",
        events,
        host="SERVER-01",
    )["TG-CORR-003"]
    assert detection["evidence"]["host"] == "server-01"
    assert detection["evidence"]["event_count"] == 3
    assert detection["related_event_ids"] == [1, 2, 3]
