from datetime import datetime, timezone

import pytest

from Backend.detection import DetectionContext, analyze_event
from Backend.schemas import SecurityEventCreate


DETECTION_TIME = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)


def make_event(event_type: str, severity: str = "low") -> SecurityEventCreate:
    return SecurityEventCreate(
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        event_type=event_type,
        username="analyst",
        severity=severity,
        message="Deterministic detection test",
    )


@pytest.mark.parametrize(
    ("event_type", "rule_id", "expected_severity", "mitre_technique_id"),
    [
        ("malware_detected", "TG-MAL-001", "critical", None),
        ("port_scan", "TG-NET-001", "high", "T1046"),
        ("unauthorized_access", "TG-IAM-001", "high", None),
        ("suspicious_login", "TG-AUTH-002", "high", "T1078"),
        ("impossible_travel", "TG-AUTH-002", "high", "T1078"),
    ],
)
def test_detection_rules_are_explainable(
    event_type,
    rule_id,
    expected_severity,
    mitre_technique_id,
):
    detections = analyze_event(
        make_event(event_type),
        DetectionContext(detected_at=DETECTION_TIME),
    )

    assert len(detections) == 1
    detection = detections[0]
    assert detection["rule_id"] == rule_id
    assert detection["rule_name"]
    assert detection["description"]
    assert detection["severity"] == expected_severity
    assert 0 <= detection["confidence"] <= 100
    assert 0 <= detection["risk_score"] <= 100
    assert detection["evidence"]["source_ip"] == "192.0.2.10"
    assert detection["mitre_technique_id"] == mitre_technique_id
    assert detection["detected_at"] == "2026-09-13T12:00:00+00:00"


def test_one_failed_login_does_not_create_an_alert():
    assert analyze_event(
        make_event("failed_login"),
        DetectionContext(detected_at=DETECTION_TIME),
    ) == []


def test_all_applicable_rules_are_returned():
    detections = analyze_event(
        make_event("port_scan", severity="critical"),
        DetectionContext(detected_at=DETECTION_TIME),
    )

    assert [detection["rule_id"] for detection in detections] == [
        "TG-NET-001",
        "TG-GEN-001",
    ]


def test_benign_event_does_not_create_detection():
    assert analyze_event(make_event("normal_activity")) == []
