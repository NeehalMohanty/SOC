from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypedDict

from Backend.schemas import SecurityEventCreate


class DetectedAlert(TypedDict):
    rule_id: str
    rule_name: str
    category: str
    title: str
    description: str
    severity: str
    confidence: int
    risk_score: int
    evidence: dict[str, Any]
    mitre_tactic: str | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    detected_at: str


@dataclass(frozen=True)
class DetectionContext:
    detected_at: datetime | None = None


def _normalized(value: str | None) -> str | None:
    """Normalize values defensively before any rule evaluates them."""
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def _base_evidence(
    event: SecurityEventCreate,
    event_type: str,
    severity: str,
) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "source_ip": str(event.source_ip),
        "destination_ip": str(event.destination_ip) if event.destination_ip else None,
        "username": _normalized(event.username),
        "host": _normalized(event.host),
        "event_severity": severity,
    }


def _alert(
    *,
    rule_id: str,
    rule_name: str,
    category: str,
    title: str,
    description: str,
    severity: str,
    confidence: int,
    risk_score: int,
    evidence: dict[str, Any],
    detected_at: str,
    mitre_tactic: str | None = None,
    mitre_technique_id: str | None = None,
    mitre_technique_name: str | None = None,
) -> DetectedAlert:
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "category": category,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "evidence": evidence,
        "mitre_tactic": mitre_tactic,
        "mitre_technique_id": mitre_technique_id,
        "mitre_technique_name": mitre_technique_name,
        "detected_at": detected_at,
    }


def analyze_event(
    event: SecurityEventCreate,
    context: DetectionContext | None = None,
) -> list[DetectedAlert]:
    """Evaluate every applicable rule and return all resulting detections."""
    context = context or DetectionContext()
    event_type = _normalized(event.event_type) or "unknown"
    severity = _normalized(event.severity.value) or "low"
    detected_at = (context.detected_at or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    ).isoformat()
    evidence = _base_evidence(event, event_type, severity)
    detections: list[DetectedAlert] = []

    if event_type == "malware_detected":
        detections.append(
            _alert(
                rule_id="TG-MAL-001",
                rule_name="Known Malware Activity",
                category="malware",
                title="Malware Detected",
                description=(
                    f"Event type malware_detected was reported by "
                    f"{event.source_ip}; immediate investigation is recommended."
                ),
                severity="critical",
                confidence=95,
                risk_score=95,
                evidence={**evidence, "message": event.message},
                detected_at=detected_at,
            )
        )

    if event_type == "port_scan":
        detections.append(
            _alert(
                rule_id="TG-NET-001",
                rule_name="Network Port Scan",
                category="network-discovery",
                title="Possible Port Scan",
                description=(
                    f"Port-scanning activity was reported from {event.source_ip}, "
                    "which may indicate network service discovery."
                ),
                severity="high",
                confidence=85,
                risk_score=75,
                evidence=evidence,
                detected_at=detected_at,
                mitre_tactic="Discovery",
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
            )
        )

    if event_type == "unauthorized_access":
        detections.append(
            _alert(
                rule_id="TG-IAM-001",
                rule_name="Unauthorized Access Attempt",
                category="access-control",
                title="Unauthorized Access Attempt",
                description=(
                    f"An access-control violation was reported from {event.source_ip}"
                    f" for user {event.username or 'unknown'}."
                ),
                severity="high",
                confidence=85,
                risk_score=80,
                evidence=evidence,
                detected_at=detected_at,
            )
        )

    if event_type in {"suspicious_login", "impossible_travel"}:
        detections.append(
            _alert(
                rule_id="TG-AUTH-002",
                rule_name="Suspicious Authentication",
                category="authentication",
                title="Suspicious Authentication Activity",
                description=(
                    f"Authentication event {event_type} was reported for "
                    f"user {event.username or 'unknown'} from {event.source_ip}."
                ),
                severity="high",
                confidence=80,
                risk_score=80,
                evidence=evidence,
                detected_at=detected_at,
                mitre_tactic="Initial Access",
                mitre_technique_id="T1078",
                mitre_technique_name="Valid Accounts",
            )
        )

    if severity == "critical":
        detections.append(
            _alert(
                rule_id="TG-GEN-001",
                rule_name="Critical Event Escalation",
                category="event-severity",
                title="Critical Security Event",
                description=(
                    f"The incoming {event_type} event from {event.source_ip} was "
                    "explicitly classified as critical."
                ),
                severity="critical",
                confidence=75,
                risk_score=90,
                evidence=evidence,
                detected_at=detected_at,
            )
        )

    return detections
