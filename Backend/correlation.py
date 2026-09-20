from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict

from Backend.detection import DetectedAlert
from Backend.schemas import SecurityEventCreate


class CorrelatedAlert(DetectedAlert):
    correlation_key: str
    detection_source: str
    related_event_ids: list[int]
    suppression_minutes: int


@dataclass(frozen=True)
class CorrelationContext:
    detected_at: datetime
    failed_login_threshold: int = 5
    failed_login_window_minutes: int = 5
    correlation_window_minutes: int = 10
    repeated_scan_threshold: int = 3
    suspicious_host_threshold: int = 3


def _event_time(event: dict[str, Any]) -> datetime:
    value = datetime.fromisoformat(event["timestamp"])
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _events_within(
    events: list[dict[str, Any]],
    detected_at: datetime,
    minutes: int,
) -> list[dict[str, Any]]:
    cutoff = detected_at - timedelta(minutes=minutes)
    return [
        event
        for event in events
        if cutoff <= _event_time(event) <= detected_at
    ]


def _correlated_alert(
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
    detected_at: datetime,
    correlation_key: str,
    related_event_ids: list[int],
    suppression_minutes: int,
    mitre_tactic: str | None = None,
    mitre_technique_id: str | None = None,
    mitre_technique_name: str | None = None,
) -> CorrelatedAlert:
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
        "detected_at": detected_at.astimezone(timezone.utc).isoformat(),
        "correlation_key": correlation_key,
        "detection_source": "correlation",
        "related_event_ids": sorted(set(related_event_ids)),
        "suppression_minutes": suppression_minutes,
    }


def correlate_events(
    current_event_id: int,
    current_event: SecurityEventCreate,
    recent_events: list[dict[str, Any]],
    context: CorrelationContext,
) -> list[CorrelatedAlert]:
    """Find suspicious patterns across recent, normalized security events."""
    detections: list[CorrelatedAlert] = []
    source_ip = str(current_event.source_ip)
    username = current_event.username
    event_type = current_event.event_type
    correlation_events = _events_within(
        recent_events,
        context.detected_at,
        context.correlation_window_minutes,
    )

    if event_type == "failed_login":
        failed_logins = [
            event
            for event in _events_within(
                recent_events,
                context.detected_at,
                context.failed_login_window_minutes,
            )
            if event["event_type"] == "failed_login"
            and (
                event["source_ip"] == source_ip
                or (username is not None and event.get("username") == username)
            )
        ]
        if len(failed_logins) >= context.failed_login_threshold:
            related_ids = [int(event["id"]) for event in failed_logins]
            detections.append(
                _correlated_alert(
                    rule_id="TG-AUTH-001",
                    rule_name="Repeated Failed Logins",
                    category="credential-access",
                    title="Possible Brute-Force Attack",
                    description=(
                        f"{len(failed_logins)} failed logins were observed within "
                        f"{context.failed_login_window_minutes} minutes for source "
                        f"{source_ip} or user {username or 'unknown'}."
                    ),
                    severity="high",
                    confidence=90,
                    risk_score=85,
                    evidence={
                        "source_ip": source_ip,
                        "username": username,
                        "failed_login_count": len(failed_logins),
                        "threshold": context.failed_login_threshold,
                        "window_minutes": context.failed_login_window_minutes,
                        "trigger_event_id": current_event_id,
                        "related_event_ids": related_ids,
                    },
                    detected_at=context.detected_at,
                    correlation_key=f"TG-AUTH-001:{source_ip}:{username or '-'}",
                    related_event_ids=related_ids,
                    suppression_minutes=context.failed_login_window_minutes,
                    mitre_tactic="Credential Access",
                    mitre_technique_id="T1110",
                    mitre_technique_name="Brute Force",
                )
            )

    if event_type in {"failed_login", "unauthorized_access", "suspicious_login"}:
        sequence_events = [
            event
            for event in correlation_events
            if event["source_ip"] == source_ip
            and event["event_type"]
            in {"port_scan", "failed_login", "unauthorized_access", "suspicious_login"}
        ]
        scan_events = [
            event for event in sequence_events if event["event_type"] == "port_scan"
        ]
        if scan_events:
            related_ids = [int(event["id"]) for event in sequence_events]
            detections.append(
                _correlated_alert(
                    rule_id="TG-CORR-001",
                    rule_name="Reconnaissance Followed by Authentication Activity",
                    category="attack-sequence",
                    title="Reconnaissance Followed by Login Activity",
                    description=(
                        f"Source {source_ip} performed network scanning followed by "
                        f"authentication activity within "
                        f"{context.correlation_window_minutes} minutes."
                    ),
                    severity="critical",
                    confidence=90,
                    risk_score=92,
                    evidence={
                        "source_ip": source_ip,
                        "event_types": [event["event_type"] for event in sequence_events],
                        "window_minutes": context.correlation_window_minutes,
                        "trigger_event_id": current_event_id,
                        "related_event_ids": related_ids,
                    },
                    detected_at=context.detected_at,
                    correlation_key=f"TG-CORR-001:{source_ip}",
                    related_event_ids=related_ids,
                    suppression_minutes=context.correlation_window_minutes,
                    mitre_tactic="Reconnaissance",
                    mitre_technique_id="T1595",
                    mitre_technique_name="Active Scanning",
                )
            )

    if event_type == "port_scan":
        scan_events = [
            event
            for event in correlation_events
            if event["source_ip"] == source_ip
            and event["event_type"] == "port_scan"
        ]
        if len(scan_events) >= context.repeated_scan_threshold:
            related_ids = [int(event["id"]) for event in scan_events]
            detections.append(
                _correlated_alert(
                    rule_id="TG-CORR-002",
                    rule_name="Repeated Network Scanning",
                    category="network-discovery",
                    title="Repeated Network Scanning",
                    description=(
                        f"Source {source_ip} generated {len(scan_events)} port-scan "
                        f"events within {context.correlation_window_minutes} minutes."
                    ),
                    severity="high",
                    confidence=95,
                    risk_score=85,
                    evidence={
                        "source_ip": source_ip,
                        "scan_count": len(scan_events),
                        "threshold": context.repeated_scan_threshold,
                        "window_minutes": context.correlation_window_minutes,
                        "trigger_event_id": current_event_id,
                        "related_event_ids": related_ids,
                    },
                    detected_at=context.detected_at,
                    correlation_key=f"TG-CORR-002:{source_ip}",
                    related_event_ids=related_ids,
                    suppression_minutes=context.correlation_window_minutes,
                    mitre_tactic="Discovery",
                    mitre_technique_id="T1046",
                    mitre_technique_name="Network Service Discovery",
                )
            )

    target_host = current_event.host or (
        str(current_event.destination_ip) if current_event.destination_ip else None
    )
    suspicious_types = {
        "port_scan",
        "unauthorized_access",
        "malware_detected",
        "suspicious_login",
        "impossible_travel",
    }
    if target_host and event_type in suspicious_types:
        host_events = [
            event
            for event in correlation_events
            if (event.get("host") or event.get("destination_ip")) == target_host
            and event["event_type"] in suspicious_types
        ]
        distinct_types = sorted({event["event_type"] for event in host_events})
        if (
            len(host_events) >= context.suspicious_host_threshold
            and len(distinct_types) >= 2
        ):
            related_ids = [int(event["id"]) for event in host_events]
            detections.append(
                _correlated_alert(
                    rule_id="TG-CORR-003",
                    rule_name="Suspicious Host Activity",
                    category="host-correlation",
                    title="Suspicious Activity Against Host",
                    description=(
                        f"Host {target_host} was involved in {len(host_events)} suspicious "
                        f"events across {len(distinct_types)} activity types within "
                        f"{context.correlation_window_minutes} minutes."
                    ),
                    severity="critical",
                    confidence=85,
                    risk_score=90,
                    evidence={
                        "host": target_host,
                        "event_count": len(host_events),
                        "event_types": distinct_types,
                        "threshold": context.suspicious_host_threshold,
                        "window_minutes": context.correlation_window_minutes,
                        "trigger_event_id": current_event_id,
                        "related_event_ids": related_ids,
                    },
                    detected_at=context.detected_at,
                    correlation_key=f"TG-CORR-003:{target_host}",
                    related_event_ids=related_ids,
                    suppression_minutes=context.correlation_window_minutes,
                )
            )

    return detections
