from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

from Backend.config import settings
from Backend.correlation import CorrelationContext, correlate_events
from Backend.database import database_connection
from Backend.detection import DetectionContext, analyze_event
from Backend.investigation import record_activity
from Backend.schemas import AlertStatus, SecurityEventCreate, Severity


EVENT_SORT_COLUMNS = {
    "id": "id",
    "timestamp": "timestamp",
    "severity": (
        "CASE severity "
        "WHEN 'low' THEN 1 "
        "WHEN 'medium' THEN 2 "
        "WHEN 'high' THEN 3 "
        "WHEN 'critical' THEN 4 END"
    ),
    "event_type": "event_type",
}
ALERT_SORT_COLUMNS = {
    "id": "id",
    "timestamp": "timestamp",
    "severity": (
        "CASE severity "
        "WHEN 'low' THEN 1 "
        "WHEN 'medium' THEN 2 "
        "WHEN 'high' THEN 3 "
        "WHEN 'critical' THEN 4 END"
    ),
    "status": "status",
    "title": "title",
}


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _like_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _alert_from_row(
    row: Any,
    related_event_ids: list[int] | None = None,
) -> dict[str, Any]:
    alert = dict(row)
    serialized_evidence = alert.get("evidence")
    if serialized_evidence:
        try:
            alert["evidence"] = json.loads(serialized_evidence)
        except (TypeError, json.JSONDecodeError):
            alert["evidence"] = {"legacy_value": str(serialized_evidence)}
    else:
        alert["evidence"] = None
    alert.pop("correlation_key", None)
    alert["related_event_ids"] = related_event_ids or []
    return alert


def _related_event_map(
    connection: Any,
    alert_ids: list[int],
) -> dict[int, list[int]]:
    if not alert_ids:
        return {}
    placeholders = ", ".join("?" for _ in alert_ids)
    rows = connection.execute(
        f"""
        SELECT alert_id, event_id FROM alert_events
        WHERE alert_id IN ({placeholders})
        ORDER BY event_id
        """,
        alert_ids,
    ).fetchall()
    related: dict[int, list[int]] = {alert_id: [] for alert_id in alert_ids}
    for row in rows:
        related[int(row["alert_id"])].append(int(row["event_id"]))
    return related


def _recent_events(
    connection: Any,
    timestamp: datetime,
) -> list[dict[str, Any]]:
    window_minutes = max(
        settings.failed_login_window_minutes,
        settings.correlation_window_minutes,
    )
    cutoff = timestamp - timedelta(minutes=window_minutes)
    rows = connection.execute(
        """
        SELECT * FROM events
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp, id
        """,
        (cutoff.isoformat(), timestamp.isoformat()),
    ).fetchall()
    return [dict(row) for row in rows]


def _static_correlation_key(
    detection: dict[str, Any],
    event: SecurityEventCreate,
) -> str:
    rule_id = detection["rule_id"]
    source_ip = str(event.source_ip)
    if rule_id == "TG-NET-001":
        return f"{rule_id}:{source_ip}"
    if rule_id in {"TG-IAM-001", "TG-AUTH-002"}:
        return f"{rule_id}:{source_ip}:{event.username or '-'}"
    if rule_id == "TG-MAL-001":
        target = event.host or event.destination_ip or "-"
        return f"{rule_id}:{source_ip}:{target}"
    return f"{rule_id}:{source_ip}:{event.event_type}"


def _suppressed_alert_id(
    connection: Any,
    correlation_key: str,
    timestamp: datetime,
    suppression_minutes: int,
) -> int | None:
    cutoff = timestamp - timedelta(minutes=suppression_minutes)
    row = connection.execute(
        """
        SELECT id FROM alerts
        WHERE correlation_key = ?
            AND timestamp >= ?
            AND status != 'resolved'
        ORDER BY id DESC
        LIMIT 1
        """,
        (correlation_key, cutoff.isoformat()),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def _link_alert_events(
    connection: Any,
    alert_id: int,
    event_ids: list[int],
    trigger_event_id: int,
    timestamp: str,
    grouped: bool = False,
) -> None:
    for related_event_id in sorted(set(event_ids)):
        if grouped:
            relationship = "grouped"
        elif related_event_id == trigger_event_id:
            relationship = "trigger"
        else:
            relationship = "related"
        connection.execute(
            """
            INSERT OR IGNORE INTO alert_events (
                alert_id, event_id, relationship, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (alert_id, related_event_id, relationship, timestamp),
        )


def create_security_event(
    event: SecurityEventCreate,
    database_path: Path | str,
) -> dict[str, Any]:
    event_time = datetime.now(timezone.utc)
    timestamp = event_time.isoformat()

    with database_connection(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (
                source_ip,
                destination_ip,
                event_type,
                username,
                host,
                severity,
                message,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(event.source_ip),
                str(event.destination_ip) if event.destination_ip else None,
                event.event_type,
                event.username,
                event.host,
                event.severity.value,
                event.message,
                timestamp,
            ),
        )
        event_id = int(cursor.lastrowid)
        detection_context = DetectionContext(detected_at=event_time)
        detected_alerts: list[dict[str, Any]] = [
            {
                **detection,
                "detection_source": "rule",
                "correlation_key": _static_correlation_key(detection, event),
                "related_event_ids": [event_id],
                "suppression_minutes": settings.alert_suppression_minutes,
            }
            for detection in analyze_event(event, detection_context)
        ]
        correlation_context = CorrelationContext(
            detected_at=event_time,
            failed_login_threshold=settings.failed_login_threshold,
            failed_login_window_minutes=settings.failed_login_window_minutes,
            correlation_window_minutes=settings.correlation_window_minutes,
            repeated_scan_threshold=settings.repeated_scan_threshold,
            suspicious_host_threshold=settings.suspicious_host_threshold,
        )
        detected_alerts.extend(
            correlate_events(
                event_id,
                event,
                _recent_events(connection, event_time),
                correlation_context,
            )
        )
        alert_ids: list[int] = []
        grouped_alert_ids: list[int] = []
        alerts_suppressed = 0

        for detected_alert in detected_alerts:
            correlation_key = detected_alert["correlation_key"]
            related_event_ids = detected_alert["related_event_ids"]
            suppressed_alert_id = _suppressed_alert_id(
                connection,
                correlation_key,
                event_time,
                int(detected_alert["suppression_minutes"]),
            )
            if suppressed_alert_id is not None:
                _link_alert_events(
                    connection,
                    suppressed_alert_id,
                    related_event_ids,
                    event_id,
                    timestamp,
                    grouped=True,
                )
                alerts_suppressed += 1
                if suppressed_alert_id not in grouped_alert_ids:
                    grouped_alert_ids.append(suppressed_alert_id)
                continue

            alert_cursor = connection.execute(
                """
                INSERT INTO alerts (
                    event_id,
                    title,
                    description,
                    severity,
                    status,
                    timestamp,
                    rule_id,
                    rule_name,
                    category,
                    confidence,
                    risk_score,
                    evidence,
                    mitre_tactic,
                    mitre_technique_id,
                    mitre_technique_name,
                    detected_at,
                    detection_source,
                    correlation_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    detected_alert["title"],
                    detected_alert["description"],
                    detected_alert["severity"],
                    AlertStatus.OPEN.value,
                    timestamp,
                    detected_alert["rule_id"],
                    detected_alert["rule_name"],
                    detected_alert["category"],
                    detected_alert["confidence"],
                    detected_alert["risk_score"],
                    json.dumps(detected_alert["evidence"], sort_keys=True),
                    detected_alert["mitre_tactic"],
                    detected_alert["mitre_technique_id"],
                    detected_alert["mitre_technique_name"],
                    detected_alert["detected_at"],
                    detected_alert["detection_source"],
                    correlation_key,
                ),
            )
            alert_id = int(alert_cursor.lastrowid)
            alert_ids.append(alert_id)
            _link_alert_events(
                connection,
                alert_id,
                related_event_ids,
                event_id,
                timestamp,
            )

    return {
        "message": "Security event processed",
        "event_id": event_id,
        "alert_created": bool(alert_ids),
        "alert_id": alert_ids[0] if alert_ids else None,
        "alerts_created": len(alert_ids),
        "alert_ids": alert_ids,
        "alerts_suppressed": alerts_suppressed,
        "grouped_alert_ids": grouped_alert_ids,
    }


def list_events(
    database_path: Path | str,
    *,
    limit: int,
    offset: int,
    severity: Severity | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = None,
    sort_by: str = "id",
    sort_order: str = "desc",
) -> tuple[int, list[dict[str, Any]]]:
    filters: list[str] = []
    parameters: list[Any] = []

    if severity is not None:
        filters.append("severity = ?")
        parameters.append(severity.value)
    if event_type is not None:
        filters.append("event_type = ?")
        parameters.append(event_type)
    if source_ip is not None:
        filters.append("source_ip = ?")
        parameters.append(source_ip)
    if start_time is not None:
        filters.append("timestamp >= ?")
        parameters.append(_utc_iso(start_time))
    if end_time is not None:
        filters.append("timestamp <= ?")
        parameters.append(_utc_iso(end_time))
    if search is not None:
        filters.append(
            """
            (source_ip LIKE ? ESCAPE '\\'
                OR COALESCE(destination_ip, '') LIKE ? ESCAPE '\\'
                OR event_type LIKE ? ESCAPE '\\'
                OR COALESCE(username, '') LIKE ? ESCAPE '\\'
                OR COALESCE(host, '') LIKE ? ESCAPE '\\'
                OR COALESCE(message, '') LIKE ? ESCAPE '\\')
            """
        )
        pattern = _like_pattern(search)
        parameters.extend([pattern] * 6)

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    sort_column = EVENT_SORT_COLUMNS[sort_by]
    direction = "ASC" if sort_order == "asc" else "DESC"

    with database_connection(database_path) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM events {where_clause}",
            parameters,
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * FROM events
            {where_clause}
            ORDER BY {sort_column} {direction}, id {direction}
            LIMIT ? OFFSET ?
            """,
            [*parameters, limit, offset],
        ).fetchall()

    return total, [dict(row) for row in rows]


def list_alerts(
    database_path: Path | str,
    *,
    limit: int,
    offset: int,
    alert_status: AlertStatus | None = None,
    severity: Severity | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = None,
    sort_by: str = "id",
    sort_order: str = "desc",
) -> tuple[int, list[dict[str, Any]]]:
    filters: list[str] = []
    parameters: list[Any] = []

    if alert_status is not None:
        filters.append("status = ?")
        parameters.append(alert_status.value)
    if severity is not None:
        filters.append("severity = ?")
        parameters.append(severity.value)
    if start_time is not None:
        filters.append("timestamp >= ?")
        parameters.append(_utc_iso(start_time))
    if end_time is not None:
        filters.append("timestamp <= ?")
        parameters.append(_utc_iso(end_time))
    if search is not None:
        filters.append(
            "(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')"
        )
        pattern = _like_pattern(search)
        parameters.extend([pattern, pattern])

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    sort_column = ALERT_SORT_COLUMNS[sort_by]
    direction = "ASC" if sort_order == "asc" else "DESC"

    with database_connection(database_path) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM alerts {where_clause}",
            parameters,
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * FROM alerts
            {where_clause}
            ORDER BY {sort_column} {direction}, id {direction}
            LIMIT ? OFFSET ?
            """,
            [*parameters, limit, offset],
        ).fetchall()
        alert_ids = [int(row["id"]) for row in rows]
        related_events = _related_event_map(connection, alert_ids)

    return total, [
        _alert_from_row(row, related_events.get(int(row["id"]), []))
        for row in rows
    ]


def get_alert_by_id(
    alert_id: int,
    database_path: Path | str,
) -> dict[str, Any] | None:
    with database_connection(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        related_events = _related_event_map(connection, [alert_id])
    return (
        _alert_from_row(row, related_events.get(alert_id, []))
        if row is not None
        else None
    )


def update_alert_status(
    alert_id: int,
    new_status: AlertStatus,
    database_path: Path | str,
    *,
    actor: str = "Local analyst",
    resolution: str | None = None,
) -> dict[str, Any] | None:
    with database_connection(database_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        changed_at = datetime.now(timezone.utc).isoformat()
        existing_alert = connection.execute(
            "SELECT id, status, resolution FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if existing_alert is None:
            return None

        previous_status = existing_alert["status"]
        resolution = resolution if new_status == AlertStatus.RESOLVED else None
        history_id = None
        if previous_status != new_status.value:
            connection.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (new_status.value, alert_id),
            )
            history_cursor = connection.execute(
                """
                INSERT INTO alert_status_history (
                    alert_id,
                    previous_status,
                    new_status,
                    changed_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (alert_id, previous_status, new_status.value, changed_at),
            )
            history_id = history_cursor.lastrowid

        if previous_status != new_status.value or existing_alert["resolution"] != resolution:
            connection.execute("UPDATE alerts SET resolution = ? WHERE id = ?", (resolution, alert_id))
            record_activity(connection, alert_id, "status_changed", actor, {
                "previous_status": previous_status, "new_status": new_status.value,
                "previous_resolution": existing_alert["resolution"], "resolution": resolution,
            }, changed_at, history_id)

        updated_alert = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        related_events = _related_event_map(connection, [alert_id])

    return _alert_from_row(updated_alert, related_events.get(alert_id, []))


def list_alert_history(
    alert_id: int,
    database_path: Path | str,
) -> list[dict[str, Any]] | None:
    with database_connection(database_path) as connection:
        alert_exists = connection.execute(
            "SELECT id FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert_exists is None:
            return None

        rows = connection.execute(
            """
            SELECT * FROM alert_status_history
            WHERE alert_id = ?
            ORDER BY id DESC
            """,
            (alert_id,),
        ).fetchall()

    return [dict(row) for row in rows]


def list_alert_events(
    alert_id: int,
    database_path: Path | str,
) -> list[dict[str, Any]] | None:
    with database_connection(database_path) as connection:
        alert_exists = connection.execute(
            "SELECT id FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert_exists is None:
            return None

        rows = connection.execute(
            """
            SELECT events.*, alert_events.relationship
            FROM alert_events
            JOIN events ON events.id = alert_events.event_id
            WHERE alert_events.alert_id = ?
            ORDER BY events.timestamp, events.id
            """,
            (alert_id,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_dashboard_stats(database_path: Path | str) -> dict[str, Any]:
    with database_connection(database_path) as connection:
        total_events = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        alert_counts = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0)
                    AS open,
                COALESCE(SUM(CASE WHEN status = 'investigating' THEN 1 ELSE 0 END), 0)
                    AS investigating,
                COALESCE(SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END), 0)
                    AS resolved,
                COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0)
                    AS critical,
                COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0)
                    AS high,
                COALESCE(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END), 0)
                    AS medium,
                COALESCE(SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END), 0)
                    AS low
            FROM alerts
            """
        ).fetchone()

    return {
        "total_events": total_events,
        "total_alerts": alert_counts["total"],
        "alert_status": {
            "open": alert_counts["open"],
            "investigating": alert_counts["investigating"],
            "resolved": alert_counts["resolved"],
        },
        "severity": {
            "critical": alert_counts["critical"],
            "high": alert_counts["high"],
            "medium": alert_counts["medium"],
            "low": alert_counts["low"],
        },
    }
