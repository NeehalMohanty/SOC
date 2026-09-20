import sqlite3

import pytest

from Backend.database import get_connection, initialize_database


def post_event(client, **overrides):
    payload = {
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "event_type": "normal_activity",
        "username": "analyst",
        "severity": "low",
        "message": "Test security event",
    }
    payload.update(overrides)
    return client.post("/api/events", json=payload)


@pytest.mark.parametrize(
    "payload_update",
    [
        {"source_ip": "not-an-ip"},
        {"destination_ip": "999.999.999.999"},
        {"severity": "extreme"},
        {"event_type": "invalid event type"},
        {"username": "a" * 256},
        {"host": "invalid host name"},
        {"message": "a" * 2001},
        {"unexpected_field": "not allowed"},
    ],
)
def test_invalid_event_payloads_are_rejected(client, payload_update):
    assert post_event(client, **payload_update).status_code == 422


def test_event_input_is_normalized(client):
    response = post_event(
        client,
        source_ip="2001:0db8:0000:0000:0000:0000:0000:0001",
        destination_ip=None,
        event_type="  PORT_SCAN  ",
        username="  analyst  ",
        host="  SERVER-01.EXAMPLE  ",
        severity="LOW",
        message="  scan detected  ",
    )

    assert response.status_code == 200
    event = client.get("/api/events").json()["events"][0]
    assert event["source_ip"] == "2001:db8::1"
    assert event["event_type"] == "port_scan"
    assert event["username"] == "analyst"
    assert event["host"] == "server-01.example"
    assert event["severity"] == "low"
    assert event["message"] == "scan detected"


def test_malformed_and_oversized_requests_are_rejected(client):
    malformed = client.post(
        "/api/events",
        content="{invalid-json",
        headers={"content-type": "application/json"},
    )
    oversized = post_event(client, message="a" * 17_000)

    assert malformed.status_code == 422
    assert oversized.status_code == 413


def test_event_pagination_filtering_sorting_and_search(client):
    post_event(client, source_ip="192.0.2.1", event_type="normal_activity")
    post_event(
        client,
        source_ip="192.0.2.2",
        event_type="failed_login",
        severity="medium",
        username="target-user",
    )
    post_event(client, source_ip="192.0.2.3", event_type="port_scan")

    page = client.get("/api/events?limit=1&offset=1&sort_order=asc").json()
    assert page["count"] == 1
    assert page["total"] == 3
    assert page["limit"] == 1
    assert page["offset"] == 1
    assert page["events"][0]["event_type"] == "failed_login"

    assert client.get("/api/events?severity=medium").json()["total"] == 1
    assert client.get("/api/events?event_type=FAILED_LOGIN").json()["total"] == 1
    assert client.get("/api/events?source_ip=192.0.2.3").json()["total"] == 1
    assert client.get("/api/events?search=target-user").json()["total"] == 1
    severity_sorted = client.get(
        "/api/events?sort_by=severity&sort_order=desc&limit=1"
    ).json()
    assert severity_sorted["events"][0]["severity"] == "medium"
    assert client.get(
        "/api/events?start_time=2100-01-01T00:00:00Z"
    ).json()["total"] == 0

    assert client.get("/api/events?limit=101").status_code == 422
    assert client.get("/api/events?sort_by=drop_table").status_code == 422
    assert client.get(
        "/api/events?start_time=2026-01-02T00:00:00Z"
        "&end_time=2026-01-01T00:00:00"
    ).status_code == 400


def test_alert_filtering_sorting_and_search(client):
    port_scan_id = post_event(client, event_type="port_scan").json()["alert_id"]
    post_event(client, event_type="malware_detected")
    client.patch(
        f"/api/alerts/{port_scan_id}",
        json={"status": "investigating"},
    )

    assert client.get("/api/alerts?status=investigating").json()["total"] == 1
    assert client.get("/api/alerts?severity=critical").json()["total"] == 1
    assert client.get("/api/alerts?search=malware").json()["total"] == 1

    sorted_alerts = client.get(
        "/api/alerts?sort_by=title&sort_order=asc&limit=1"
    ).json()
    assert sorted_alerts["count"] == 1
    assert sorted_alerts["total"] == 2
    assert sorted_alerts["alerts"][0]["title"] == "Malware Detected"
    severity_sorted = client.get(
        "/api/alerts?sort_by=severity&sort_order=desc&limit=1"
    ).json()
    assert severity_sorted["alerts"][0]["severity"] == "critical"


def test_alert_status_changes_create_audit_history(client):
    alert_id = post_event(client, event_type="malware_detected").json()["alert_id"]

    assert client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "INVESTIGATING"},
    ).status_code == 200
    assert client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "resolved"},
    ).status_code == 200
    assert client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "resolved"},
    ).status_code == 200

    history_response = client.get(f"/api/alerts/{alert_id}/history")
    assert history_response.status_code == 200
    history = history_response.json()
    assert history["count"] == 2
    assert history["history"][0]["previous_status"] == "investigating"
    assert history["history"][0]["new_status"] == "resolved"
    assert client.get("/api/alerts/999/history").status_code == 404


def test_database_constraints_and_indexes_are_enabled(client):
    connection = get_connection(client.app.state.database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO events (
                    source_ip, event_type, severity, timestamp
                ) VALUES (?, ?, ?, ?)
                """,
                ("192.0.2.50", "test", "invalid", "2026-01-01T00:00:00+00:00"),
            )
        connection.rollback()

        indexes = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        assert "idx_events_timestamp" in indexes
        assert "idx_events_host" in indexes
        assert "idx_alerts_status" in indexes
        assert "idx_alerts_rule_id" in indexes
        assert "idx_alerts_risk_score" in indexes
        assert "idx_alerts_correlation_key" in indexes
        assert "idx_alert_events_event_id" in indexes
        assert "idx_alert_history_alert_id" in indexes
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        connection.close()


def test_health_reports_database_failure(client):
    original_path = client.app.state.database_path
    client.app.state.database_path = original_path.parent
    try:
        response = client.get("/health")
        assert response.status_code == 503
        assert response.json()["detail"] == "Database is unavailable"
    finally:
        client.app.state.database_path = original_path


def test_detection_columns_are_added_without_losing_legacy_alerts(tmp_path):
    database_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(database_path)
    try:
        connection.executescript(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                event_type TEXT NOT NULL,
                username TEXT,
                severity TEXT NOT NULL,
                message TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(event_id) REFERENCES events(id)
            );
            INSERT INTO events (
                source_ip, event_type, severity, timestamp
            ) VALUES (
                '192.0.2.10', 'port_scan', 'high',
                '2026-01-01T00:00:00+00:00'
            );
            INSERT INTO alerts (
                event_id, title, description, severity, status, timestamp
            ) VALUES (
                1, 'Legacy Alert', 'Created before Phase 4', 'high', 'open',
                '2026-01-01T00:00:00+00:00'
            );
            """
        )
        connection.commit()
    finally:
        connection.close()

    initialize_database(database_path)

    migrated = get_connection(database_path)
    try:
        columns = {
            row["name"]
            for row in migrated.execute("PRAGMA table_info(alerts)").fetchall()
        }
        assert {
            "rule_id",
            "evidence",
            "risk_score",
            "detected_at",
            "detection_source",
            "correlation_key",
        } <= columns
        event_columns = {
            row["name"]
            for row in migrated.execute("PRAGMA table_info(events)").fetchall()
        }
        assert "host" in event_columns
        assert migrated.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'alert_events'"
        ).fetchone() is not None
        legacy_alert = migrated.execute(
            "SELECT title, rule_id FROM alerts WHERE id = 1"
        ).fetchone()
        assert legacy_alert["title"] == "Legacy Alert"
        assert legacy_alert["rule_id"] is None
        legacy_link = migrated.execute(
            "SELECT event_id, relationship FROM alert_events WHERE alert_id = 1"
        ).fetchone()
        assert legacy_link["event_id"] == 1
        assert legacy_link["relationship"] == "trigger"
    finally:
        migrated.close()
