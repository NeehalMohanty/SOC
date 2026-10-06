import pytest

from Backend.database import database_connection, initialize_database


def create_alert(client):
    result = client.post("/api/events", json={
        "source_ip": "192.0.2.10", "event_type": "port_scan", "severity": "high",
    })
    assert result.status_code == 200
    return result.json()["alert_id"]


def timeline(client, alert_id):
    response = client.get(f"/api/alerts/{alert_id}/timeline")
    assert response.status_code == 200
    return response.json()["activities"]


def test_full_investigation_lifecycle(client):
    alert_id = create_alert(client)
    url = f"/api/alerts/{alert_id}"
    assert timeline(client, alert_id)[0]["action"] == "created"
    assignment = {"actor": " Neehal ", "assigned_to": " Analyst A "}
    assert client.patch(url + "/assignment", json=assignment).json()["alert"]["assigned_to"] == "Analyst A"
    assert client.patch(url, json={"status": "investigating", "actor": "Neehal"}).status_code == 200
    note = client.post(url + "/notes", json={"actor": "Neehal", "body": " Checked host logs. "})
    assert note.status_code == 201
    assert note.json()["details"] == {"body": "Checked host logs."}
    closed = client.patch(url, json={"status": "resolved", "resolution": "false_positive", "actor": "Neehal"})
    assert closed.json()["alert"]["resolution"] == "false_positive"
    assert client.get("/api/dashboard/stats").json()["alert_status"]["resolved"] == 1
    reopened = client.patch(url, json={"status": "open", "actor": "Neehal"}).json()["alert"]
    assert reopened["resolution"] is None
    assert reopened["assigned_to"] == "Analyst A"
    activities = timeline(client, alert_id)
    assert [a["action"] for a in activities] == [
        "status_changed", "status_changed", "note_added", "status_changed", "assigned", "created",
    ]
    assert all(a["actor"] == "Neehal" for a in activities[:-1])
    assert len(client.get(url + "/history").json()["history"]) == 3
    # Reinitializing must neither discard notes nor duplicate dual-written status history.
    initialize_database(client.app.state.database_path)
    assert timeline(client, alert_id) == activities


def test_assignment_noops_unassignment_and_status_noops(client):
    alert_id = create_alert(client)
    url = f"/api/alerts/{alert_id}"
    for _ in range(2):
        client.patch(url + "/assignment", json={"actor": "A", "assigned_to": "B"})
    client.patch(url + "/assignment", json={"actor": "A", "assigned_to": " "})
    for _ in range(2):
        client.patch(url, json={"status": "open"})
    assert client.get(url).json()["assigned_to"] is None
    assert len(timeline(client, alert_id)) == 3
    assert client.get(url + "/history").json()["count"] == 0


def test_resolution_only_change_is_audited(client):
    alert_id = create_alert(client)
    url = f"/api/alerts/{alert_id}"
    client.patch(url, json={"status": "resolved"})
    client.patch(url, json={"status": "resolved", "resolution": "false_positive"})
    client.patch(url, json={"status": "resolved", "resolution": "false_positive"})
    assert len(timeline(client, alert_id)) == 3
    assert client.get(url + "/history").json()["count"] == 1


@pytest.mark.parametrize("suffix,payload", [
    ("/notes", {"actor": " ", "body": "Note"}),
    ("/notes", {"actor": "A", "body": " "}),
    ("/notes", {"actor": "A", "body": "x" * 4001}),
    ("/notes", {"actor": "x" * 101, "body": "Note"}),
    ("/notes", {"actor": "A", "body": "Note", "admin": True}),
    ("/assignment", {"actor": "A", "assigned_to": "x" * 101}),
    ("/assignment", {"actor": "A"}),
    ("", {"status": "open", "resolution": "false_positive"}),
    ("", {"status": "resolved", "resolution": "invalid"}),
])
def test_invalid_inputs(client, suffix, payload):
    alert_id = create_alert(client)
    method = client.post if suffix == "/notes" else client.patch
    assert method(f"/api/alerts/{alert_id}" + suffix, json=payload).status_code == 422
    assert len(timeline(client, alert_id)) == 1


def test_missing_alert_and_invalid_pagination(client):
    assert client.get("/api/alerts/999/timeline").status_code == 404
    assert client.post("/api/alerts/999/notes", json={"actor": "A", "body": "Note"}).status_code == 404
    assert client.patch("/api/alerts/999/assignment", json={"actor": "A", "assigned_to": None}).status_code == 404
    for query in ("limit=0", "limit=101", "offset=-1"):
        assert client.get("/api/alerts/999/timeline?" + query).status_code == 422


def test_timeline_pagination_and_alert_isolation(client):
    first = create_alert(client)
    second = client.post("/api/events", json={
        "source_ip": "192.0.2.20", "event_type": "malware", "severity": "critical",
    }).json()["alert_id"]
    for i in range(5):
        client.post(f"/api/alerts/{first}/notes", json={"actor": "A", "body": f"Note {i}"})
    page = client.get(f"/api/alerts/{first}/timeline?limit=2&offset=2").json()
    assert page["total"] == 6
    assert [a["details"]["body"] for a in page["activities"]] == ["Note 2", "Note 1"]
    assert len(timeline(client, second)) == 1


def test_legacy_history_backfill_is_idempotent(client):
    alert_id = create_alert(client)
    path = client.app.state.database_path
    with database_connection(path) as connection:
        connection.execute("""
            INSERT INTO alert_status_history (alert_id, previous_status, new_status, changed_at)
            VALUES (?, 'open', 'investigating', '2026-10-06T12:00:00+00:00')
        """, (alert_id,))
    initialize_database(path)
    initialize_database(path)
    entries = [a for a in timeline(client, alert_id) if a["action"] == "status_changed"]
    assert len(entries) == 1
    assert entries[0]["actor"] == "Unknown (legacy)"


def test_audit_failure_rolls_back_status_and_assignment(client):
    alert_id = create_alert(client)
    with database_connection(client.app.state.database_path) as connection:
        connection.execute("""
            CREATE TRIGGER fail_activity BEFORE INSERT ON alert_activity
            BEGIN SELECT RAISE(ABORT, 'test audit failure'); END
        """)
    url = f"/api/alerts/{alert_id}"
    assert client.patch(url, json={"status": "investigating"}).status_code == 500
    assert client.patch(url + "/assignment", json={"actor": "A", "assigned_to": "B"}).status_code == 500
    assert client.post(url + "/notes", json={"actor": "A", "body": "Note"}).status_code == 500
    alert = client.get(url).json()
    assert alert["status"] == "open"
    assert alert["assigned_to"] is None
    assert client.get(url + "/history").json()["count"] == 0
    assert len(timeline(client, alert_id)) == 1


def test_note_content_stored_literally(client):
    alert_id = create_alert(client)
    body = "<script>alert(1)</script> '); DROP TABLE alerts; --"
    client.post(f"/api/alerts/{alert_id}/notes", json={"actor": "A", "body": body})
    assert timeline(client, alert_id)[0]["details"]["body"] == body
    assert client.get(f"/api/alerts/{alert_id}").status_code == 200
