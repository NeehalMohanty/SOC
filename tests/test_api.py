def create_event(client, event_type="normal_activity", severity="low", **overrides):
    payload = {
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "event_type": event_type,
        "username": "analyst",
        "host": "server-01",
        "severity": severity,
        "message": "Automated test event",
    }
    payload.update(overrides)
    return client.post("/api/events", json=payload)


def test_root_and_health(client):
    root_response = client.get("/")
    health_response = client.get("/health")

    assert root_response.status_code == 200
    assert root_response.json()["name"] == "TethysGuard"
    assert health_response.status_code == 200
    assert health_response.json() == {
        "status": "healthy",
        "database": "connected",
    }
    assert client.get("/api/dashboard/stats").json()["total_alerts"] == 0


def test_event_without_detection_is_stored(client):
    response = create_event(client)

    assert response.status_code == 200
    assert response.json()["alert_created"] is False
    assert response.json()["alert_id"] is None
    assert response.json()["alerts_created"] == 0
    assert response.json()["alert_ids"] == []
    assert response.json()["alerts_suppressed"] == 0
    assert response.json()["grouped_alert_ids"] == []

    events_response = client.get("/api/events")
    assert events_response.status_code == 200
    assert events_response.json()["count"] == 1
    assert events_response.json()["events"][0]["event_type"] == "normal_activity"


def test_detected_event_creates_retrievable_alert(client):
    response = create_event(client, event_type="port_scan")

    assert response.status_code == 200
    assert response.json()["alert_created"] is True
    assert response.json()["alerts_created"] == 1
    alert_id = response.json()["alert_id"]

    alerts_response = client.get("/api/alerts")
    alert_response = client.get(f"/api/alerts/{alert_id}")

    assert alerts_response.status_code == 200
    assert alerts_response.json()["count"] == 1
    assert alert_response.status_code == 200
    assert alert_response.json()["title"] == "Possible Port Scan"
    assert alert_response.json()["severity"] == "high"
    assert alert_response.json()["status"] == "open"
    assert alert_response.json()["rule_id"] == "TG-NET-001"
    assert alert_response.json()["rule_name"] == "Network Port Scan"
    assert alert_response.json()["confidence"] == 85
    assert alert_response.json()["risk_score"] == 75
    assert alert_response.json()["evidence"]["source_ip"] == "192.0.2.10"
    assert alert_response.json()["mitre_technique_id"] == "T1046"
    assert alert_response.json()["detected_at"]
    assert alert_response.json()["detection_source"] == "rule"
    assert alert_response.json()["related_event_ids"] == [response.json()["event_id"]]


def test_failed_login_alert_requires_threshold(client):
    responses = [
        create_event(client, event_type="failed_login")
        for _ in range(5)
    ]

    assert all(
        response.json()["alert_created"] is False
        for response in responses[:4]
    )
    threshold_response = responses[4].json()
    assert threshold_response["alert_created"] is True
    alert = client.get(
        f"/api/alerts/{threshold_response['alert_id']}"
    ).json()
    assert alert["rule_id"] == "TG-AUTH-001"
    assert alert["title"] == "Possible Brute-Force Attack"
    assert alert["evidence"]["failed_login_count"] == 5
    assert alert["mitre_technique_id"] == "T1110"
    assert alert["detection_source"] == "correlation"
    assert len(alert["related_event_ids"]) == 5


def test_duplicate_alerts_are_suppressed_and_grouped(client):
    first = create_event(client, event_type="port_scan").json()
    second = create_event(client, event_type="port_scan").json()

    assert first["alerts_created"] == 1
    assert second["alerts_created"] == 0
    assert second["alerts_suppressed"] == 1
    assert second["grouped_alert_ids"] == [first["alert_id"]]
    grouped_alert = client.get(f"/api/alerts/{first['alert_id']}").json()
    assert grouped_alert["related_event_ids"] == [
        first["event_id"],
        second["event_id"],
    ]
    related_response = client.get(
        f"/api/alerts/{first['alert_id']}/events"
    )
    assert related_response.status_code == 200
    assert related_response.json()["count"] == 2
    assert related_response.json()["events"][0]["relationship"] == "trigger"
    assert related_response.json()["events"][1]["relationship"] == "grouped"


def test_resolved_alert_does_not_suppress_new_activity(client):
    first = create_event(client, event_type="port_scan").json()
    client.patch(
        f"/api/alerts/{first['alert_id']}",
        json={"status": "resolved"},
    )

    second = create_event(client, event_type="port_scan").json()

    assert second["alerts_created"] == 1
    assert second["alerts_suppressed"] == 0
    assert second["alert_id"] != first["alert_id"]


def test_repeated_scans_create_one_correlated_alert(client):
    create_event(client, event_type="port_scan")
    create_event(client, event_type="port_scan")
    third = create_event(client, event_type="port_scan").json()

    assert third["alerts_created"] == 1
    assert third["alerts_suppressed"] == 1
    correlated = client.get(f"/api/alerts/{third['alert_id']}").json()
    assert correlated["rule_id"] == "TG-CORR-002"
    assert correlated["detection_source"] == "correlation"
    assert len(correlated["related_event_ids"]) == 3
    assert client.get("/api/alerts").json()["total"] == 2


def test_reconnaissance_then_login_creates_sequence_alert(client):
    scan = create_event(client, event_type="port_scan").json()
    login = create_event(client, event_type="failed_login").json()

    assert login["alerts_created"] == 1
    alert = client.get(f"/api/alerts/{login['alert_id']}").json()
    assert alert["rule_id"] == "TG-CORR-001"
    assert alert["risk_score"] == 92
    assert alert["related_event_ids"] == [scan["event_id"], login["event_id"]]


def test_one_event_can_create_multiple_explainable_alerts(client):
    response = create_event(
        client,
        event_type="port_scan",
        severity="critical",
    ).json()

    assert response["alerts_created"] == 2
    assert len(response["alert_ids"]) == 2
    rules = {
        client.get(f"/api/alerts/{alert_id}").json()["rule_id"]
        for alert_id in response["alert_ids"]
    }
    assert rules == {"TG-NET-001", "TG-GEN-001"}


def test_alert_status_workflow(client):
    alert_id = create_event(client, event_type="malware_detected").json()["alert_id"]

    response = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "INVESTIGATING"},
    )

    assert response.status_code == 200
    assert response.json()["alert"]["status"] == "investigating"

    invalid_response = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "closed"},
    )
    assert invalid_response.status_code == 422


def test_missing_resources_and_invalid_payloads(client):
    assert client.get("/api/alerts/999").status_code == 404
    assert client.get("/api/alerts/999/events").status_code == 404
    assert client.patch(
        "/api/alerts/999",
        json={"status": "open"},
    ).status_code == 404
    assert client.post(
        "/api/events",
        json={"event_type": "port_scan"},
    ).status_code == 422


def test_dashboard_statistics(client):
    create_event(client, event_type="normal_activity")
    create_event(client, event_type="malware_detected")
    create_event(client, event_type="failed_login")

    response = client.get("/api/dashboard/stats")

    assert response.status_code == 200
    assert response.json() == {
        "total_events": 3,
        "total_alerts": 1,
        "alert_status": {
            "open": 1,
            "investigating": 0,
            "resolved": 0,
        },
        "severity": {
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
    }
