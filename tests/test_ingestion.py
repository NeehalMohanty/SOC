import json
from pathlib import Path

import pytest


def ssh_record(message=None):
    return {
        "host": "WEB-01",
        "message": message or "Failed password for invalid user admin from 192.0.2.10 port 52100 ssh2",
    }


def test_ssh_batch_correlates_and_preserves_evidence(client):
    records = [ssh_record() for _ in range(6)]
    response = client.post("/api/ingest/batch", json={"source": "ssh_auth", "records": records})
    assert response.status_code == 200
    body = response.json()
    assert (body["received"], body["accepted"], body["rejected"]) == (6, 6, 0)
    assert body["results"][4]["result"]["alerts_created"] == 1
    assert body["results"][5]["result"]["alerts_suppressed"] == 1
    alert_id = body["results"][4]["result"]["alert_id"]
    alert = client.get(f"/api/alerts/{alert_id}").json()
    assert alert["rule_id"] == "TG-AUTH-001"
    related = client.get(f"/api/alerts/{alert_id}/events").json()["events"]
    assert len(related) == 6
    assert all(event["host"] == "web-01" for event in related)
    assert related[0]["message"] == records[0]["message"]


def test_partial_batch_reports_indices_without_echoing_input(client):
    response = client.post("/api/ingest/batch", json={
        "source": "security_event",
        "records": [
            {"source_ip": "192.0.2.1", "event_type": "port_scan"},
            {"source_ip": "secret-invalid-input", "event_type": "port_scan"},
            None,
            {"source_ip": "192.0.2.2", "event_type": "normal_activity"},
        ],
    })
    assert response.status_code == 200
    body = response.json()
    assert (body["accepted"], body["rejected"]) == (2, 2)
    assert [item["index"] for item in body["results"]] == [0, 3]
    assert [item["index"] for item in body["errors"]] == [1, 2]
    assert "secret-invalid-input" not in response.text
    assert client.get("/api/dashboard/stats").json()["total_events"] == 2


@pytest.mark.parametrize("message", [
    "Accepted password for analyst from 2001:db8::1 port 22 ssh2",
    "Accepted publickey for analyst from 192.0.2.10 port 22 ssh2: ED25519 SHA256:example",
])
def test_accepted_authentication_is_not_a_failed_login(client, message):
    body = client.post("/api/ingest/batch", json={
        "source": "ssh_auth", "records": [ssh_record(message)],
    }).json()
    assert body["accepted"] == 1
    assert body["results"][0]["result"]["alert_created"] is False
    assert client.get("/api/events").json()["events"][0]["event_type"] == "successful_login"


@pytest.mark.parametrize("record", [
    ssh_record("Unrecognized authentication message"),
    ssh_record("Failed password for admin from invalid-ip port 22 ssh2"),
    ssh_record("Failed password for admin from 192.0.2.1 port 65536 ssh2"),
    ssh_record("Accepted password for invalid user admin from 192.0.2.1 port 22 ssh2"),
    {"host": "bad/host", "message": ssh_record()["message"]},
    {**ssh_record(), "unexpected": True},
])
def test_bad_ssh_records_are_rejected_without_storage(client, record):
    response = client.post("/api/ingest/batch", json={"source": "ssh_auth", "records": [record]})
    assert response.status_code == 200
    assert response.json()["rejected"] == 1
    assert client.get("/api/events").json()["total"] == 0


@pytest.mark.parametrize("payload", [
    {"source": "unknown", "records": [{}]},
    {"source": "ssh_auth", "records": []},
    {"source": "ssh_auth", "records": [{}] * 101},
    {"source": "ssh_auth", "records": [{}], "unexpected": True},
])
def test_invalid_envelope_rejects_entire_request(client, payload):
    assert client.post("/api/ingest/batch", json=payload).status_code == 422
    assert client.get("/api/events").json()["total"] == 0


def test_sample_produces_brute_force_alert(client):
    sample = Path(__file__).resolve().parents[1] / "examples" / "ssh-auth-batch.json"
    response = client.post("/api/ingest/batch", json=json.loads(sample.read_text()))
    assert response.status_code == 200
    assert response.json()["accepted"] == 6
    alerts = client.get("/api/alerts").json()["alerts"]
    assert any(alert["rule_id"] == "TG-AUTH-001" for alert in alerts)
