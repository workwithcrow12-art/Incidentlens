import json
from datetime import timezone
from pathlib import Path

from incidentlens.ingest.alertmanager import AlertmanagerPayload, to_alerts

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "alertmanager_payload.json"


def test_parse_sample_payload():
    alerts = to_alerts(AlertmanagerPayload.model_validate(json.loads(SAMPLE.read_text(encoding="utf-8"))))
    assert len(alerts) == 3
    first = alerts[0]
    assert first.name == "HighLatency"
    assert first.service == "auth-service"
    assert first.ends_at is None  # "0001-01-01" nghĩa là chưa kết thúc
    assert alerts[2].status == "resolved"
    assert alerts[2].ends_at is not None


def test_fingerprint_fallback_is_stable():
    payload = {"alerts": [{"status": "firing", "labels": {"alertname": "A", "b": "1"},
                           "startsAt": "2026-11-12T00:00:00Z"}]}
    a1 = to_alerts(AlertmanagerPayload.model_validate(payload))[0]
    a2 = to_alerts(AlertmanagerPayload.model_validate(payload))[0]
    assert a1.fingerprint == a2.fingerprint


def test_times_are_normalized_to_utc():
    payload = {"alerts": [{"status": "firing", "labels": {"alertname": "A"},
                           "startsAt": "2026-11-12T09:00:00+07:00"}]}
    alert = to_alerts(AlertmanagerPayload.model_validate(payload))[0]
    assert alert.starts_at.tzinfo == timezone.utc
    assert alert.starts_at.hour == 2
