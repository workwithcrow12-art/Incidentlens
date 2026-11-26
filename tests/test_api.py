import hashlib
import hmac
import json
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from incidentlens.app import build_synthesizer, create_app
from incidentlens.config import Settings

SAMPLE = json.loads((Path(__file__).resolve().parents[1] / "examples" / "alertmanager_payload.json").read_text(encoding="utf-8"))
SECRET = "slack-signing-secret"


def client(lens, **kw):
    return TestClient(create_app(Settings(enable_scheduler=False, _env_file=None, **kw), service=lens))


def slack_post(c, action_id, value, user="U1", secret=SECRET, ts=None):
    payload = {"type": "block_actions", "user": {"id": user, "username": "alice"},
               "actions": [{"action_id": action_id, "value": value}]}
    body = urlencode({"payload": json.dumps(payload)}).encode()
    ts = ts or str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return c.post("/slack/interactions", content=body, headers={
        "content-type": "application/x-www-form-urlencoded",
        "x-slack-request-timestamp": ts, "x-slack-signature": sig})


def test_webhook_incident_and_lookup(lens, world, clock):
    with client(lens) as c:
        assert c.get("/healthz").json() == {"status": "ok"}
        resp = c.post("/webhooks/alertmanager", json=SAMPLE)
        assert resp.json() == {"received": 3, "critical": 1, "action": 1, "info": 1}
    # Thoát khỏi `with` = tắt ứng dụng: các cuộc điều tra đang chạy được chờ hoàn tất
    assert len(world.pages) == 1

    with client(lens) as c:
        incidents = c.get("/incidents").json()
        assert incidents[0]["code"] == "INC-0001" and incidents[0]["duration_minutes"] is None
        detail = c.get("/incidents/1").json()
        assert len(detail["investigations"]) == 1
        assert c.get("/alerts/a1b2c3d4e5f60002").json()["name"] == "DiskSpaceLow"
        assert c.get("/alerts/nope").status_code == 404
        assert c.get("/incidents/99").status_code == 404

        path = c.post("/digest/run").json()["path"]
        assert Path(path).exists()
        assert c.post("/escalations/check").json() == {"escalated": []}
        clock.now += timedelta(hours=5)  # cảnh báo 🟡 vẫn chưa hồi phục sau 5 giờ
        assert c.post("/escalations/check").json() == {"escalated": ["a1b2c3d4e5f60002"]}
        assert c.post("/maintenance/run").json()["purged"] == {"alerts": 0, "episodes": 0}


def test_feedback_resolution_postmortem_and_roi(lens):
    with client(lens) as c:
        c.post("/webhooks/alertmanager", json=SAMPLE)
    with client(lens) as c:
        assert c.post("/investigations/1/feedback", json={"choice": 9, "user": "a"}).status_code == 422
        assert c.post("/investigations/77/feedback", json={"choice": 1, "user": "a"}).status_code == 404
        assert c.post("/investigations/1/feedback", json={"choice": 0, "user": "alice"}).status_code == 200

        body = {"root_cause": "generateToken() không giải phóng bộ nhớ", "fix": "rollback về v2.3.1"}
        assert c.post("/incidents/1/resolution", json=body).json()["fix"] == "rollback về v2.3.1"
        assert c.post("/incidents/9/resolution", json=body).status_code == 404

        post = c.get("/incidents/1/postmortem")
        assert post.headers["content-type"].startswith("text/markdown")
        assert "generateToken() không giải phóng bộ nhớ" in post.text and "rollback về v2.3.1" in post.text
        assert c.get("/incidents/9/postmortem").status_code == 404

        roi = c.post("/reports/roi", params={"month": "2026-11"}).json()
        assert roi["markdown"].startswith("# 📊 Báo cáo tháng 11/2026") and Path(roi["path"]).exists()
        assert c.post("/reports/roi", params={"month": "thang-11"}).status_code == 422


def test_token_protects_every_endpoint(lens):
    with client(lens, webhook_token="secret") as c:
        for method, url in [("post", "/webhooks/alertmanager"), ("post", "/digest/run"), ("get", "/incidents"),
                            ("get", "/incidents/1/postmortem"), ("post", "/reports/roi"),
                            ("post", "/incidents/1/resolution"), ("post", "/investigations/1/feedback")]:
            assert getattr(c, method)(url).status_code == 401, url
        ok = c.post("/webhooks/alertmanager", json=SAMPLE, headers={"Authorization": "Bearer secret"})
        assert ok.status_code == 200
        assert c.get("/healthz").status_code == 200


def test_slack_buttons_require_valid_signature(lens, world):
    with client(lens) as c:
        c.post("/webhooks/alertmanager", json=SAMPLE)
        assert slack_post(c, "fb_1", "1:1").status_code == 503  # chưa cấu hình khóa ký

    with client(lens, slack_signing_secret=SECRET) as c:
        assert slack_post(c, "fb_1", "1:1", secret="wrong").status_code == 401
        assert slack_post(c, "fb_1", "1:1", ts=str(int(time.time()) - 3600)).status_code == 401  # phát lại
        assert c.post("/slack/interactions", content=b"payload=x").status_code == 401  # không có chữ ký
        assert lens.store.get_investigation(1).feedback is None

        assert slack_post(c, "fb_1", "1:1").status_code == 200
        assert lens.store.get_investigation(1).feedback == "up"

        # Hành động: người ngoài danh sách duyệt bị từ chối và được ghi vào nhật ký kiểm toán
        assert slack_post(c, "act_restart", "1:restart", user="U999").status_code == 200
        log = lens.store.actions_for_incident(1)
        assert [(a.action, a.status) for a in log] == [("restart", "denied")]


def test_llm_settings_validation():
    def s(**kw):
        return Settings(_env_file=None, **kw)

    assert build_synthesizer(s(), None) is None
    assert build_synthesizer(s(llm_provider="anthropic", llm_api_key="k", llm_model="m"), None) is not None
    assert build_synthesizer(s(llm_provider="openai-compatible", llm_base_url="http://x/v1", llm_model="m"), None)
    for bad in (dict(llm_provider="anthropic", llm_api_key="k"), dict(llm_provider="anthropic", llm_model="m"),
                dict(llm_provider="openai-compatible", llm_model="m")):
        with pytest.raises(ValueError):
            build_synthesizer(s(**bad), None)


def test_real_wiring_from_config_files(tmp_path, monkeypatch):
    """Khởi động ứng dụng thật từ file cấu hình (không tiêm service giả lập), ở chế độ dry-run."""
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    settings = Settings(_env_file=None, enable_scheduler=False, database_url=f"sqlite:///{tmp_path}/il.db",
                        digest_dir=tmp_path / "digests")
    with TestClient(create_app(settings)) as c:
        assert c.post("/webhooks/alertmanager", json=SAMPLE).json()["critical"] == 1
        assert Path(c.post("/digest/run").json()["path"]).exists()
    with TestClient(create_app(settings)) as c:
        assert c.get("/incidents/1").json()["investigations"][0]["investigation"]["engine"] == "rules"
