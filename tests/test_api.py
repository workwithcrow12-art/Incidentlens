import asyncio
from datetime import timedelta
import hashlib
import hmac
import json
import logging
from pathlib import Path
import time
from urllib.parse import urlencode

from fastapi.testclient import TestClient
import pytest
import yaml

from conftest import START
from incidentlens.app import build_synthesizer, create_app
from incidentlens.config import Settings
from incidentlens.outputs.pagerduty import PagerDutyPager
from incidentlens.testing import make_alert

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "examples" / "alertmanager_payload.json").read_text(encoding="utf-8"))
SECRET = "slack-signing-secret"
TOKEN = "test-webhook-token"


def client(lens, *, webhook_token=TOKEN, auth_header=True, **kw):
    headers = {"Authorization": f"Bearer {webhook_token}"} if auth_header and webhook_token else None
    return TestClient(
        create_app(Settings(enable_scheduler=False, _env_file=None, webhook_token=webhook_token, **kw), service=lens),
        headers=headers,
    )


def slack_post(c, action_id, value, user="U1", secret=SECRET, ts=None):
    payload = {
        "type": "block_actions",
        "user": {"id": user, "username": "alice"},
        "actions": [{"action_id": action_id, "value": value}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode()
    ts = ts or str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return c.post(
        "/slack/interactions",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )


def test_webhook_incident_and_lookup(lens, world, clock):
    with client(lens) as c:
        assert c.get("/healthz").json() == {"status": "ok"}
        resp = c.post("/webhooks/alertmanager", json=SAMPLE)
        assert resp.json() == {"received": 3, "critical": 1, "action": 1, "info": 1}
    # Exiting `with` runs shutdown lifespan, draining in-flight investigations.
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
        clock.now += timedelta(hours=5)  # 🟡 warning remains unresolved after 5 hours
        assert c.post("/escalations/check").json() == {"escalated": ["a1b2c3d4e5f60002"]}
        assert c.post("/maintenance/run").json()["purged"] == {
            "alerts": 0,
            "episodes": 0,
            "interactions": 0,
            "deliveries": 0,
        }


def test_feedback_resolution_postmortem_and_roi(lens):
    with client(lens) as c:
        c.post("/webhooks/alertmanager", json=SAMPLE)
    with client(lens) as c:
        assert c.post("/investigations/1/feedback", json={"choice": 9, "user": "a"}).status_code == 422
        assert c.post("/investigations/77/feedback", json={"choice": 1, "user": "a"}).status_code == 404
        assert c.post("/investigations/1/feedback", json={"choice": 0, "user": "alice"}).status_code == 200

        body = {"root_cause": "generateToken() leaked buffers", "fix": "roll back to v2.3.1"}
        assert c.post("/incidents/1/resolution", json=body).json()["fix"] == "roll back to v2.3.1"
        assert c.post("/incidents/9/resolution", json=body).status_code == 404

        post = c.get("/incidents/1/postmortem")
        assert post.headers["content-type"].startswith("text/markdown")
        assert "generateToken() leaked buffers" in post.text and "roll back to v2.3.1" in post.text
        assert c.get("/incidents/9/postmortem").status_code == 404

        roi = c.post("/reports/roi", params={"month": "2026-11"}).json()
        assert roi["markdown"].startswith("# 📊 Monthly ROI Report 11/2026") and Path(roi["path"]).exists()
        assert c.post("/reports/roi", params={"month": "nov-2026"}).status_code == 422


def test_token_protects_every_endpoint(lens):
    with client(lens, webhook_token="secret", auth_header=False) as c:
        for method, url in [
            ("post", "/webhooks/alertmanager"),
            ("post", "/digest/run"),
            ("get", "/incidents"),
            ("get", "/incidents/1/postmortem"),
            ("post", "/reports/roi"),
            ("post", "/incidents/1/resolution"),
            ("post", "/investigations/1/feedback"),
        ]:
            assert getattr(c, method)(url).status_code == 401, url
        ok = c.post("/webhooks/alertmanager", json=SAMPLE, headers={"Authorization": "Bearer secret"})
        assert ok.status_code == 200
        assert c.get("/healthz").status_code == 200


@pytest.mark.parametrize("empty_token", [None, "", "   "])
def test_empty_or_unset_webhook_token_fails_closed(lens, empty_token):
    with client(lens, webhook_token=empty_token, auth_header=False) as c:
        assert c.get("/incidents").status_code == 401
        assert c.get("/incidents", headers={"Authorization": "Bearer "}).status_code == 401
        assert c.post("/webhooks/alertmanager", json=SAMPLE).status_code == 401
        assert c.get("/healthz").status_code == 200

    with client(lens, webhook_token=empty_token, auth_header=False, allow_unauthenticated=True) as dev_client:
        assert dev_client.get("/incidents").status_code == 200


def test_compose_binds_loopback_and_requires_webhook_token():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    svc = compose["services"]["incidentlens"]
    assert svc["ports"] == ["${IL_BIND_HOST:-127.0.0.1}:8000:8000"]
    assert svc["environment"]["IL_WEBHOOK_TOKEN"].startswith("${IL_WEBHOOK_TOKEN:?")
    assert svc["volumes"] == ["digests:/app/digests"]
    assert "digests" in compose["volumes"]


def test_env_example_has_no_inline_comments_that_break_docker_compose(tmp_path):
    raw = (ROOT / ".env.example").read_text(encoding="utf-8")
    kv: dict[str, str] = {}
    for lineno, line in enumerate(raw.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        assert "=" in line, f"Invalid line {lineno} in .env.example: {line!r}"
        key, value = line.split("=", 1)
        assert "#" not in value, f"Inline comment on {key} breaks Docker Compose/--env-file parsing"
        assert value == value.strip(), f"Leading/trailing whitespace on {key} in .env.example"
        kv[key] = value
    assert kv["IL_WEBHOOK_TOKEN"] == ""
    assert kv["IL_SLACK_SIGNING_SECRET"] == ""

    env_copy = tmp_path / ".env"
    env_copy.write_text(raw, encoding="utf-8")
    loaded = Settings(_env_file=env_copy)
    assert loaded.webhook_token is None
    assert loaded.slack_signing_secret is None
    assert loaded.github_token is None
    assert loaded.grafana_url is None


def test_slack_buttons_require_valid_signature(lens, world):
    with client(lens) as c:
        c.post("/webhooks/alertmanager", json=SAMPLE)
        assert slack_post(c, "fb_1", "1:1").status_code == 503  # signing secret not configured

    with client(lens, slack_signing_secret=SECRET) as c:
        assert slack_post(c, "fb_1", "1:1", secret="wrong").status_code == 401
        assert slack_post(c, "fb_1", "1:1", ts=str(int(time.time()) - 3600)).status_code == 401  # replay expired
        assert c.post("/slack/interactions", content=b"payload=x").status_code == 401  # missing signature
        assert lens.store.get_investigation(1).feedback is None

        assert slack_post(c, "fb_1", "1:1").status_code == 200
        assert lens.store.get_investigation(1).feedback == "up"

        # Unauthorized action click is denied and recorded in the audit log
        assert slack_post(c, "act_restart", "1:restart", user="U999").status_code == 200
        log = lens.store.actions_for_incident(1)
        assert [(a.action, a.status) for a in log] == [("restart", "denied")]


def test_llm_settings_validation():
    def s(**kw):
        return Settings(_env_file=None, **kw)

    assert build_synthesizer(s(), None) is None
    assert build_synthesizer(s(llm_provider="anthropic", llm_api_key="k", llm_model="m"), None) is not None
    assert build_synthesizer(s(llm_provider="openai-compatible", llm_base_url="http://x/v1", llm_model="m"), None)
    for bad in (
        dict(llm_provider="anthropic", llm_api_key="k"),
        dict(llm_provider="anthropic", llm_model="m"),
        dict(llm_provider="openai-compatible", llm_model="m"),
    ):
        with pytest.raises(ValueError):
            build_synthesizer(s(**bad), None)


def test_real_wiring_from_config_files(tmp_path, monkeypatch, caplog):
    """Boot the real FastAPI app from shipped YAML configs without injected test doubles."""
    monkeypatch.chdir(ROOT)
    settings = Settings(
        _env_file=None,
        enable_scheduler=False,
        webhook_token=TOKEN,
        database_url=f"sqlite:///{tmp_path}/il.db",
        digest_dir=tmp_path / "digests",
    )
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with caplog.at_level(logging.WARNING):
        with TestClient(create_app(settings), headers=auth) as c:
            assert c.post("/webhooks/alertmanager", json=SAMPLE).json()["critical"] == 1
            assert Path(c.post("/digest/run").json()["path"]).exists()
    assert any(
        r.levelno == logging.WARNING and "PagerDuty not configured" in r.message for r in caplog.records
    )
    with TestClient(create_app(settings), headers=auth) as c:
        assert c.get("/incidents/1").json()["investigations"][0]["investigation"]["engine"] == "rules"


def test_startup_does_not_warn_when_pagerduty_is_configured(lens, caplog):
    with caplog.at_level(logging.WARNING):
        with client(lens) as c:
            assert c.get("/healthz").status_code == 200
    assert not any("PagerDuty not configured" in r.message for r in caplog.records)

    lens.pager = PagerDutyPager(None, None)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        with client(lens) as c:
            assert c.get("/healthz").status_code == 200
    assert any("PagerDuty not configured" in r.message for r in caplog.records)


def test_postmortem_regenerates_on_post_recovery_updates_until_manually_edited(lens, clock):
    with client(lens) as c:
        c.post("/webhooks/alertmanager", json=SAMPLE)

    clock.now = START + timedelta(minutes=25)
    asyncio.run(
        lens.handle_alerts([make_alert(fp="a1b2c3d4e5f60001", status="resolved", starts_at=START, ends_at=clock.now)])
    )
    asyncio.run(lens.drain())
    postmortem_file = lens.archive.root / "postmortems" / "INC-0001.md"
    assert postmortem_file.exists()
    assert "_To be determined" in postmortem_file.read_text(encoding="utf-8")

    # Adding human root cause & fix after recovery regenerates the unedited postmortem and updates GET.
    with client(lens) as c:
        res = c.post(
            "/incidents/1/resolution",
            json={"root_cause": "Connection leak in auth pool", "fix": "Rolled back auth-service to v2.3.1"},
        )
        assert res.status_code == 200
        text = c.get("/incidents/1/postmortem").text
        assert "Connection leak in auth pool" in text
        assert "Rolled back auth-service to v2.3.1" in text
        assert text == postmortem_file.read_text(encoding="utf-8")

        # Later Slack/API hypothesis feedback also updates the unedited postmortem.
        fb = c.post("/investigations/1/feedback", json={"choice": 1, "user": "alice"})
        assert fb.status_code == 200
        text_after_fb = c.get("/incidents/1/postmortem").text
        assert "confirmed by alice" in text_after_fb
        assert "Connection leak in auth pool" in text_after_fb  # Human root cause preserved
        assert text_after_fb == postmortem_file.read_text(encoding="utf-8")

    # Once an engineer manually edits the file on disk, later updates never overwrite their file edits.
    manual = postmortem_file.read_text(encoding="utf-8") + "\n- [x] Added pool saturation alert.\n"
    postmortem_file.write_text(manual, encoding="utf-8")
    with client(lens) as c:
        c.post("/incidents/1/resolution", json={"fix": "Updated pool cap"})
        assert c.get("/incidents/1/postmortem").text == manual
    assert postmortem_file.read_text(encoding="utf-8") == manual


def test_get_postmortem_is_read_only_and_preserves_manual_edits(lens, clock):
    with client(lens) as c:
        c.post("/webhooks/alertmanager", json=SAMPLE)

    postmortem_file = lens.archive.root / "postmortems" / "INC-0001.md"
    with client(lens) as c:
        draft = c.get("/incidents/1/postmortem")
        assert draft.status_code == 200 and "INC-0001" in draft.text
        assert not postmortem_file.exists()

    clock.now = START + timedelta(minutes=25)
    asyncio.run(
        lens.handle_alerts([make_alert(fp="a1b2c3d4e5f60001", status="resolved", starts_at=START, ends_at=clock.now)])
    )
    asyncio.run(lens.drain())
    assert postmortem_file.exists()

    edited = postmortem_file.read_text(encoding="utf-8") + "\nManual postmortem edit by engineer.\n"
    postmortem_file.write_text(edited, encoding="utf-8")

    with client(lens) as c:
        fetched = c.get("/incidents/1/postmortem")
        assert fetched.status_code == 200
        assert "Manual postmortem edit by engineer." in fetched.text
    assert postmortem_file.read_text(encoding="utf-8") == edited


async def test_slow_database_call_does_not_block_async_event_loop(lens, monkeypatch):
    import httpx

    entered = asyncio.Event()
    loop = asyncio.get_running_loop()
    original_list = lens.store.list_incidents

    def slow_list_incidents(limit: int = 50):
        loop.call_soon_threadsafe(entered.set)
        time.sleep(0.25)
        return original_list(limit)

    monkeypatch.setattr(lens.store, "list_incidents", slow_list_incidents)
    app = create_app(Settings(enable_scheduler=False, _env_file=None, webhook_token=TOKEN), service=lens)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test", headers=headers) as ac:
            slow_req = asyncio.create_task(ac.get("/incidents"))
            await asyncio.wait_for(entered.wait(), timeout=1.0)
            t0 = time.monotonic()
            health = await ac.get("/healthz")
            elapsed = time.monotonic() - t0
            assert health.status_code == 200
            assert elapsed < 0.15  # Responds while slow DB call is still sleeping in worker thread
            resp = await slow_req
            assert resp.status_code == 200


def test_dockerfile_uses_locked_uv_and_non_root_user():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "uv.lock" in dockerfile
    assert "uv sync --locked" in dockerfile
    user_lines = [line.strip() for line in dockerfile.splitlines() if line.strip().startswith("USER ")]
    assert user_lines and user_lines[-1] != "USER root" and user_lines[-1] != "USER 0"
