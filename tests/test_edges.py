"""Edge cases: periodic scheduler resilience, investigation card variants, Git errors, and network errors."""

import asyncio
from datetime import timedelta
import subprocess

from fastapi.testclient import TestClient

from conftest import START
from incidentlens.app import _every, create_app
from incidentlens.config import Settings
from incidentlens.models import Investigation, InvestigationRecord, InvestigationTarget
from incidentlens.outputs.archive import DigestArchive
from incidentlens.outputs.cards import investigation_card
from incidentlens.outputs.slack import SlackNotifier
from incidentlens.testing import make_alert


async def test_periodic_job_survives_errors():
    calls = []

    async def job():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("first run failure")

    task = asyncio.create_task(_every(0.01, job))
    await asyncio.sleep(0.08)
    task.cancel()
    assert len(calls) >= 3  # First failure does not terminate the schedule


def test_scheduler_starts_and_stops_cleanly(lens):
    settings = Settings(_env_file=None, enable_scheduler=True)
    with TestClient(create_app(settings, service=lens)) as c:
        assert c.get("/healthz").status_code == 200


async def test_card_when_nothing_found(lens, world):
    await lens.handle_alerts([make_alert(service="payment-worker", starts_at=START)])
    await lens.drain()
    card = world.slack[-1]
    assert "No anomalies found" in card["text"]
    ids = [e["action_id"] for b in card["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert "fb_1" not in ids and "fb_0" not in ids  # No feedback buttons when there are no hypotheses
    assert "act_rollback" in ids


def test_card_with_evidence_but_no_hypothesis():
    target = InvestigationTarget(fingerprint="f", service="svc", name="A", summary="s", started_at=START)
    inv = Investigation(
        target=target,
        evidence=[{"id": "E1", "kind": "metric", "description": "x" * 500, "url": "http://p/graph?a=b|c>d"}],
    )
    text, blocks = investigation_card(InvestigationRecord(id=1, created_at=START, investigation=inv), None, [], None)
    assert "Insufficient basis for a hypothesis" in text
    assert "b%7Cc%3Ed" in text and "…" in text  # URL characters escaped and long text truncated
    assert not any(b["type"] == "actions" for b in blocks)


async def test_digest_shows_escalation_and_recent_deploy(lens, clock):
    await lens.handle_alerts([make_alert(name="MemoryHigh", severity="warning", starts_at=START)])
    clock.now += timedelta(hours=5)
    await lens.check_escalations()
    await lens.drain()
    text = (await lens.run_digest()).read_text(encoding="utf-8")
    assert "⬆️ automatically escalated to 🔴" in text
    assert "**Recent changes:**" in text and "deploy [`a1b2c3d`]" in text and "by dev-a" in text


def test_git_push_failure_is_logged_not_raised(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", str(tmp_path / "missing.git")], check=True)
    archive = DigestArchive(tmp_path, git_push=True)
    archive.write_named("a.md", "x")
    assert archive.sync("commit succeeds despite missing remote") is True
    assert DigestArchive(tmp_path, git_push=False).sync("disabled") is False


async def test_slack_respond_network_error(world):
    world.fail_hosts.add("hooks.slack.com")
    assert await SlackNotifier(world.client()).respond("https://hooks.slack.com/actions/x", "hi") is False
