"""Các trường hợp biên: lịch chạy định kỳ, biến thể thẻ điều tra, lỗi Git, lỗi mạng."""

import asyncio
import subprocess
from datetime import timedelta

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
            raise RuntimeError("lỗi lần đầu")

    task = asyncio.create_task(_every(0.01, job))
    await asyncio.sleep(0.08)
    task.cancel()
    assert len(calls) >= 3  # lỗi ở lần đầu không làm dừng lịch


def test_scheduler_starts_and_stops_cleanly(lens):
    settings = Settings(_env_file=None, enable_scheduler=True)
    with TestClient(create_app(settings, service=lens)) as c:
        assert c.get("/healthz").status_code == 200


async def test_card_when_nothing_found(lens, world):
    await lens.handle_alerts([make_alert(service="payment-worker", starts_at=START)])
    await lens.drain()
    card = world.slack[-1]
    assert "Không tìm thấy bất thường nào" in card["text"]
    ids = [e["action_id"] for b in card["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert "fb_1" not in ids and "fb_0" not in ids  # không có giả thuyết thì không hỏi đúng/sai
    assert "act_rollback" in ids


def test_card_with_evidence_but_no_hypothesis():
    target = InvestigationTarget(fingerprint="f", service="svc", name="A", summary="s", started_at=START)
    inv = Investigation(target=target, evidence=[
        {"id": "E1", "kind": "metric", "description": "x" * 500, "url": "http://p/graph?a=b|c>d"}])
    text, blocks = investigation_card(InvestigationRecord(id=1, created_at=START, investigation=inv), None, [], None)
    assert "Chưa đủ cơ sở để đưa ra giả thuyết" in text
    assert "b%7Cc%3Ed" in text and "…" in text  # link được mã hóa an toàn, mô tả dài được cắt
    assert not any(b["type"] == "actions" for b in blocks)  # không có sự cố → không có nút hành động


async def test_digest_shows_escalation_and_recent_deploy(lens, clock):
    await lens.handle_alerts([make_alert(name="MemoryHigh", severity="warning", starts_at=START)])
    clock.now += timedelta(hours=5)
    await lens.check_escalations()
    await lens.drain()
    text = (await lens.run_digest()).read_text(encoding="utf-8")
    assert "⬆️ đã tự động nâng lên 🔴" in text
    assert "**Thay đổi gần đây:**" in text and "deploy [`a1b2c3d`]" in text and "bởi dev-a" in text


def test_git_push_failure_is_logged_not_raised(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", str(tmp_path / "missing.git")], check=True)
    archive = DigestArchive(tmp_path, git_push=True)
    archive.write_named("a.md", "x")
    assert archive.sync("commit vẫn thành công dù push lỗi") is True
    assert DigestArchive(tmp_path, git_push=False).sync("tắt") is False


async def test_slack_respond_network_error(world):
    world.fail_hosts.add("hooks.slack.com")
    assert await SlackNotifier(world.client()).respond("https://hooks.slack.com/actions/x", "hi") is False
