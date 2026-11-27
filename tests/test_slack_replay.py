import asyncio
import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from threading import Barrier
from urllib.parse import urlencode

import httpx
import pytest

from incidentlens.actions.runner import ActionRunner, ActionsConfig, ActionSpec
from incidentlens.app import create_app
from incidentlens.config import Settings
from incidentlens.store import Store
from incidentlens.testing import make_alert, simulated_service

SECRET = "slack-replay-test-secret"


def signed_action(*, action_id="act_restart", value="1:restart", action_ts="12345.001", timestamp=None):
    payload = {
        "type": "block_actions",
        "user": {"id": "U1", "username": "alice"},
        "actions": [{"action_id": action_id, "value": value, "action_ts": action_ts}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode()
    timestamp = timestamp or str(int(time.time()))
    signature = hmac.new(
        SECRET.encode(), b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256
    ).hexdigest()
    return {"content": body, "headers": {
        "content-type": "application/x-www-form-urlencoded",
        "x-slack-request-timestamp": timestamp,
        "x-slack-signature": "v0=" + signature,
    }}


@asynccontextmanager
async def slack_client(lens):
    settings = Settings(_env_file=None, enable_scheduler=False, slack_signing_secret=SECRET)
    app = create_app(settings, service=lens)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
            yield client


@pytest.fixture
def action_service(tmp_path, clock, world):
    executed = []
    database_url = f"sqlite:///{tmp_path / 'interactions.db'}"
    config = ActionsConfig(actions={"restart": ActionSpec(
        label="Restart", command=["restart-test", "{service}"], approvers=["U1"]
    )})

    async def executor(argv, timeout):
        executed.append(argv)
        await asyncio.sleep(0)
        return 0, "restarted"

    def build():
        lens = simulated_service(tmp_path / "archive", clock, world, database_url=database_url)
        lens.actions = ActionRunner(config, enabled=True, executor=executor)
        if lens.store.get_incident(1) is None:
            record = lens.store.record(lens.router.classify(make_alert(starts_at=clock.now)), clock.now)
            lens.store.open_incident(record, "critical", clock.now)
        return lens

    return build, executed


async def test_identical_signed_requests_execute_once_and_keep_audit(action_service):
    build, executed = action_service
    lens = build()
    request = signed_action()
    async with slack_client(lens) as client:
        first = await client.post("/slack/interactions", **request)
        retry = await client.post("/slack/interactions", **request)

    assert first.status_code == retry.status_code == 200
    assert executed == [["restart-test", "auth-service"]]
    audit = lens.store.actions_for_incident(1)
    assert [(row.action, row.status, row.user, row.output) for row in audit] == [
        ("restart", "executed", "alice (U1)", "restarted")
    ]


async def test_simultaneous_signed_retries_execute_once(action_service):
    build, executed = action_service
    lens = build()
    request = signed_action()
    async with slack_client(lens) as client:
        responses = await asyncio.gather(*(
            client.post("/slack/interactions", **request) for _ in range(8)
        ))

    assert [response.status_code for response in responses] == [200] * 8
    assert executed == [["restart-test", "auth-service"]]
    assert len(lens.store.actions_for_incident(1)) == 1


async def test_signed_retry_is_deduplicated_after_store_reopens(action_service):
    build, executed = action_service
    request = signed_action()
    original = build()
    async with slack_client(original) as client:
        assert (await client.post("/slack/interactions", **request)).status_code == 200
    original.store._engine.dispose()

    reopened = build()
    async with slack_client(reopened) as client:
        assert (await client.post("/slack/interactions", **request)).status_code == 200

    assert executed == [["restart-test", "auth-service"]]
    assert len(reopened.store.actions_for_incident(1)) == 1


@pytest.mark.parametrize("change", ["body", "timestamp"])
async def test_fresh_signed_action_respects_cooldown_and_requires_reconfirm(action_service, clock, change):
    from datetime import timedelta

    build, executed = action_service
    lens = build()
    timestamp = str(int(time.time()))
    first = signed_action(timestamp=timestamp)
    during_cooldown = (
        signed_action(action_ts="12345.002", timestamp=timestamp)
        if change == "body"
        else signed_action(timestamp=str(int(timestamp) + 1))
    )
    after_cooldown_unconfirmed = (
        signed_action(action_ts="12345.003", timestamp=timestamp)
        if change == "body"
        else signed_action(timestamp=str(int(timestamp) + 2))
    )
    after_cooldown_confirmed = (
        signed_action(
            action_id="act_confirm_restart",
            value="1:restart:confirm:1",
            action_ts="12345.004",
            timestamp=timestamp,
        )
        if change == "body"
        else signed_action(
            action_id="act_confirm_restart",
            value="1:restart:confirm:1",
            timestamp=str(int(timestamp) + 3),
        )
    )
    async with slack_client(lens) as client:
        assert (await client.post("/slack/interactions", **first)).status_code == 200
        assert (await client.post("/slack/interactions", **during_cooldown)).status_code == 200
        assert executed == [["restart-test", "auth-service"]]
        clock.now += timedelta(minutes=6)
        assert (await client.post("/slack/interactions", **after_cooldown_unconfirmed)).status_code == 200
        assert executed == [["restart-test", "auth-service"]]
        assert (await client.post("/slack/interactions", **after_cooldown_confirmed)).status_code == 200

    assert executed == [["restart-test", "auth-service"], ["restart-test", "auth-service"]]
    assert [row.status for row in lens.store.actions_for_incident(1)] == [
        "executed",
        "denied",
        "denied",
        "executed",
    ]


async def test_invalid_signature_does_not_consume_a_valid_request(action_service):
    build, executed = action_service
    lens = build()
    request = signed_action()
    invalid = {**request, "headers": {**request["headers"], "x-slack-signature": "v0=invalid"}}
    async with slack_client(lens) as client:
        assert (await client.post("/slack/interactions", **invalid)).status_code == 401
        assert executed == []
        assert (await client.post("/slack/interactions", **request)).status_code == 200

    assert executed == [["restart-test", "auth-service"]]
    assert len(lens.store.actions_for_incident(1)) == 1


def test_interaction_claim_is_atomic_across_store_connections(tmp_path, clock):
    database_url = f"sqlite:///{tmp_path / 'claims.db'}"
    stores = [Store(database_url) for _ in range(6)]
    barrier = Barrier(len(stores))

    def claim(store):
        barrier.wait(timeout=5)
        return store.claim_interaction("same-signed-request", clock.now)

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        claimed = list(pool.map(claim, stores))

    assert claimed.count(True) == 1
    assert claimed.count(False) == 5
