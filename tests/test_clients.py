"""HTTP client tests for Prometheus, Loki, GitHub, Slack, PagerDuty, and LLM adapters."""

from datetime import timedelta
import hashlib
import hmac
import json

import httpx
import pytest

from conftest import START
from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import GitHubChangeProvider
from incidentlens.investigation.llm import AnthropicLLM, OpenAICompatibleLLM
from incidentlens.investigation.loki import LokiClient, top_patterns
from incidentlens.investigation.prometheus import PrometheusClient
from incidentlens.models import DeliveryStatus
from incidentlens.outputs.pagerduty import PagerDutyPager
from incidentlens.outputs.slack import SlackNotifier, verify_slack_signature
from incidentlens.testing import CONFIG


def mock(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_prometheus_query_range(world):
    prom = PrometheusClient("http://prometheus.test/", world.client())
    values = await prom.query_range('x{service="auth-service"} memory', START - timedelta(minutes=10), START, 60)
    assert len(values) == 11
    assert values[0] == 200 * 2**20 and values[-1] == 900 * 2**20


async def test_prometheus_skips_nan_and_reports_errors():
    ok = {"status": "success", "data": {"result": [{"values": [[1, "NaN"], [2, "1.5"], [3, "+Inf"]]}]}}
    prom = PrometheusClient("http://p", mock(lambda r: httpx.Response(200, json=ok)))
    assert await prom.query_range("q", START, START) == [1.5]

    bad = PrometheusClient("http://p", mock(lambda r: httpx.Response(200, json={"status": "error", "error": "boom"})))
    with pytest.raises(RuntimeError, match="boom"):
        await bad.query_range("q", START, START)


def test_prometheus_graph_url_is_encoded():
    url = PrometheusClient("http://p", None).graph_url('up{a="b|c"}', START)
    assert url.startswith("http://p/graph?g0.expr=up%7Ba%3D%22b%7Cc%22%7D")
    assert "|" not in url and ">" not in url


async def test_prometheus_sends_bearer_token():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"status": "success", "data": {"result": []}})

    await PrometheusClient("http://p", mock(handler), "tok").query_range("q", START, START)
    assert seen["auth"] == "Bearer tok"


async def test_loki_count_and_lines(world):
    loki = LokiClient("http://loki.test", world.client())
    query = '{service="auth-service"}'
    assert await loki.count(query, START + timedelta(minutes=1), 300) == 87
    assert await loki.count(query, START - timedelta(minutes=20), 300) == 3
    lines = await loki.lines(query, START, START + timedelta(minutes=5))
    assert len(lines) == 46 and "OutOfMemoryError" in lines[0]


async def test_loki_empty_result_returns_none_while_zero_returns_zero():
    empty_resp = {"status": "success", "data": {"result": []}}
    empty = LokiClient("http://loki.test", mock(lambda r: httpx.Response(200, json=empty_resp)))
    assert await empty.count('{service="auth-service"}', START, 300) is None

    zero_body = {"status": "success", "data": {"result": [{"metric": {}, "value": [1, "0"]}]}}
    quiet = LokiClient("http://loki.test", mock(lambda r: httpx.Response(200, json=zero_body)))
    assert await quiet.count('{service="auth-service"}', START, 300) == 0

    err_resp = {"status": "error", "error": "bad logql"}
    err = LokiClient("http://loki.test", mock(lambda r: httpx.Response(200, json=err_resp)))
    with pytest.raises(RuntimeError, match="bad logql"):
        await err.count('{service="auth-service"}', START, 300)


def test_loki_links():
    plain = LokiClient("http://loki.test", None).explore_url("{a}", START, START)
    assert plain.startswith("http://loki.test/loki/api/v1/query_range?")
    grafana = LokiClient("http://loki.test", None, "http://grafana.test/").explore_url("{a}", START, START)
    assert grafana.startswith("http://grafana.test/explore?left=")


def test_log_patterns_group_and_redact():
    lines = [f"2026-11-12T02:14:0{i}Z ERROR OOM user=u{i}@x.com req=4f9a000{i} took {i}.5ms" for i in range(5)]
    lines.append("something else")
    patterns = top_patterns(lines)
    assert patterns[0] == ("#time ERROR OOM user=[EMAIL] req=#id took #ms", 5)
    assert "@" not in patterns[0][0]


async def test_github_deployments(world):
    catalog = ServiceCatalog.from_yaml(CONFIG / "services.yaml")
    gh = GitHubChangeProvider("tok", catalog, world.client())
    changes = await gh.recent_changes("auth-service", START - timedelta(hours=2))
    assert [(c.ref, c.author, c.kind) for c in changes] == [("a1b2c3d", "dev-a", "deploy")]
    assert changes[0].url.endswith("/commit/a1b2c3d4e5f6a7b8c9d0")
    assert await gh.recent_changes("auth-service", START) == []  # Before `since` cutoff
    assert await gh.recent_changes("user-db", START - timedelta(hours=2)) == []  # Unmapped repo

    world.fail_hosts.add("api.github.com")
    assert await gh.recent_changes("auth-service", START - timedelta(hours=2)) == []  # Graceful degradation


async def test_github_filters_environment_status_and_paginates():
    catalog = ServiceCatalog.from_yaml(CONFIG / "services.yaml")
    seen_envs: list[str | None] = []
    seen_pages: list[int] = []
    at = (START - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")

    statuses_by_id = {
        10: [{"state": "failure"}],
        11: [{"state": "in_progress"}],
        12: [],
        13: [{"state": "inactive"}, {"state": "failure"}],
        14: [{"state": "inactive"}, {"state": "success"}],
        15: [{"state": "success"}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/deployments"):
            seen_envs.append(request.url.params.get("environment"))
            page = int(request.url.params.get("page", "1"))
            seen_pages.append(page)
            if page == 1:
                # 25 staging/failed deploys on page 1 (per_page=25) would previously push out page 2's prod deploy.
                items = [
                    {
                        "id": 100 + i,
                        "environment": "staging",
                        "sha": f"stage{i:04d}",
                        "created_at": at,
                        "creator": {"login": "ci"},
                    }
                    for i in range(21)
                ] + [
                    {
                        "id": dep_id,
                        "environment": "production",
                        "sha": sha,
                        "created_at": at,
                        "creator": {"login": login},
                    }
                    for dep_id, sha, login in [
                        (10, "failed00", "dev-f"),
                        (11, "inprog00", "dev-p"),
                        (12, "nostat00", "dev-n"),
                        (13, "inactf00", "dev-x"),
                    ]
                ]
                return httpx.Response(200, json=items)
            if page == 2:
                return httpx.Response(
                    200,
                    json=[
                        {
                            "id": 14,
                            "environment": "production",
                            "sha": "supersed1234",
                            "created_at": (START - timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "creator": {"login": "dev-old"},
                        },
                        {
                            "id": 15,
                            "environment": "production",
                            "sha": "goodprod1234",
                            "created_at": (START - timedelta(minutes=25)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "creator": {"login": "dev-ok"},
                        },
                    ],
                )
            return httpx.Response(200, json=[])
        for dep_id, st in statuses_by_id.items():
            if path.endswith(f"/deployments/{dep_id}/statuses"):
                return httpx.Response(200, json=st)
        return httpx.Response(404)

    gh = GitHubChangeProvider("tok", catalog, mock(handler), per_page=25)
    changes = await gh.recent_changes("auth-service", START - timedelta(hours=2))
    assert seen_envs == ["production", "production"]
    assert seen_pages == [1, 2]
    assert [c.ref for c in changes] == ["goodpro", "superse"]


async def test_slack_bot_webhook_and_dry_run(world):
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "x"}}]
    assert await SlackNotifier(world.client(), bot_token="xoxb", channel="#c").send("hi", blocks)
    assert world.slack[-1] == {"channel": "#c", "text": "hi", "blocks": blocks}

    assert await SlackNotifier(world.client(), webhook_url="https://hooks.slack.com/services/T/B/x").send("yo")
    assert world.slack[-1] == {"text": "yo"}

    assert await SlackNotifier(world.client()).send("nobody") == DeliveryStatus.NOT_CONFIGURED
    world.fail_hosts.add("slack.com")
    assert await SlackNotifier(world.client(), bot_token="xoxb", channel="#c").send("hi") == DeliveryStatus.FAILED


async def test_slack_rejection_is_reported():
    client = mock(lambda r: httpx.Response(200, json={"ok": False, "error": "channel_not_found"}))
    assert await SlackNotifier(client, bot_token="x", channel="#c").send("hi") == DeliveryStatus.FAILED


async def test_slack_respond_only_to_slack(world):
    slack = SlackNotifier(world.client())
    assert await slack.respond("https://hooks.slack.com/actions/T/1/x", "done")
    assert world.slack[-1]["text"] == "done"
    assert await slack.respond("https://evil.example.com/steal", "done") is False
    assert await slack.respond(None, "done") is False


def test_slack_signature():
    secret, body, ts = "s3cret", b"payload=%7B%7D", "1700000000"
    sig = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    assert verify_slack_signature(secret, ts, body, sig, now=1700000100)
    assert not verify_slack_signature(secret, ts, body, sig, now=1700000900)  # Replayed after 15 minutes
    assert not verify_slack_signature(secret, ts, body + b"x", sig, now=1700000100)  # Tampered body
    assert not verify_slack_signature("other", ts, body, sig, now=1700000100)
    assert not verify_slack_signature(secret, None, body, sig)
    assert not verify_slack_signature(secret, "abc", body, sig)


async def test_pagerduty_trigger_resolve_and_dry_run(world, caplog):
    import logging

    pager = PagerDutyPager("rk", world.client())
    assert await pager.trigger("fp1", "boom", "svc", {"a": "b"}, "http://src")
    event = world.pages[-1]
    assert event["routing_key"] == "rk" and event["event_action"] == "trigger" and event["dedup_key"] == "fp1"
    assert event["payload"]["severity"] == "critical" and event["links"][0]["href"] == "http://src"
    assert await pager.resolve("fp1") and world.pages[-1]["event_action"] == "resolve"

    with caplog.at_level(logging.WARNING):
        assert await PagerDutyPager(None, world.client()).trigger("fp", "s", "svc") == DeliveryStatus.NOT_CONFIGURED
    assert any(r.levelno == logging.WARNING and "PagerDuty not configured" in r.message for r in caplog.records)
    world.fail_hosts.add("events.pagerduty.com")
    assert await pager.trigger("fp", "s", "svc") == DeliveryStatus.FAILED


async def test_anthropic_client(world):
    world.llm_reply = "hello"
    llm = AnthropicLLM("key", "some-model", world.client())
    assert await llm.complete("sys", "user") == "hello"
    sent = world.llm_requests[-1]
    assert sent["model"] == "some-model" and sent["system"] == "sys"
    assert sent["messages"] == [{"role": "user", "content": "user"}]


async def test_openai_compatible_client():
    seen = {}

    def handler(request):
        seen["url"], seen["auth"], seen["body"] = (
            str(request.url),
            request.headers.get("authorization"),
            json.loads(request.content),
        )
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    llm = OpenAICompatibleLLM("http://llm.internal/v1/", "local-model", mock(handler), "k")
    assert await llm.complete("sys", "user") == "ok"
    assert seen["url"] == "http://llm.internal/v1/chat/completions" and seen["auth"] == "Bearer k"
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]
