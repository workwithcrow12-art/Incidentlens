"""Môi trường giả lập cho test và demo.

Giả lập các hệ thống bên ngoài (Prometheus, Loki, GitHub, Slack, PagerDuty, LLM) ở tầng HTTP,
nên toàn bộ mã nguồn thật của IncidentLens (kể cả phần gọi và đọc API) đều được chạy qua.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from incidentlens.actions.runner import ActionRunner, ActionsConfig
from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import GitHubChangeProvider
from incidentlens.investigation.engine import EvidenceEngine
from incidentlens.investigation.llm import AnthropicLLM, Synthesizer
from incidentlens.investigation.loki import LokiClient
from incidentlens.investigation.prometheus import PrometheusClient
from incidentlens.investigation.signals import SignalConfig
from incidentlens.memory.similarity import IncidentMemory
from incidentlens.models import Alert
from incidentlens.outputs.archive import DigestArchive
from incidentlens.outputs.pagerduty import PagerDutyPager
from incidentlens.outputs.slack import SlackNotifier
from incidentlens.reports.roi import Baseline
from incidentlens.routing.rules import Router
from incidentlens.service import IncidentLens
from incidentlens.store import Base, Store

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class SimulatedWorld:
    """Một hệ thống đang gặp sự cố: `broken` bị rò rỉ bộ nhớ sau một lần deploy."""

    def __init__(self, incident_start: datetime, broken: str = "auth-service",
                 deploy_minutes_before: int | None = 30, llm_reply: str | None = None) -> None:
        self.incident_start = incident_start
        self.broken = broken
        self.deploy_minutes_before = deploy_minutes_before
        self.llm_reply = llm_reply
        self.slack: list[dict] = []
        self.pages: list[dict] = []
        self.llm_requests: list[dict] = []
        self.fail_hosts: set[str] = set()

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle), timeout=5)

    # --- Giá trị metric: bình thường trước sự cố, bất thường từ 4 phút trước khi cảnh báo bắn ---
    def _value(self, query: str, ts: float) -> float:
        bad = self.broken in query and ts >= (self.incident_start - timedelta(minutes=4)).timestamp()
        if "memory" in query:
            return 900 * 2**20 if bad else 200 * 2**20
        if "5.." in query:
            return 0.05 if bad else 0.002
        if "duration" in query:
            return 0.45 if bad else 0.05
        if "cpu" in query:
            return 0.32 if bad else 0.30
        return 0.0

    def _handle(self, request: httpx.Request) -> httpx.Response:
        host, path, q = request.url.host, request.url.path, request.url.params
        if host in self.fail_hosts:
            return httpx.Response(503, text="unavailable")

        if host == "prometheus.test" and path == "/api/v1/query_range":
            start, end, step = float(q["start"]), float(q["end"]), float(q["step"])
            values, ts = [], start
            while ts <= end:
                values.append([ts, str(self._value(q["query"], ts))])
                ts += step
            return httpx.Response(200, json={"status": "success", "data": {
                "resultType": "matrix", "result": [{"metric": {}, "values": values}]}})

        if host == "loki.test" and path == "/loki/api/v1/query":
            at = int(q["time"]) / 1e9
            count = 87 if self.broken in q["query"] and at >= self.incident_start.timestamp() else 3
            return httpx.Response(200, json={"status": "success", "data": {
                "resultType": "vector", "result": [{"metric": {}, "value": [at, str(count)]}]}})

        if host == "loki.test" and path == "/loki/api/v1/query_range":
            lines = [[str(int(q["end"]) - i), f"2026-11-12T02:{14 + i % 40:02d}:00Z ERROR OutOfMemoryError in "
                      f"generateToken() user=alice{i}@example.com token=abc{i}def request=4f9a{i:04d}"]
                     for i in range(40)]
            lines += [[q["end"], "ERROR connection reset by peer 10.0.0.7:5432"]] * 6
            return httpx.Response(200, json={"status": "success", "data": {
                "resultType": "streams", "result": [{"stream": {}, "values": lines}]}})

        if host == "api.github.com" and path.endswith("/deployments"):
            if self.broken not in path or self.deploy_minutes_before is None:
                return httpx.Response(200, json=[])
            at = self.incident_start - timedelta(minutes=self.deploy_minutes_before)
            return httpx.Response(200, json=[{
                "sha": "a1b2c3d4e5f6a7b8c9d0", "created_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "creator": {"login": "dev-a"}}])

        if host == "slack.com" and path == "/api/chat.postMessage":
            self.slack.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})
        if host == "hooks.slack.com":
            self.slack.append(json.loads(request.content))
            return httpx.Response(200, text="ok")

        if host == "events.pagerduty.com":
            self.pages.append(json.loads(request.content))
            return httpx.Response(202, json={"status": "success"})

        if host == "api.anthropic.com" and path == "/v1/messages":
            self.llm_requests.append(json.loads(request.content))
            if self.llm_reply is None:
                return httpx.Response(500, text="error")
            return httpx.Response(200, json={"content": [{"type": "text", "text": self.llm_reply}]})

        return httpx.Response(404, text=f"không giả lập {host}{path}")


def simulated_service(root: Path, clock: Clock, world: SimulatedWorld, *, use_llm: bool = False,
                      actions: ActionsConfig | None = None, actions_enabled: bool = False,
                      baseline: Baseline | None = None, database_url: str = "sqlite://",
                      git_push: bool = False) -> IncidentLens:
    """Dựng IncidentLens đầy đủ, nối với thế giới giả lập."""
    http = world.client()
    catalog = ServiceCatalog.from_yaml(CONFIG / "services.yaml")
    # Đặt IL_TEST_DATABASE_URL để chạy cùng bộ test trên PostgreSQL thật (mỗi lần dựng là một CSDL sạch)
    external = os.environ.get("IL_TEST_DATABASE_URL")
    if external and database_url == "sqlite://":
        store = Store(external)
        Base.metadata.drop_all(store._engine)
        Base.metadata.create_all(store._engine)
    else:
        store = Store(database_url)
    changes = GitHubChangeProvider("test-token", catalog, http)
    engine = EvidenceEngine(
        store=store, catalog=catalog, changes=changes, memory=IncidentMemory(store),
        signals=SignalConfig.from_yaml(CONFIG / "signals.yaml"),
        prometheus=PrometheusClient("http://prometheus.test", http),
        loki=LokiClient("http://loki.test", http, grafana_url="http://grafana.test"),
        synthesizer=Synthesizer(AnthropicLLM("test-key", "test-model", http)) if use_llm else None,
        public_url="http://incidentlens.test", clock=clock,
    )
    return IncidentLens(
        router=Router.from_yaml(CONFIG / "routing_rules.yaml"), store=store, catalog=catalog,
        notifier=SlackNotifier(http, bot_token="xoxb-test", channel="#incidents"),
        pager=PagerDutyPager("test-routing-key", http),
        archive=DigestArchive(root, git_push=git_push), changes=changes, investigator=engine,
        actions=ActionRunner(actions or ActionsConfig.from_yaml(CONFIG / "actions.yaml"), actions_enabled),
        baseline=baseline or Baseline(), clock=clock,
    )


def make_alert(name: str = "HighLatency", service: str = "auth-service", severity: str = "critical",
               status: str = "firing", fp: str | None = None, starts_at: datetime | None = None,
               ends_at: datetime | None = None, summary: str | None = None, **labels: str) -> Alert:
    return Alert(
        fingerprint=fp or f"{service}-{name}",
        name=name,
        status=status,
        labels={"alertname": name, "service": service, "severity": severity, **labels},
        annotations={"summary": summary or f"{name} on {service}"},
        starts_at=starts_at or datetime(2026, 11, 12, 8, 0, tzinfo=timezone.utc),
        ends_at=ends_at,
    )
