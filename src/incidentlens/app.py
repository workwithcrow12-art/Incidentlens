"""Ứng dụng web FastAPI.

Chạy: uvicorn incidentlens.app:create_app --factory --port 8000
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from incidentlens.actions.runner import ActionRunner, ActionsConfig
from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import GitHubChangeProvider, NoChanges
from incidentlens.config import Settings
from incidentlens.ingest.alertmanager import AlertmanagerPayload, to_alerts
from incidentlens.investigation.engine import EvidenceEngine
from incidentlens.investigation.llm import AnthropicLLM, OpenAICompatibleLLM, Synthesizer
from incidentlens.investigation.loki import LokiClient
from incidentlens.investigation.prometheus import PrometheusClient
from incidentlens.investigation.signals import SignalConfig
from incidentlens.memory.similarity import IncidentMemory
from incidentlens.outputs.archive import DigestArchive
from incidentlens.outputs.pagerduty import PagerDutyPager
from incidentlens.outputs.slack import SlackNotifier, verify_slack_signature
from incidentlens.reports.roi import Baseline
from incidentlens.routing.rules import Router
from incidentlens.service import IncidentLens
from incidentlens.store import Store

log = logging.getLogger("incidentlens")


def build_synthesizer(settings: Settings, http: httpx.AsyncClient) -> Synthesizer | None:
    if settings.llm_provider == "none":
        return None
    if not settings.llm_model:
        raise ValueError("Cần đặt IL_LLM_MODEL khi bật LLM")
    if settings.llm_provider == "anthropic":
        if not settings.llm_api_key:
            raise ValueError("Cần đặt IL_LLM_API_KEY cho nhà cung cấp anthropic")
        return Synthesizer(AnthropicLLM(settings.llm_api_key, settings.llm_model, http))
    if not settings.llm_base_url:
        raise ValueError("Cần đặt IL_LLM_BASE_URL cho nhà cung cấp openai-compatible")
    return Synthesizer(OpenAICompatibleLLM(settings.llm_base_url, settings.llm_model, http, settings.llm_api_key))


def build_service(settings: Settings, http: httpx.AsyncClient) -> IncidentLens:
    catalog = ServiceCatalog.from_yaml(settings.services_path)
    store = Store(settings.database_url)
    changes = GitHubChangeProvider(settings.github_token, catalog, http) if settings.github_token else NoChanges()
    investigator = EvidenceEngine(
        store=store,
        catalog=catalog,
        changes=changes,
        memory=IncidentMemory(store),
        signals=SignalConfig.from_yaml(settings.signals_path),
        prometheus=(PrometheusClient(settings.prometheus_url, http, settings.prometheus_bearer_token)
                    if settings.prometheus_url else None),
        loki=(LokiClient(settings.loki_url, http, settings.grafana_url, settings.grafana_loki_datasource)
              if settings.loki_url else None),
        synthesizer=build_synthesizer(settings, http),
        public_url=settings.public_url,
    )
    return IncidentLens(
        router=Router.from_yaml(settings.rules_path),
        store=store,
        catalog=catalog,
        notifier=SlackNotifier(http, settings.slack_webhook_url, settings.slack_bot_token, settings.slack_channel),
        pager=PagerDutyPager(settings.pagerduty_routing_key, http),
        archive=DigestArchive(settings.digest_dir, settings.digest_git_push),
        changes=changes,
        investigator=investigator,
        actions=ActionRunner(ActionsConfig.from_yaml(settings.actions_path), settings.actions_enabled),
        baseline=Baseline.from_yaml(settings.baseline_path),
        change_lookback=timedelta(hours=settings.change_lookback_hours),
        investigation_timeout=settings.investigation_timeout_seconds,
        digest_investigation_limit=settings.digest_investigation_limit,
        retention=timedelta(days=settings.retention_days),
    )


async def _every(seconds: float, job: Callable[[], Awaitable[object]]) -> None:
    while True:
        await asyncio.sleep(seconds)
        try:
            await job()
        except Exception:
            log.exception("Tác vụ định kỳ thất bại")


class ResolutionBody(BaseModel):
    root_cause: str | None = None
    fix: str | None = None


class FeedbackBody(BaseModel):
    choice: int
    user: str


def create_app(settings: Settings | None = None, service: IncidentLens | None = None) -> FastAPI:
    settings = settings or Settings()
    logging.basicConfig(level=logging.INFO)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        http = None
        svc = service
        if svc is None:
            http = httpx.AsyncClient(timeout=10)
            svc = build_service(settings, http)
        app.state.service = svc

        tasks = []
        if settings.enable_scheduler:
            tasks = [
                asyncio.create_task(_every(settings.escalation_check_seconds, svc.check_escalations)),
                asyncio.create_task(_every(settings.digest_interval_minutes * 60, svc.run_digest)),
                asyncio.create_task(_every(settings.maintenance_interval_hours * 3600, svc.run_maintenance)),
            ]
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            await svc.drain()
            if http:
                await http.aclose()

    def require_token(request: Request) -> None:
        expected = settings.webhook_token
        if not expected:
            return
        given = request.headers.get("authorization", "")
        if not hmac.compare_digest(given.encode(), f"Bearer {expected}".encode()):
            raise HTTPException(status_code=401, detail="Token không hợp lệ")

    def svc(request: Request) -> IncidentLens:
        return request.app.state.service

    app = FastAPI(title="IncidentLens", version="1.0.0", lifespan=lifespan)
    auth = [Depends(require_token)]

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    # ----- Nhận cảnh báo và tác vụ định kỳ -----

    @app.post("/webhooks/alertmanager", dependencies=auth)
    async def alertmanager_webhook(payload: AlertmanagerPayload, request: Request) -> dict:
        return await svc(request).handle_alerts(to_alerts(payload))

    @app.post("/digest/run", dependencies=auth)
    async def run_digest(request: Request) -> dict:
        path = await svc(request).run_digest()
        return {"path": str(path) if path else None}

    @app.post("/escalations/check", dependencies=auth)
    async def check_escalations(request: Request) -> dict:
        return {"escalated": await svc(request).check_escalations()}

    @app.post("/maintenance/run", dependencies=auth)
    async def run_maintenance(request: Request) -> dict:
        return await svc(request).run_maintenance()

    # ----- Tra cứu -----

    @app.get("/alerts/{fingerprint}", dependencies=auth)
    async def get_alert(fingerprint: str, request: Request) -> dict:
        record = svc(request).store.get(fingerprint)
        if record is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy cảnh báo")
        return record.model_dump(mode="json")

    @app.get("/incidents", dependencies=auth)
    async def list_incidents(request: Request, limit: int = 50) -> list[dict]:
        return [{**i.model_dump(mode="json"), "code": i.code, "duration_minutes": i.duration_minutes}
                for i in svc(request).store.list_incidents(min(max(limit, 1), 500))]

    @app.get("/incidents/{incident_id}", dependencies=auth)
    async def get_incident(incident_id: int, request: Request) -> dict:
        store = svc(request).store
        incident = store.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy sự cố")
        return {
            **incident.model_dump(mode="json"), "code": incident.code,
            "duration_minutes": incident.duration_minutes,
            "investigations": [r.model_dump(mode="json") for r in store.investigations_for_incident(incident_id)],
            "actions": [a.model_dump(mode="json") for a in store.actions_for_incident(incident_id)],
        }

    @app.get("/incidents/{incident_id}/postmortem", dependencies=auth, response_class=PlainTextResponse)
    async def postmortem(incident_id: int, request: Request) -> PlainTextResponse:
        try:
            path = svc(request).write_postmortem(incident_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown; charset=utf-8")

    # ----- Ghi nhận từ con người -----

    @app.post("/incidents/{incident_id}/resolution", dependencies=auth)
    async def set_resolution(incident_id: int, body: ResolutionBody, request: Request) -> dict:
        incident = svc(request).store.set_resolution(incident_id, body.root_cause, body.fix)
        if incident is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy sự cố")
        return incident.model_dump(mode="json")

    @app.post("/investigations/{investigation_id}/feedback", dependencies=auth)
    async def feedback(investigation_id: int, body: FeedbackBody, request: Request) -> dict:
        try:
            return {"message": svc(request).record_feedback(investigation_id, body.choice, body.user)}
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/reports/roi", dependencies=auth)
    async def roi(request: Request, month: str | None = None) -> dict:
        try:
            start = (datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc) if month
                     else datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="month phải có dạng YYYY-MM") from exc
        path, markdown = await svc(request).publish_roi(start, announce=False)
        return {"path": str(path), "markdown": markdown}

    # ----- Nút bấm trên Slack -----

    @app.post("/slack/interactions")
    async def slack_interactions(request: Request, background: BackgroundTasks) -> Response:
        """Lối vào DUY NHẤT để chạy hành động. Bắt buộc có chữ ký hợp lệ của Slack."""
        secret = settings.slack_signing_secret
        if not secret:
            raise HTTPException(status_code=503, detail="Chưa cấu hình IL_SLACK_SIGNING_SECRET")
        body = await request.body()
        timestamp = request.headers.get("x-slack-request-timestamp", "")
        if not verify_slack_signature(secret, timestamp, body,
                                      request.headers.get("x-slack-signature")):
            raise HTTPException(status_code=401, detail="Chữ ký Slack không hợp lệ")
        try:
            payload = json.loads(parse_qs(body.decode())["payload"][0])
            action = payload["actions"][0]
            user = payload["user"]
            args = (action["action_id"], action.get("value", ""), user["id"],
                    user.get("username") or user.get("name") or user["id"], payload.get("response_url"))
        except (KeyError, IndexError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Payload không hợp lệ") from exc
        if payload.get("type") == "block_actions":
            service = svc(request)
            request_id = hashlib.sha256(b"v0:" + timestamp.encode() + b":" + body).hexdigest()
            if not service.store.claim_interaction(request_id, datetime.now(timezone.utc)):
                return Response(status_code=200)
            # Slack yêu cầu trả lời trong 3 giây nên việc thật chạy sau khi đã phản hồi
            background.add_task(service.handle_interaction, *args)
        return Response(status_code=200)

    return app
