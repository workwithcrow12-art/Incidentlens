"""FastAPI web application.

Run locally: uvicorn incidentlens.app:create_app --factory --port 8000
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import logging
from typing import Any
from urllib.parse import parse_qs

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
import httpx
from pydantic import BaseModel

from incidentlens.actions.runner import ActionRunner, ActionsConfig
from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import ChangeProvider, GitHubChangeProvider, NoChanges
from incidentlens.config import Settings
from incidentlens.ingest.alertmanager import AlertmanagerPayload, to_alerts
from incidentlens.investigation.engine import EvidenceEngine
from incidentlens.investigation.llm import AnthropicLLM, OpenAICompatibleLLM, Synthesizer
from incidentlens.investigation.loki import LokiClient
from incidentlens.investigation.prometheus import PrometheusClient
from incidentlens.investigation.signals import SignalConfig
from incidentlens.memory.similarity import IncidentMemory
from incidentlens.models import as_utc
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
        raise ValueError("IL_LLM_MODEL is required when LLM is enabled")
    if settings.llm_provider == "anthropic":
        if not settings.llm_api_key:
            raise ValueError("IL_LLM_API_KEY is required for provider anthropic")
        return Synthesizer(AnthropicLLM(settings.llm_api_key, settings.llm_model, http))
    if not settings.llm_base_url:
        raise ValueError("IL_LLM_BASE_URL is required for provider openai-compatible")
    return Synthesizer(OpenAICompatibleLLM(settings.llm_base_url, settings.llm_model, http, settings.llm_api_key))


def build_service(settings: Settings, http: httpx.AsyncClient) -> IncidentLens:
    catalog = ServiceCatalog.from_yaml(settings.services_path)
    store = Store(settings.database_url)
    changes: ChangeProvider = (
        GitHubChangeProvider(settings.github_token, catalog, http) if settings.github_token else NoChanges()
    )
    investigator = EvidenceEngine(
        store=store,
        catalog=catalog,
        changes=changes,
        memory=IncidentMemory(store),
        signals=SignalConfig.from_yaml(settings.signals_path),
        prometheus=(
            PrometheusClient(settings.prometheus_url, http, settings.prometheus_bearer_token)
            if settings.prometheus_url
            else None
        ),
        loki=(
            LokiClient(settings.loki_url, http, settings.grafana_url, settings.grafana_loki_datasource)
            if settings.loki_url
            else None
        ),
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


async def _every(
    seconds: float,
    job: Callable[[], Awaitable[object]],
    *,
    store: Store | None = None,
    name: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> None:
    now_fn = clock or (lambda: datetime.now(timezone.utc))
    delay = 0.0
    if store is not None and name is not None:
        last = store.kv_get(f"schedule:{name}")
        if last is not None:
            elapsed = (now_fn() - as_utc(datetime.fromisoformat(last))).total_seconds()
            delay = max(0.0, seconds - elapsed)
    if delay > 0:
        await asyncio.sleep(delay)
    while True:
        try:
            await job()
            if store is not None and name is not None:
                store.kv_set(f"schedule:{name}", now_fn().isoformat())
        except Exception:
            log.exception("Scheduled background job failed")
        await asyncio.sleep(seconds)


class ResolutionBody(BaseModel):
    root_cause: str | None = None
    fix: str | None = None


class FeedbackBody(BaseModel):
    choice: int
    user: str


def create_app(settings: Settings | None = None, service: IncidentLens | None = None) -> FastAPI:
    cfg = settings or Settings()
    logging.basicConfig(level=logging.INFO)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        http: httpx.AsyncClient | None = None
        svc_instance = service
        if svc_instance is None:
            http = httpx.AsyncClient(timeout=10)
            svc_instance = build_service(cfg, http)
        app.state.service = svc_instance

        if not svc_instance._pager_configured():
            log.warning("PagerDuty not configured (IL_PAGERDUTY_ROUTING_KEY is empty); nobody will be paged")
        if not (cfg.webhook_token or "").strip() and not cfg.allow_unauthenticated:
            log.warning("IL_WEBHOOK_TOKEN is not configured; protected API endpoints will reject requests")

        tasks: list[asyncio.Task[None]] = []
        if cfg.enable_scheduler:
            tasks = [
                asyncio.create_task(
                    _every(
                        cfg.escalation_check_seconds,
                        svc_instance.check_escalations,
                        store=svc_instance.store,
                        name="escalations",
                        clock=svc_instance._clock,
                    )
                ),
                asyncio.create_task(
                    _every(
                        cfg.digest_interval_minutes * 60,
                        svc_instance.run_digest,
                        store=svc_instance.store,
                        name="digest",
                        clock=svc_instance._clock,
                    )
                ),
                asyncio.create_task(
                    _every(
                        cfg.maintenance_interval_hours * 3600,
                        svc_instance.run_maintenance,
                        store=svc_instance.store,
                        name="maintenance",
                        clock=svc_instance._clock,
                    )
                ),
            ]
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await svc_instance.drain()
            if http:
                await http.aclose()

    def require_token(request: Request) -> None:
        expected = (cfg.webhook_token or "").strip()
        if not expected:
            if cfg.allow_unauthenticated:
                return
            raise HTTPException(status_code=401, detail="IL_WEBHOOK_TOKEN is not configured")
        given = request.headers.get("authorization", "")
        if not hmac.compare_digest(given.encode(), f"Bearer {expected}".encode()):
            raise HTTPException(status_code=401, detail="Invalid bearer token")

    def svc(request: Request) -> IncidentLens:
        instance: IncidentLens = request.app.state.service
        return instance

    app = FastAPI(title="IncidentLens", version="1.0.0", lifespan=lifespan)
    auth = [Depends(require_token)]

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ----- Alert ingestion and scheduled jobs -----

    @app.post("/webhooks/alertmanager", dependencies=auth)
    async def alertmanager_webhook(payload: AlertmanagerPayload, request: Request) -> dict[str, int]:
        return await svc(request).handle_alerts(to_alerts(payload))

    @app.post("/digest/run", dependencies=auth)
    async def run_digest(request: Request) -> dict[str, str | None]:
        path = await svc(request).run_digest()
        return {"path": str(path) if path else None}

    @app.post("/escalations/check", dependencies=auth)
    async def check_escalations(request: Request) -> dict[str, list[str]]:
        return {"escalated": await svc(request).check_escalations()}

    @app.post("/maintenance/run", dependencies=auth)
    async def run_maintenance(request: Request) -> dict[str, Any]:
        return await svc(request).run_maintenance()

    # ----- Queries -----

    @app.get("/alerts/{fingerprint}", dependencies=auth)
    async def get_alert(fingerprint: str, request: Request) -> dict[str, Any]:
        record = svc(request).store.get(fingerprint)
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return record.model_dump(mode="json")

    @app.get("/incidents", dependencies=auth)
    async def list_incidents(request: Request, limit: int = 50) -> list[dict[str, Any]]:
        return [
            {**i.model_dump(mode="json"), "code": i.code, "duration_minutes": i.duration_minutes}
            for i in svc(request).store.list_incidents(min(max(limit, 1), 500))
        ]

    @app.get("/incidents/{incident_id}", dependencies=auth)
    async def get_incident(incident_id: int, request: Request) -> dict[str, Any]:
        store = svc(request).store
        incident = store.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {
            **incident.model_dump(mode="json"),
            "code": incident.code,
            "duration_minutes": incident.duration_minutes,
            "investigations": [r.model_dump(mode="json") for r in store.investigations_for_incident(incident_id)],
            "actions": [a.model_dump(mode="json") for a in store.actions_for_incident(incident_id)],
        }

    @app.get("/incidents/{incident_id}/postmortem", dependencies=auth, response_class=PlainTextResponse)
    async def postmortem(incident_id: int, request: Request) -> PlainTextResponse:
        try:
            markdown = svc(request).read_postmortem(incident_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return PlainTextResponse(markdown, media_type="text/markdown; charset=utf-8")

    # ----- Human resolution and feedback -----

    @app.post("/incidents/{incident_id}/resolution", dependencies=auth)
    async def set_resolution(incident_id: int, body: ResolutionBody, request: Request) -> dict[str, Any]:
        incident = svc(request).set_resolution(incident_id, body.root_cause, body.fix)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident.model_dump(mode="json")

    @app.post("/investigations/{investigation_id}/feedback", dependencies=auth)
    async def feedback(investigation_id: int, body: FeedbackBody, request: Request) -> dict[str, str]:
        try:
            return {"message": svc(request).record_feedback(investigation_id, body.choice, body.user)}
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/reports/roi", dependencies=auth)
    async def roi(request: Request, month: str | None = None) -> dict[str, str]:
        try:
            start = (
                datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
                if month
                else datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="month must match YYYY-MM") from exc
        path, markdown = await svc(request).publish_roi(start, announce=False)
        return {"path": str(path), "markdown": markdown}

    # ----- Slack interactive buttons -----

    @app.post("/slack/interactions")
    async def slack_interactions(request: Request, background: BackgroundTasks) -> Response:
        """Sole entrypoint for one-click actions; requires a valid Slack HMAC signature."""
        secret = cfg.slack_signing_secret
        if not secret:
            raise HTTPException(status_code=503, detail="IL_SLACK_SIGNING_SECRET is not configured")
        body = await request.body()
        timestamp = request.headers.get("x-slack-request-timestamp", "")
        if not verify_slack_signature(secret, timestamp, body, request.headers.get("x-slack-signature")):
            raise HTTPException(status_code=401, detail="Invalid Slack signature")
        try:
            payload: dict[str, Any] = json.loads(parse_qs(body.decode())["payload"][0])
            action = payload["actions"][0]
            user = payload["user"]
            args = (
                str(action["action_id"]),
                str(action.get("value", "")),
                str(user["id"]),
                str(user.get("username") or user.get("name") or user["id"]),
                payload.get("response_url"),
            )
        except (KeyError, IndexError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Invalid interaction payload") from exc
        if payload.get("type") == "block_actions":
            svc_instance = svc(request)
            request_id = hashlib.sha256(b"v0:" + timestamp.encode() + b":" + body).hexdigest()
            if not svc_instance.store.claim_interaction(request_id, datetime.now(timezone.utc)):
                return Response(status_code=200)
            # Slack requires an HTTP response within 3s, so execution continues in the background.
            background.add_task(svc_instance.handle_interaction, *args)
        return Response(status_code=200)

    return app
