"""On-call paging via PagerDuty Events API v2. Unconfigured routing key enters dry-run state."""

from __future__ import annotations

import logging
from typing import Any, Protocol

import httpx

from incidentlens.models import DeliveryStatus

log = logging.getLogger(__name__)


class Pager(Protocol):
    async def trigger(
        self,
        dedup_key: str,
        summary: str,
        source: str,
        details: dict[str, Any] | None = None,
        link: str | None = None,
    ) -> DeliveryStatus | bool: ...

    async def resolve(self, dedup_key: str) -> DeliveryStatus | bool: ...


class PagerDutyPager:
    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str | None, client: httpx.AsyncClient) -> None:
        self._key = routing_key
        self._client = client

    @property
    def configured(self) -> bool:
        return bool(self._key)

    async def _send(self, body: dict[str, Any]) -> DeliveryStatus:
        if not self._key:
            log.info("[dry-run PagerDuty] %s", body)
            return DeliveryStatus.NOT_CONFIGURED
        try:
            resp = await self._client.post(self.EVENTS_URL, json={"routing_key": self._key, **body})
            resp.raise_for_status()
            return DeliveryStatus.SENT
        except httpx.HTTPError as exc:
            log.error("PagerDuty delivery failed: %s", exc)
            return DeliveryStatus.FAILED

    async def trigger(
        self,
        dedup_key: str,
        summary: str,
        source: str,
        details: dict[str, Any] | None = None,
        link: str | None = None,
    ) -> DeliveryStatus:
        body: dict[str, Any] = {
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": summary[:1024],
                "source": source,
                "severity": "critical",
                "custom_details": details or {},
            },
        }
        if link:
            body["links"] = [{"href": link, "text": "Alert source"}]
        return await self._send(body)

    async def resolve(self, dedup_key: str) -> DeliveryStatus:
        return await self._send({"event_action": "resolve", "dedup_key": dedup_key})
