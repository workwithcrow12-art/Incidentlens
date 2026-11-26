"""Gọi on-call qua PagerDuty Events API v2. Không có routing key → dry-run."""

from __future__ import annotations

import logging
from typing import Protocol

import httpx

log = logging.getLogger(__name__)


class Pager(Protocol):
    async def trigger(self, dedup_key: str, summary: str, source: str,
                      details: dict | None = None, link: str | None = None) -> bool: ...

    async def resolve(self, dedup_key: str) -> bool: ...


class PagerDutyPager:
    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str | None, client: httpx.AsyncClient) -> None:
        self._key = routing_key
        self._client = client

    async def _send(self, body: dict) -> bool:
        if not self._key:
            log.warning("[dry-run PagerDuty] %s", body)
            return False
        try:
            resp = await self._client.post(self.EVENTS_URL, json={"routing_key": self._key, **body})
            resp.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            log.error("Gửi PagerDuty thất bại: %s", exc)
            return False

    async def trigger(self, dedup_key: str, summary: str, source: str,
                      details: dict | None = None, link: str | None = None) -> bool:
        body: dict = {
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {"summary": summary[:1024], "source": source, "severity": "critical",
                        "custom_details": details or {}},
        }
        if link:
            body["links"] = [{"href": link, "text": "Nguồn cảnh báo"}]
        return await self._send(body)

    async def resolve(self, dedup_key: str) -> bool:
        return await self._send({"event_action": "resolve", "dedup_key": dedup_key})
