"""Slack delivery via chat.postMessage (bot token + channel) or Incoming Webhook.

Unconfigured credentials log messages locally with DeliveryStatus.NOT_CONFIGURED.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Any, Protocol

import httpx

from incidentlens.models import DeliveryStatus

log = logging.getLogger(__name__)


class Notifier(Protocol):
    async def send(self, text: str, blocks: list[dict[str, Any]] | None = None) -> DeliveryStatus | bool: ...

    async def respond(self, response_url: str | None, text: str) -> bool: ...


class SlackNotifier:
    POST_MESSAGE = "https://slack.com/api/chat.postMessage"

    def __init__(
        self,
        client: httpx.AsyncClient,
        webhook_url: str | None = None,
        bot_token: str | None = None,
        channel: str | None = None,
    ) -> None:
        self._client = client
        self._webhook = webhook_url
        self._token = bot_token
        self._channel = channel

    @property
    def configured(self) -> bool:
        return bool((self._token and self._channel) or self._webhook)

    async def send(self, text: str, blocks: list[dict[str, Any]] | None = None) -> DeliveryStatus:
        if not self.configured:
            log.info("[dry-run Slack] %s", text)
            return DeliveryStatus.NOT_CONFIGURED
        body: dict[str, Any] = {"text": text}
        if blocks:
            body["blocks"] = blocks
        try:
            if self._token and self._channel:
                resp = await self._client.post(
                    self.POST_MESSAGE,
                    json={"channel": self._channel, **body},
                    headers={"Authorization": f"Bearer {self._token}"},
                )
                resp.raise_for_status()
                data = resp.json()
                if not data.get("ok"):
                    log.error("Slack rejected message: %s", data.get("error"))
                    return DeliveryStatus.FAILED
                return DeliveryStatus.SENT
            if self._webhook:
                resp = await self._client.post(self._webhook, json=body)
                resp.raise_for_status()
                return DeliveryStatus.SENT
        except (httpx.HTTPError, ValueError) as exc:
            log.error("Slack delivery failed: %s", exc)
            return DeliveryStatus.FAILED
        return DeliveryStatus.NOT_CONFIGURED

    async def respond(self, response_url: str | None, text: str) -> bool:
        """Reply to an interactive Slack button click. Only accepts official Slack hook URLs."""
        if not response_url or not response_url.startswith("https://hooks.slack.com/"):
            log.info("[interaction reply] %s", text)
            return False
        try:
            resp = await self._client.post(response_url, json={"text": text, "replace_original": False})
            resp.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            log.error("Slack interaction reply failed: %s", exc)
            return False


def verify_slack_signature(
    secret: str,
    timestamp: str | None,
    body: bytes,
    signature: str | None,
    now: float | None = None,
    tolerance: int = 300,
) -> bool:
    """Verify Slack request authenticity (HMAC-SHA256) and timestamp freshness."""
    if not timestamp or not signature:
        return False
    try:
        sent = int(timestamp)
    except ValueError:
        return False
    if abs((now if now is not None else time.time()) - sent) > tolerance:
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
