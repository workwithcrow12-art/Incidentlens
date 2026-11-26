"""Gửi Slack. Hỗ trợ hai cách:

- Bot token + kênh (khuyên dùng): gửi được thẻ có nút bấm qua chat.postMessage.
- Incoming Webhook: đơn giản hơn; nút bấm chỉ hoạt động nếu webhook thuộc một Slack App
  đã bật Interactivity trỏ về /slack/interactions.

Không cấu hình gì → chỉ ghi log (dry-run).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Protocol

import httpx

log = logging.getLogger(__name__)


class Notifier(Protocol):
    async def send(self, text: str, blocks: list[dict] | None = None) -> bool: ...

    async def respond(self, response_url: str | None, text: str) -> bool: ...


class SlackNotifier:
    POST_MESSAGE = "https://slack.com/api/chat.postMessage"

    def __init__(self, client: httpx.AsyncClient, webhook_url: str | None = None,
                 bot_token: str | None = None, channel: str | None = None) -> None:
        self._client = client
        self._webhook = webhook_url
        self._token = bot_token
        self._channel = channel

    async def send(self, text: str, blocks: list[dict] | None = None) -> bool:
        body: dict = {"text": text}
        if blocks:
            body["blocks"] = blocks
        try:
            if self._token and self._channel:
                resp = await self._client.post(
                    self.POST_MESSAGE, json={"channel": self._channel, **body},
                    headers={"Authorization": f"Bearer {self._token}"})
                resp.raise_for_status()
                data = resp.json()
                if not data.get("ok"):
                    log.error("Slack từ chối tin nhắn: %s", data.get("error"))
                    return False
                return True
            if self._webhook:
                resp = await self._client.post(self._webhook, json=body)
                resp.raise_for_status()
                return True
        except (httpx.HTTPError, ValueError) as exc:
            log.error("Gửi Slack thất bại: %s", exc)
            return False
        log.info("[dry-run Slack] %s", text)
        return False

    async def respond(self, response_url: str | None, text: str) -> bool:
        """Trả lời người vừa bấm nút. Chỉ chấp nhận địa chỉ của Slack."""
        if not response_url or not response_url.startswith("https://hooks.slack.com/"):
            log.info("[phản hồi tương tác] %s", text)
            return False
        try:
            resp = await self._client.post(response_url, json={"text": text, "replace_original": False})
            resp.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            log.error("Trả lời tương tác Slack thất bại: %s", exc)
            return False


def verify_slack_signature(secret: str, timestamp: str | None, body: bytes, signature: str | None,
                           now: float | None = None, tolerance: int = 300) -> bool:
    """Xác thực yêu cầu thật sự đến từ Slack (HMAC-SHA256) và không bị phát lại."""
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
