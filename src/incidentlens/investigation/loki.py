"""Read-only Loki log client and log pattern clustering."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import re
from urllib.parse import urlencode

import httpx

from incidentlens.redact import redact


_STREAM_RE = re.compile(r'^\s*(\{(?:[^}"`]|"(?:\\.|[^"\\])*"|`[^`]*`)*\})')
_SERVICE_RE = re.compile(r'\bservice\s*=~?\s*(?:"(?:\\.|[^"\\])*"|`[^`]*`)')


def _ns(dt: datetime) -> int:
    return int(dt.timestamp() * 1_000_000_000)


def _unfiltered_selector(query: str) -> str | None:
    s = query.strip()
    if not (stream := _STREAM_RE.match(s)):
        return None
    selector = stream.group(1)
    svc = _SERVICE_RE.search(selector)
    base = f"{{{svc.group(0)}}}" if svc else selector
    return base if base != s else None


class LokiClient:
    def __init__(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        grafana_url: str | None = None,
        grafana_datasource: str = "Loki",
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client = client
        self._grafana = grafana_url.rstrip("/") if grafana_url else None
        self._datasource = grafana_datasource

    async def _raw_count(self, query: str, at: datetime, window_seconds: int) -> int | None:
        resp = await self._client.get(
            f"{self._base}/loki/api/v1/query",
            params={"query": f"sum(count_over_time({query}[{window_seconds}s]))", "time": _ns(at)},
        )
        resp.raise_for_status()
        body = resp.json()
        if "status" in body and body["status"] != "success":
            raise RuntimeError(f"Loki error: {body.get('error', 'unknown')}")
        result = body.get("data", {}).get("result", [])
        return int(float(result[0]["value"][1])) if result else None

    async def count(self, query: str, at: datetime, window_seconds: int) -> int | None:
        """Return matching log count, 0 when the service logged non-matching lines, or None if absent."""
        matched = await self._raw_count(query, at, window_seconds)
        if matched is not None:
            return matched
        # Loki returns an empty vector when a filter matches zero lines (grafana/loki#6946);
        # check the unfiltered stream selector to distinguish zero errors from missing logs.
        unfiltered = _unfiltered_selector(query)
        if unfiltered is None:
            return None
        total = await self._raw_count(unfiltered, at, window_seconds)
        return 0 if total and total > 0 else None

    async def lines(self, query: str, start: datetime, end: datetime, limit: int = 100) -> list[str]:
        resp = await self._client.get(
            f"{self._base}/loki/api/v1/query_range",
            params={"query": query, "start": _ns(start), "end": _ns(end), "limit": limit, "direction": "backward"},
        )
        resp.raise_for_status()
        out: list[str] = []
        for stream in resp.json().get("data", {}).get("result", []):
            out.extend(line for _, line in stream.get("values", []))
        return out

    def explore_url(self, query: str, start: datetime, end: datetime) -> str:
        if self._grafana:
            left = {
                "datasource": self._datasource,
                "queries": [{"refId": "A", "expr": query}],
                "range": {"from": str(_ns(start) // 1_000_000), "to": str(_ns(end) // 1_000_000)},
            }
            return f"{self._grafana}/explore?{urlencode({'left': json.dumps(left)})}"
        params = {"query": query, "start": _ns(start), "end": _ns(end), "limit": 100}
        return f"{self._base}/loki/api/v1/query_range?{urlencode(params)}"


_NOISE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "#id"),
    (re.compile(r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?"), "#time"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}\b", re.I), "#id"),
    (re.compile(r"\d+(?:\.\d+)?"), "#"),
    (re.compile(r"\s+"), " "),
]


def top_patterns(lines: list[str], limit: int = 3, width: int = 120) -> list[tuple[str, int]]:
    """Cluster similar log lines after redacting sensitive values and normalizing IDs/timestamps."""
    counter: Counter[str] = Counter()
    for line in lines:
        text = redact(line)
        for pattern, replacement in _NOISE:
            text = pattern.sub(replacement, text)
        text = text.strip()[:width]
        if text:
            counter[text] += 1
    return counter.most_common(limit)
