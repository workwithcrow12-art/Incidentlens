"""Đọc metric từ Prometheus (chỉ quyền đọc)."""

from __future__ import annotations

import math
from datetime import datetime
from urllib.parse import urlencode

import httpx


class PrometheusClient:
    def __init__(self, base_url: str, client: httpx.AsyncClient, bearer_token: str | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._client = client
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}

    async def query_range(self, query: str, start: datetime, end: datetime, step: int = 60) -> list[float]:
        """Trả về các giá trị hữu hạn trong khoảng thời gian (gộp mọi chuỗi số trả về)."""
        resp = await self._client.get(
            f"{self._base}/api/v1/query_range",
            params={"query": query, "start": start.timestamp(), "end": end.timestamp(), "step": step},
            headers=self._headers,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("status") != "success":
            raise RuntimeError(f"Prometheus báo lỗi: {body.get('error', 'không rõ')}")
        values = []
        for series in body.get("data", {}).get("result", []):
            for _, raw in series.get("values", []):
                value = float(raw)
                if math.isfinite(value):
                    values.append(value)
        return values

    def graph_url(self, query: str, end: datetime) -> str:
        params = {"g0.expr": query, "g0.tab": "0", "g0.range_input": "2h",
                  "g0.end_input": end.strftime("%Y-%m-%d %H:%M:%S")}
        return f"{self._base}/graph?{urlencode(params)}"
