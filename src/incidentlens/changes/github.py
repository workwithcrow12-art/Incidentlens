"""Change correlation: fetch recent deployments from the GitHub Deployments API."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Protocol

import httpx

from incidentlens.catalog import ServiceCatalog
from incidentlens.models import Change

log = logging.getLogger(__name__)


class ChangeProvider(Protocol):
    async def recent_changes(self, service: str, since: datetime) -> list[Change]: ...


class NoChanges:
    async def recent_changes(self, service: str, since: datetime) -> list[Change]:
        return []


class GitHubChangeProvider:
    API = "https://api.github.com"

    def __init__(
        self,
        token: str,
        catalog: ServiceCatalog,
        client: httpx.AsyncClient,
        *,
        per_page: int = 100,
        max_pages: int = 5,
    ) -> None:
        self._token = token
        self._catalog = catalog
        self._client = client
        self._per_page = per_page
        self._max_pages = max_pages

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/vnd.github+json"}

    async def _deployment_succeeded(self, repo: str, deployment_id: int | str) -> bool:
        resp = await self._client.get(
            f"{self.API}/repos/{repo}/deployments/{deployment_id}/statuses",
            params={"per_page": 100},
            headers=self._headers(),
        )
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, list):
            return False
        return next((s.get("state") for s in body if s.get("state") != "inactive"), None) == "success"

    async def recent_changes(self, service: str, since: datetime) -> list[Change]:
        info = self._catalog.get(service)
        repo = info.repo
        if not repo:
            return []
        env = info.environment
        candidates: list[tuple[datetime, dict[str, Any]]] = []
        try:
            for page in range(1, self._max_pages + 1):
                resp = await self._client.get(
                    f"{self.API}/repos/{repo}/deployments",
                    params={"environment": env, "per_page": self._per_page, "page": page},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                batch = resp.json()
                if not isinstance(batch, list) or not batch:
                    break
                reached_cutoff = False
                for d in batch:
                    created = datetime.fromisoformat(d["created_at"].replace("Z", "+00:00"))
                    if created < since:
                        reached_cutoff = True
                        continue
                    if (d.get("environment") or "").lower() != env.lower():
                        continue
                    if d.get("id") is None:
                        continue
                    candidates.append((created, d))
                if reached_cutoff or len(batch) < self._per_page:
                    break

            sem = asyncio.Semaphore(10)

            async def verify(item: tuple[datetime, dict[str, Any]]) -> Change | None:
                created, d = item
                async with sem:
                    if not await self._deployment_succeeded(repo, d["id"]):
                        return None
                sha = d.get("sha", "")
                return Change(
                    service=service,
                    kind="deploy",
                    ref=sha[:7],
                    author=(d.get("creator") or {}).get("login"),
                    created_at=created,
                    url=f"https://github.com/{repo}/commit/{sha}" if sha else None,
                )

            verified = await asyncio.gather(*(verify(item) for item in candidates))
        except httpx.HTTPError as exc:
            # Missing deployment data must never break a digest or investigation.
            log.warning("Failed to fetch deployments for %s: %s", repo, exc)
            return []

        changes = [c for c in verified if c is not None]
        return sorted(changes, key=lambda c: c.created_at, reverse=True)
