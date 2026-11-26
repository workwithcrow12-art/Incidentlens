"""Change correlation: fetch recent deployments from the GitHub Deployments API."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Protocol

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

    def __init__(self, token: str, catalog: ServiceCatalog, client: httpx.AsyncClient) -> None:
        self._token = token
        self._catalog = catalog
        self._client = client

    async def recent_changes(self, service: str, since: datetime) -> list[Change]:
        repo = self._catalog.get(service).repo
        if not repo:
            return []
        try:
            resp = await self._client.get(
                f"{self.API}/repos/{repo}/deployments",
                params={"per_page": 20},
                headers={"Authorization": f"Bearer {self._token}", "Accept": "application/vnd.github+json"},
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            # Missing deployment data must never break a digest or investigation.
            log.warning("Failed to fetch deployments for %s: %s", repo, exc)
            return []

        changes: list[Change] = []
        for d in resp.json():
            created = datetime.fromisoformat(d["created_at"].replace("Z", "+00:00"))
            if created < since:
                continue
            sha = d.get("sha", "")
            changes.append(
                Change(
                    service=service,
                    kind="deploy",
                    ref=sha[:7],
                    author=(d.get("creator") or {}).get("login"),
                    created_at=created,
                    url=f"https://github.com/{repo}/commit/{sha}" if sha else None,
                )
            )
        return sorted(changes, key=lambda c: c.created_at, reverse=True)
