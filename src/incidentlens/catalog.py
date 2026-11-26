"""Service catalog: owning team, source repository, upstream dependencies, and runbook link."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ServiceInfo(BaseModel):
    team: str = "Unassigned"
    repo: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    runbook: str | None = None


class ServiceCatalog:
    def __init__(self, services: dict[str, ServiceInfo] | None = None) -> None:
        self._services = services or {}

    @classmethod
    def from_yaml(cls, path: Path) -> ServiceCatalog:
        if not Path(path).exists():
            return cls()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        raw = data.get("services") or {}
        return cls({name: ServiceInfo.model_validate(info or {}) for name, info in raw.items()})

    def get(self, service: str) -> ServiceInfo:
        return self._services.get(service, ServiceInfo())
