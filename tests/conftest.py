from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from incidentlens.routing.rules import Router
from incidentlens.testing import CONFIG, Clock, SimulatedWorld, simulated_service

START = datetime(2026, 11, 12, 2, 14, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def dispose_test_databases(monkeypatch):
    from incidentlens.store import Store

    stores = []
    original = Store.__init__

    def tracked_init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        stores.append(self)

    monkeypatch.setattr(Store, "__init__", tracked_init)
    yield
    for store in stores:
        store._engine.dispose()


@pytest.fixture
def clock() -> Clock:
    return Clock(START + timedelta(minutes=2))


@pytest.fixture
def world() -> SimulatedWorld:
    return SimulatedWorld(START)


@pytest.fixture
def router() -> Router:
    return Router.from_yaml(CONFIG / "routing_rules.yaml")


@pytest.fixture
def lens(tmp_path, clock, world):
    return simulated_service(tmp_path / "archive", clock, world)


def texts(world: SimulatedWorld) -> list[str]:
    return [m["text"] for m in world.slack]
