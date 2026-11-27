import logging
import re

import pytest

from conftest import START
from incidentlens.catalog import ServiceCatalog, ServiceInfo
from incidentlens.investigation.engine import render_service_query
from incidentlens.investigation.signals import Signal, SignalConfig, compare, fmt
from incidentlens.models import InvestigationTarget
from incidentlens.testing import CONFIG, SimulatedWorld, simulated_service, validate_promql_strings


def unquote_promql_string(literal_body: str) -> str:
    validate_promql_strings(f'"{literal_body}"')
    return bytes(literal_body, "utf-8").decode("unicode_escape")


def sig(**kw):
    return Signal(name="s", title="S", query="q", **kw)


def test_increase_detected():
    a = compare(sig(min_ratio=2, min_abs=0.01), [0.002] * 10, [0.05] * 5)
    assert a and round(a.ratio) == 25


def test_small_change_ignored():
    assert compare(sig(min_ratio=2), [0.30] * 10, [0.32] * 5) is None


def test_big_ratio_but_tiny_absolute_ignored():
    assert compare(sig(min_ratio=2, min_abs=0.01), [0.0001] * 10, [0.001] * 5) is None


def test_appears_from_zero_requires_measured_baseline():
    assert compare(sig(min_abs=1), [0.0] * 10, [3.0] * 5) is not None
    assert compare(sig(min_abs=1), [], [3.0] * 5) is None  # Missing baseline must not count as 0


def test_no_current_data_means_no_claim():
    assert compare(sig(), [1.0] * 10, []) is None


def test_decrease_direction():
    drop = sig(direction="down", min_ratio=2, min_abs=10)
    assert compare(drop, [100.0] * 10, [20.0] * 5) is not None
    assert compare(drop, [100.0] * 10, [90.0] * 5) is None
    assert compare(drop, [], [20.0] * 5) is None


def test_format_units():
    assert fmt(0.044, "ratio") == "4.4%"
    assert fmt(900 * 2**20, "bytes") == "900 MB"
    assert fmt(0.45, "s") == "450ms"
    assert fmt(2.5, "s") == "2.5s"


def test_shipped_config_is_valid_and_pod_queries_do_not_match_other_services():
    cfg = SignalConfig.from_yaml(CONFIG / "signals.yaml")
    assert {s.name for s in cfg.signals} >= {"error_rate", "latency_p95", "memory"}
    assert all("{service}" in s.query for s in cfg.signals)
    assert cfg.logs and "{service}" in cfg.logs.query

    pod_signals = [s for s in cfg.signals if "pod=~" in s.query]
    assert {s.name for s in pod_signals} == {"memory", "cpu", "restarts"}
    for s in pod_signals:
        rendered = render_service_query(s.query, "auth")
        match = re.search(r'pod=~"([^"]+)"', rendered)
        assert match is not None
        pattern = re.compile(match.group(1))
        for own_pod in ("auth-7d9f8b6c5-x2k4q", "auth-64b8d97f5c-abc12", "auth-0", "auth-12"):
            assert pattern.fullmatch(own_pod), own_pod
        for other_service_pod in (
            "auth-service-7d9f8b6c5-x2k4q",
            "auth-worker-7d9f8b6c5-x2k4q",
            "auth-canary-64b8d97f5c-abc12",
            "auth-db-0",
            "auth-proxy",
        ):
            assert not pattern.fullmatch(other_service_pod), other_service_pod

        dotted_query = render_service_query(s.query, "svc.v2")
        validate_promql_strings(dotted_query)
        dotted = re.search(r'pod=~"((?:\\.|[^"\\])*)"', dotted_query)
        assert dotted is not None
        assert r"svc\\.v2-" in dotted.group(1)
        unquoted_regex = unquote_promql_string(dotted.group(1))
        assert unquoted_regex.startswith(r"svc\.v2-")
        dotted_re = re.compile(unquoted_regex)
        assert dotted_re.fullmatch("svc.v2-7d9f8b6c5-x2k4q")
        assert not dotted_re.fullmatch("svcXv2-7d9f8b6c5-x2k4q")

    with pytest.raises(ValueError, match="Invalid Go string escape"):
        validate_promql_strings('max(container_memory_working_set_bytes{pod=~"svc\\.v2-0"})')


async def test_dotted_service_name_collects_pod_metrics_without_warnings(tmp_path, clock, caplog):
    world = SimulatedWorld(START, broken="svc.v2")
    lens = simulated_service(tmp_path, clock, world)
    lens.catalog = ServiceCatalog({"svc.v2": ServiceInfo(team="Platform Team", repo="your-org/svc.v2")})
    lens.investigator._catalog = lens.catalog

    tgt = InvestigationTarget(
        fingerprint="svc.v2-HighLatency",
        service="svc.v2",
        name="HighLatency",
        summary="p95 latency high",
        started_at=START,
    )
    with caplog.at_level(logging.WARNING):
        inv = await lens.investigator.investigate(tgt)

    assert not [r for r in caplog.records if "Signal" in r.message or "Failed to collect" in r.message]
    metrics = [e.description for e in inv.evidence if e.kind == "metric"]
    assert any(m.startswith("Memory usage: 200 MB") for m in metrics)
