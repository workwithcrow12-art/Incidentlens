import re

from incidentlens.investigation.engine import render_service_query
from incidentlens.investigation.signals import Signal, SignalConfig, compare, fmt
from incidentlens.testing import CONFIG


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

        dotted = re.search(r'pod=~"([^"]+)"', render_service_query(s.query, "svc.v2"))
        assert dotted is not None
        dotted_re = re.compile(dotted.group(1))
        assert dotted_re.fullmatch("svc.v2-7d9f8b6c5-x2k4q")
        assert not dotted_re.fullmatch("svcXv2-7d9f8b6c5-x2k4q")
