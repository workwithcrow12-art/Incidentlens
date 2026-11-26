from datetime import timedelta

from pydantic import ValidationError
import pytest

from incidentlens.models import AlertRecord, Severity
from incidentlens.routing.rules import EscalationPolicy, Router, RoutingConfig, Rule
from incidentlens.testing import make_alert


def test_critical_label_goes_to_critical(router):
    assert router.classify(make_alert(severity="critical")).severity is Severity.CRITICAL


def test_warning_goes_to_digest(router):
    assert router.classify(make_alert(severity="warning")).severity is Severity.ACTION


def test_regex_rule(router):
    routed = router.classify(make_alert(name="SLOAvailabilityBurnRateFast", severity="warning"))
    assert routed.severity is Severity.CRITICAL
    assert routed.rule == "slo-burn"


def test_security_category_is_critical(router):
    assert router.classify(make_alert(severity="info", category="security")).severity is Severity.CRITICAL


def test_unknown_falls_back_to_default(router):
    routed = router.classify(make_alert(severity="whatever"))
    assert routed.severity is Severity.INFO
    assert routed.rule == "default"


def test_invalid_regex_rejected():
    with pytest.raises(ValidationError):
        Rule(name="bad", severity="critical", match_re={"alertname": "("})


def _record(clock, minutes_ago, **kw):
    base = dict(
        fingerprint="x",
        name="DiskSpaceLow",
        service="db",
        severity=Severity.ACTION,
        status="firing",
        summary="s",
        first_seen=clock.now - timedelta(minutes=minutes_ago),
        last_seen=clock.now,
        receive_count=1,
    )
    base.update(kw)
    return AlertRecord(**base)


def test_escalation_after_max_pending(router, clock):
    assert router.escalation_reason(_record(clock, 239), clock.now) is None
    assert "240 minutes" in router.escalation_reason(_record(clock, 240), clock.now)


def test_no_escalation_when_resolved_or_already_escalated(router, clock):
    assert router.escalation_reason(_record(clock, 500, status="resolved"), clock.now) is None
    assert router.escalation_reason(_record(clock, 500, escalated=True), clock.now) is None
    assert router.escalation_reason(_record(clock, 500, severity=Severity.INFO), clock.now) is None


def test_escalation_after_too_many_repeats(clock):
    router = Router(RoutingConfig(escalation=EscalationPolicy(max_pending_minutes=None, max_receive_count=5)))
    assert router.escalation_reason(_record(clock, 999, receive_count=4), clock.now) is None
    assert "5 times" in router.escalation_reason(_record(clock, 1, receive_count=5), clock.now)
