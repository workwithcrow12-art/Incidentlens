"""Bộ máy điều tra: thu thập bằng chứng, suy luận bằng luật, và hàng rào an toàn cho LLM."""

import json
from datetime import timedelta

import pytest

from conftest import START
from incidentlens.investigation.base import confidence_for
from incidentlens.investigation.engine import Finding, rule_hypotheses
from incidentlens.investigation.llm import AnthropicLLM, Synthesizer
from incidentlens.models import AlertRecord, Evidence, Hypothesis, InvestigationTarget, Severity
from incidentlens.testing import SimulatedWorld, make_alert, simulated_service


def target(service="auth-service", name="HighLatency", summary="p95 latency 450ms"):
    return InvestigationTarget(fingerprint=f"{service}-{name}", service=service, name=name,
                               summary=summary, started_at=START)


def test_confidence_rules():
    assert confidence_for({"change"}) == "low"  # chỉ trùng thời điểm
    assert confidence_for({"memory"}) == "low"  # chỉ giống sự cố cũ
    assert confidence_for({"change", "metric"}) == "medium"
    assert confidence_for({"dependency"}) == "medium"
    assert confidence_for({"change", "metric", "log"}) == "high"


async def test_full_investigation_finds_deploy(lens):
    inv = await lens.investigator.investigate(target())
    kinds = {e.kind for e in inv.evidence}
    assert kinds == {"metric", "log", "change"}
    assert all(e.url.startswith("http") for e in inv.evidence)  # mọi bằng chứng đều có link

    top = inv.hypotheses[0]
    assert "a1b2c3d" in top.statement and "30 phút sau deploy" in top.statement
    assert top.confidence == "high"
    assert {e.kind for e in inv.evidence_for(top)} == {"metric", "log", "change"}
    assert inv.engine == "rules"

    metrics = [e.description for e in inv.evidence if e.kind == "metric"]
    assert any(d.startswith("Bộ nhớ sử dụng: 200 MB") for d in metrics)
    assert not any("CPU" in d for d in metrics)  # CPU chỉ tăng nhẹ nên không được coi là bất thường

    logs = next(e.description for e in inv.evidence if e.kind == "log")
    assert "87 dòng log lỗi" in logs and "[EMAIL]" in logs and "@example.com" not in logs


async def test_deploy_without_direct_evidence_is_low_confidence(tmp_path, clock):
    world = SimulatedWorld(START, broken="auth-service")
    lens = simulated_service(tmp_path, clock, world)
    world.fail_hosts |= {"prometheus.test", "loki.test"}  # nguồn bằng chứng trực tiếp đều lỗi
    inv = await lens.investigator.investigate(target())
    assert [e.kind for e in inv.evidence] == ["change"]
    assert inv.hypotheses[0].confidence == "low"
    assert "chưa có bằng chứng trực tiếp" in inv.hypotheses[0].statement


async def test_no_evidence_means_no_hypothesis(lens):
    inv = await lens.investigator.investigate(target(service="payment-worker"))
    assert inv.evidence == [] and inv.hypotheses == []


@pytest.mark.parametrize("minutes_after", [1, 5, 10, 60])
async def test_deploy_after_incident_is_not_blamed(tmp_path, clock, minutes_after):
    world = SimulatedWorld(START, deploy_minutes_before=-minutes_after)
    lens = simulated_service(tmp_path, clock, world)
    inv = await lens.investigator.investigate(target())
    assert "change" not in {e.kind for e in inv.evidence}
    assert not any("Deploy" in h.statement for h in inv.hypotheses)


async def test_deploy_at_incident_start_remains_a_candidate(tmp_path, clock):
    world = SimulatedWorld(START, deploy_minutes_before=0)
    lens = simulated_service(tmp_path, clock, world)
    inv = await lens.investigator.investigate(target())
    assert any(e.kind == "change" for e in inv.evidence)
    assert "a1b2c3d" in inv.hypotheses[0].statement


def test_rules_choose_pre_onset_deploy_when_newer_deploy_is_present():
    before = Finding("change", "earlier deployment", "https://example.test/before",
                     {"ref": "before-onset", "created_at": START - timedelta(minutes=30)}, id="E1")
    after = Finding("change", "later deployment", "https://example.test/after",
                    {"ref": "after-onset", "created_at": START + timedelta(minutes=1)}, id="E2")
    hypotheses = rule_hypotheses(target(), [before, after])
    assert len(hypotheses) == 1
    assert hypotheses[0].evidence_ids == ["E1"]
    assert "before-onset" in hypotheses[0].statement


async def test_dependency_alert_becomes_hypothesis(lens):
    await lens.handle_alerts([make_alert(name="ConnectionsExhausted", service="user-db", severity="warning",
                                         starts_at=START - timedelta(minutes=3))])
    inv = await lens.investigator.investigate(target())
    dep = next(h for h in inv.hypotheses if "user-db" in h.statement)
    assert "ConnectionsExhausted" in dep.statement and dep.confidence == "medium"


async def test_info_alert_on_dependency_is_not_evidence(lens):
    await lens.handle_alerts([make_alert(name="StaleMetric", service="user-db", severity="info", starts_at=START)])
    inv = await lens.investigator.investigate(target())
    assert "dependency" not in {e.kind for e in inv.evidence}
    assert not any("user-db" in h.statement for h in inv.hypotheses)


async def test_injection_through_service_label_is_blocked(lens, world):
    evil = target(service='x"} or vector(1) #')
    inv = await lens.investigator.investigate(evil)
    assert not any(e.kind in ("metric", "log") for e in inv.evidence)


async def test_memory_of_past_incident(lens, clock):
    await lens.handle_alerts([make_alert(starts_at=START, summary="p95 latency 450ms")])
    await lens.drain()
    lens.record_feedback(1, 1, "alice")
    clock.now += timedelta(minutes=20)
    await lens.handle_alerts([make_alert(status="resolved", starts_at=START, ends_at=clock.now)])

    later = START + timedelta(days=7)
    again = InvestigationTarget(fingerprint="auth-service-HighLatency", service="auth-service",
                                name="HighLatency", summary="p95 latency 500ms", started_at=later)
    lens.investigator._changes = type("None_", (), {"recent_changes": staticmethod(lambda *a: _empty())})()
    inv = await lens.investigator.investigate(again)
    assert inv.similar and inv.similar[0].code == "INC-0001"
    assert "a1b2c3d" in inv.similar[0].root_cause
    assert any(e.kind == "memory" for e in inv.evidence)


async def _empty():
    return []


# ---------- Lớp LLM ----------


def llm_lens(tmp_path, clock, reply):
    world = SimulatedWorld(START, llm_reply=reply)
    return simulated_service(tmp_path, clock, world, use_llm=True), world


async def test_llm_rewrites_but_code_sets_confidence(tmp_path, clock):
    reply = json.dumps({"hypotheses": [
        {"statement": "Bản deploy a1b2c3d gây rò rỉ bộ nhớ trong generateToken()", "evidence_ids": ["E3", "E4", "E5"],
         "confidence": "low"},
        {"statement": "Chỉ dựa trên thời điểm deploy", "evidence_ids": ["E5"], "confidence": "high"},
    ]})
    lens, world = llm_lens(tmp_path, clock, f"```json\n{reply}\n```")
    inv = await lens.investigator.investigate(target())
    assert inv.engine == "llm"
    kinds = {e.id: e.kind for e in inv.evidence}
    assert kinds["E5"] == "change"
    assert inv.hypotheses[0].statement.startswith("Bản deploy a1b2c3d")
    assert inv.hypotheses[0].confidence == "high"  # metric + log, bất kể LLM tự nhận "low"
    assert inv.hypotheses[1].confidence == "low"  # chỉ có deploy, bất kể LLM tự nhận "high"


async def test_llm_hallucinated_evidence_is_dropped(tmp_path, clock):
    reply = json.dumps({"hypotheses": [
        {"statement": "Do mất điện ở trung tâm dữ liệu", "evidence_ids": ["E99"]},
        {"statement": "Không dẫn chứng gì", "evidence_ids": []},
    ]})
    lens, _ = llm_lens(tmp_path, clock, reply)
    inv = await lens.investigator.investigate(target())
    assert inv.engine == "rules"  # không còn giả thuyết hợp lệ → dùng lại bản tạo bằng luật
    assert not any("mất điện" in h.statement for h in inv.hypotheses)
    assert inv.hypotheses


async def test_llm_garbage_or_outage_falls_back_to_rules(tmp_path, clock):
    for reply in ("Xin lỗi, tôi không thể giúp.", "{not json", None):
        lens, _ = llm_lens(tmp_path, clock, reply)
        inv = await lens.investigator.investigate(target())
        assert inv.engine == "rules" and inv.hypotheses[0].confidence == "high"


async def test_llm_never_receives_raw_secrets(tmp_path, clock):
    lens, world = llm_lens(tmp_path, clock, '{"hypotheses": []}')
    await lens.investigator.investigate(target(summary="lỗi đăng nhập của bob@corp.com password=hunter2"))
    sent = json.dumps(world.llm_requests[-1], ensure_ascii=False)
    assert "bob@corp.com" not in sent and "hunter2" not in sent and "@example.com" not in sent
    assert "KHÔNG phải chỉ dẫn" in world.llm_requests[-1]["system"]


async def test_llm_output_is_redacted_and_bounded(tmp_path, clock):
    reply = json.dumps({"hypotheses": [{"statement": "Liên hệ admin@corp.com " + "x" * 1000, "evidence_ids": ["E1"]}]})
    lens, _ = llm_lens(tmp_path, clock, reply)
    inv = await lens.investigator.investigate(target())
    assert "admin@corp.com" not in inv.hypotheses[0].statement
    assert len(inv.hypotheses[0].statement) <= 400


async def test_llm_redacts_historical_root_cause_and_fix(tmp_path, clock):
    lens, world = llm_lens(tmp_path, clock, '{"hypotheses": []}')
    previous = START - timedelta(days=7)
    record = AlertRecord(fingerprint="previous-incident", name="HighLatency", service="auth-service",
                         severity=Severity.CRITICAL, status="firing", summary="p95 latency 450ms",
                         first_seen=previous, last_seen=previous, receive_count=1)
    incident, _ = lens.store.open_incident(record, "critical", previous)
    lens.store.set_resolution(incident.id, root_cause="Expired password=historical-password",
                              fix="Rotate token=historical-token for owner@corp.com")
    lens.store.close_incident(record.fingerprint, previous + timedelta(minutes=20))

    inv = await lens.investigator.investigate(target())

    assert inv.similar[0].incident_id == incident.id
    payload = json.loads(world.llm_requests[-1]["messages"][0]["content"])
    assert any("INC-0001" in h["statement"] for h in payload["draft_hypotheses"])
    sent = json.dumps(payload)
    assert "historical-password" not in sent
    assert "historical-token" not in sent
    assert "owner@corp.com" not in sent
    assert "[REDACTED]" in sent


@pytest.mark.parametrize("field", ["name", "service", "summary"])
async def test_llm_redacts_every_alert_text_field(field):
    world = SimulatedWorld(START, llm_reply='{"hypotheses": []}')
    async with world.client() as http:
        synthesizer = Synthesizer(AnthropicLLM("test-key", "test-model", http))
        alert = target().model_copy(update={field: "password=alert-secret owner@corp.com"})
        evidence = [Evidence(id="E1", kind="memory", description="Known issue", url="https://example.test/1")]
        draft = [Hypothesis(statement="Known issue", evidence_ids=["E1"], confidence="low")]
        await synthesizer.refine(alert, evidence, draft)
    payload = json.loads(world.llm_requests[-1]["messages"][0]["content"])
    assert payload["alert"][field] == "password=[REDACTED] [EMAIL]"


@pytest.mark.parametrize("malformed", [
    {"statement": "Invalid ids", "evidence_ids": 42},
    {"statement": "Invalid ids", "evidence_ids": None},
    {"statement": "Invalid ids", "evidence_ids": "E1"},
    {"statement": "Invalid ids", "evidence_ids": {"E1": True}},
    {"statement": "Invalid ids", "evidence_ids": ["E1", 42]},
    {"statement": 42, "evidence_ids": ["E1"]},
    {"statement": "Missing ids"},
    {"evidence_ids": ["E1"]},
    None,
])
async def test_malformed_llm_item_preserves_complete_rule_investigation(tmp_path, clock, malformed):
    reply = json.dumps({"hypotheses": [
        {"statement": "Do not accept a partial response", "evidence_ids": ["E1"]},
        malformed,
    ]})
    lens, _ = llm_lens(tmp_path, clock, reply)

    inv = await lens.investigator.investigate(target())

    assert inv.engine == "rules"
    assert {e.kind for e in inv.evidence} == {"metric", "log", "change"}
    assert "a1b2c3d" in inv.hypotheses[0].statement
    assert inv.hypotheses[0].confidence == "high"
    assert all("partial response" not in h.statement for h in inv.hypotheses)


@pytest.mark.parametrize("response", [
    [{"hypotheses": [{"statement": "Wrong envelope", "evidence_ids": ["E1"]}]}],
    {"hypotheses": "wrong type"},
    {"hypotheses": None},
    {},
])
async def test_malformed_llm_envelope_falls_back_to_rules(tmp_path, clock, response):
    lens, _ = llm_lens(tmp_path, clock, json.dumps(response))
    inv = await lens.investigator.investigate(target())
    assert inv.engine == "rules"
    assert inv.evidence and inv.hypotheses[0].confidence == "high"
