"""Thẻ điều tra trên Slack (mục 8.1 của kế hoạch)."""

from __future__ import annotations

from incidentlens.actions.runner import ActionSpec
from incidentlens.models import CONFIDENCE_LABEL, IncidentRecord, InvestigationRecord


def esc(text: str) -> str:
    """Thoát ký tự điều khiển của Slack để nội dung từ cảnh báo/log không chèn được link hay mention."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def link(url: str, text: str) -> str:
    safe_url = url.replace("|", "%7C").replace(">", "%3E").replace("<", "%3C")
    return f"<{safe_url}|{esc(text).replace('|', '/')}>"


def _short(text: str, limit: int = 280) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}


def _button(text: str, action_id: str, value: str, **extra) -> dict:
    return {"type": "button", "text": {"type": "plain_text", "text": text[:75]},
            "action_id": action_id, "value": value, **extra}


def investigation_card(record: InvestigationRecord, incident: IncidentRecord | None,
                       actions: list[tuple[str, ActionSpec]], runbook: str | None) -> tuple[str, list[dict]]:
    inv = record.investigation
    t = inv.target
    code = f" · {incident.code}" if incident else ""
    parts = [f"🔍 *Điều tra tự động: {esc(t.name)}* trên `{esc(t.service)}`{code}\n{esc(t.summary)}"]

    if inv.hypotheses:
        lines = ["*Giả thuyết*"]
        cited: list[str] = []
        for n, h in enumerate(inv.hypotheses, 1):
            lines.append(f"{n}. *[{CONFIDENCE_LABEL[h.confidence]}]* {esc(h.statement)} _({', '.join(h.evidence_ids)})_")
            cited += [i for i in h.evidence_ids if i not in cited]
        parts.append("\n".join(lines))
        # Mỗi bằng chứng chỉ liệt kê một lần, kèm link về dữ liệu gốc
        shown = [e for e in inv.evidence if e.id in cited]
        parts.append("\n".join(["*Bằng chứng*", *[f"• {e.id} {link(e.url, _short(e.description))}" for e in shown]]))
    elif inv.evidence:
        lines = ["_Chưa đủ cơ sở để đưa ra giả thuyết. Dữ liệu thu thập được:_"]
        lines += [f"• {link(e.url, _short(e.description))}" for e in inv.evidence]
        parts.append("\n".join(lines))
    else:
        parts.append("_Không tìm thấy bất thường nào trong metric, log, deploy hay dịch vụ phụ thuộc._")

    if inv.similar:
        s = inv.similar[0]
        text = f"📎 *Sự cố tương tự:* {s.code} ({esc(s.name)} trên `{esc(s.service)}`)"
        if s.root_cause:
            text += f"\nNguyên nhân khi đó: {esc(s.root_cause)}"
        if s.fix:
            text += f"\nĐã sửa bằng: {esc(s.fix)}"
        if s.duration_minutes is not None:
            text += f"\nThời gian xử lý: {s.duration_minutes} phút"
        parts.append(text)

    blocks = [_section(p) for p in parts]
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text":
                   "Gợi ý do máy tạo, cần người kiểm chứng. Hành động chỉ chạy khi người có quyền bấm duyệt."}]})

    ops: list[dict] = []
    if runbook:
        ops.append({"type": "button", "text": {"type": "plain_text", "text": "📋 Runbook"},
                    "action_id": "runbook", "url": runbook})
    if incident:
        for name, spec in actions[:4]:
            question = (spec.confirm or "Chạy *" + spec.label + "* trên `{service}`?").replace("{service}", t.service)
            ops.append(_button(spec.label, f"act_{name}", f"{incident.id}:{name}", style="danger", confirm={
                "title": {"type": "plain_text", "text": "Xác nhận"},
                "text": {"type": "mrkdwn", "text": question[:290]},
                "confirm": {"type": "plain_text", "text": "Chạy"},
                "deny": {"type": "plain_text", "text": "Hủy"},
            }))
    if ops:
        blocks.append({"type": "actions", "elements": ops})

    if inv.hypotheses:
        feedback = [_button(f"✅ Giả thuyết {n} đúng", f"fb_{n}", f"{record.id}:{n}")
                    for n in range(1, len(inv.hypotheses) + 1)]
        feedback.append(_button("👎 Không cái nào đúng", "fb_0", f"{record.id}:0"))
        blocks.append({"type": "actions", "elements": feedback})

    return "\n\n".join(parts), blocks
