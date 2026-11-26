"""Bản nháp postmortem tạo tự động từ dữ liệu đã ghi lại (không cần LLM)."""

from __future__ import annotations

from incidentlens.models import CONFIDENCE_LABEL, ActionRecord, IncidentRecord, InvestigationRecord

_TODO = "_Chưa xác định — cần người phụ trách bổ sung._"


def render_postmortem(incident: IncidentRecord, investigations: list[InvestigationRecord],
                      actions: list[ActionRecord], team: str) -> str:
    origin = "🔴 Khẩn cấp (gọi on-call ngay)" if incident.origin == "critical" else "⬆️ Leo thang từ 🟡"
    resolved = f"{incident.resolved_at:%Y-%m-%d %H:%M} UTC" if incident.resolved_at else "chưa hồi phục"
    duration = f"{incident.duration_minutes} phút" if incident.duration_minutes is not None else "—"

    timeline = [(incident.started_at, "Sự cố bắt đầu"), (incident.opened_at, "Gọi on-call")]
    for rec in investigations:
        n = len(rec.investigation.hypotheses)
        timeline.append((rec.created_at, f"Điều tra tự động hoàn tất ({n} giả thuyết, "
                                         f"{rec.investigation.duration_seconds:.0f} giây)"))
    for a in actions:
        timeline.append((a.at, f"{a.user} bấm hành động `{a.action}` → {a.status}"))
    if incident.resolved_at:
        timeline.append((incident.resolved_at, "Hồi phục"))
    timeline.sort(key=lambda item: item[0])

    lines = [
        f"# Postmortem (bản nháp) · {incident.code} · {incident.name} trên `{incident.service}`",
        "",
        "> Bản nháp tạo tự động từ dữ liệu hệ thống. Cần người phụ trách rà soát và bổ sung trước khi chia sẻ.",
        "",
        "## Tóm tắt",
        f"- **Mô tả:** {incident.summary}",
        f"- **Dịch vụ:** `{incident.service}` · **Phụ trách:** {team}",
        f"- **Loại:** {origin}",
        f"- **Bắt đầu:** {incident.started_at:%Y-%m-%d %H:%M} UTC · **Hồi phục:** {resolved}",
        f"- **Thời gian xử lý:** {duration}",
        "",
        "## Dòng thời gian (UTC)",
        *[f"- {at:%m-%d %H:%M} — {text}" for at, text in timeline],
        "",
        "## Nguyên nhân",
        incident.root_cause or _TODO,
    ]

    for rec in investigations:
        inv = rec.investigation
        if not inv.hypotheses:
            continue
        lines += ["", "### Giả thuyết của hệ thống"]
        cited: list[str] = []
        for n, h in enumerate(inv.hypotheses, 1):
            mark = ""
            if rec.feedback == "up" and rec.feedback_hypothesis == n:
                mark = f" ✅ _(xác nhận bởi {rec.feedback_by})_"
            lines.append(f"{n}. **[{CONFIDENCE_LABEL[h.confidence]}]** {h.statement} ({', '.join(h.evidence_ids)}){mark}")
            cited += [i for i in h.evidence_ids if i not in cited]
        if rec.feedback == "down":
            lines.append(f"\n_👎 {rec.feedback_by} đánh giá: không giả thuyết nào đúng._")
        # Mỗi bằng chứng chỉ liệt kê một lần
        lines += ["", "### Bằng chứng"]
        lines += [f"- **{e.id}** [{e.description}]({e.url})" for e in inv.evidence if e.id in cited]

    lines += [
        "",
        "## Cách khắc phục",
        incident.fix or _TODO,
        "",
        "## Bài học và việc cần làm",
        "- [ ] Làm gì để sự cố này không lặp lại?",
        "- [ ] Có thể phát hiện sớm hơn bằng cảnh báo nào?",
        "- [ ] Runbook có cần cập nhật không?",
        "",
    ]
    return "\n".join(lines)
