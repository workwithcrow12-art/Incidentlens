"""Tạo nội dung Markdown cho digest, theo mẫu trong tài liệu kế hoạch (mục 8.2)."""

from __future__ import annotations

from datetime import datetime

from incidentlens.models import CONFIDENCE_LABEL, AlertGroup


def _time(dt: datetime, ref: datetime) -> str:
    return dt.strftime("%H:%M") if dt.date() == ref.date() else dt.strftime("%m-%d %H:%M")


def _render_incident(index: int, inc: AlertGroup, ref: datetime) -> list[str]:
    status = "🔥 đang xảy ra" if inc.is_ongoing else "✅ đã hồi phục"
    lines = [
        f"## {inc.severity.icon} #{index} {inc.name} · `{inc.service}`",
        f"- **Phụ trách:** {inc.team}",
        f"- **Thời gian:** {_time(inc.first_seen, ref)} → {_time(inc.last_seen, ref)} (UTC)",
        f"- **Trạng thái:** {status}",
        f"- **Số lần nhận cảnh báo:** {inc.receive_count} (từ {len(inc.records)} nguồn)",
        f"- **Mô tả:** {inc.summary}",
    ]
    if inc.escalated:
        lines.append("- **Leo thang:** ⬆️ đã tự động nâng lên 🔴 và gọi on-call")
    if inc.changes:
        lines.append("- **Thay đổi gần đây:**")
        for ch in inc.changes:
            who = f" bởi {ch.author}" if ch.author else ""
            ref_text = f"[`{ch.ref}`]({ch.url})" if ch.url else f"`{ch.ref}`"
            lines.append(f"  - {ch.kind} {ref_text}{who} lúc {_time(ch.created_at, ref)}")
    if inc.investigation and inc.investigation.hypotheses:
        top = inc.investigation.hypotheses[0]
        links = " · ".join(f"[{e.description}]({e.url})" for e in inc.investigation.evidence_for(top))
        lines.append(f"- **Giả thuyết [{CONFIDENCE_LABEL[top.confidence]}]:** {top.statement}")
        lines.append(f"  - Bằng chứng: {links}")
    if inc.source_url:
        lines.append(f"- **Nguồn:** [Xem trong hệ thống monitoring]({inc.source_url})")
    return lines


def render_digest(incidents: list[AlertGroup], window_start: datetime, window_end: datetime) -> str:
    title = f"# 📋 Digest {window_end:%Y-%m-%d} · {_time(window_start, window_end)}–{window_end:%H:%M} (UTC)"
    lines = [title, ""]

    if not incidents:
        lines += ["> Không có sự cố nào trong khung giờ này. 🎉", ""]
        return "\n".join(lines)

    total = sum(i.receive_count for i in incidents)
    summary = f"> {total} cảnh báo → {len(incidents)} sự cố."
    focus = next((n for n, inc in enumerate(incidents, 1) if inc.is_ongoing), None)
    if focus:
        summary += f" **Ưu tiên: #{focus}**"
    lines += [summary, "", "## Việc cần làm"]

    for n, inc in enumerate(incidents, 1):
        box = "[ ]" if inc.is_ongoing else "[x]"
        tail = "" if inc.is_ongoing else " — đã tự hồi phục"
        lines.append(f"- {box} {inc.severity.icon} #{n} `{inc.service}` {inc.name} — {inc.team}{tail}")

    lines += ["", "---"]
    for n, inc in enumerate(incidents, 1):
        lines += ["", *_render_incident(n, inc, window_end)]

    lines += [
        "",
        "---",
        f"_Tạo bởi IncidentLens lúc {window_end:%Y-%m-%d %H:%M} UTC. "
        "Mức cảnh báo do luật định tuyến quyết định, không phải AI. Giả thuyết là gợi ý, cần người kiểm chứng._",
        "",
    ]
    return "\n".join(lines)
