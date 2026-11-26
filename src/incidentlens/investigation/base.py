"""Giao diện chung cho bộ máy điều tra và cách tính mức tin cậy."""

from __future__ import annotations

from typing import Protocol

from incidentlens.models import Confidence, Investigation, InvestigationTarget

# Bằng chứng TRỰC TIẾP về hành vi của hệ thống. "change" chỉ là trùng thời điểm,
# "memory" chỉ là suy diễn từ sự cố cũ, nên hai loại này không tính.
DIRECT_KINDS = {"metric", "log", "dependency"}


def confidence_for(kinds: set[str]) -> Confidence:
    """Mức tin cậy do MÃ NGUỒN tính theo số nguồn bằng chứng độc lập, không lấy từ AI.

    - Cao: từ 2 nguồn bằng chứng trực tiếp trở lên
    - Trung bình: 1 nguồn bằng chứng trực tiếp
    - Thấp: chỉ trùng thời điểm hoặc giống sự cố cũ
    """
    direct = len(kinds & DIRECT_KINDS)
    if direct >= 2:
        return "high"
    return "medium" if direct == 1 else "low"


class Investigator(Protocol):
    async def investigate(self, target: InvestigationTarget) -> Investigation | None: ...


class NoopInvestigator:
    async def investigate(self, target: InvestigationTarget) -> Investigation | None:
        return None
