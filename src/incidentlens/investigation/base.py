"""Common investigation protocol and deterministic confidence scoring."""

from __future__ import annotations

from collections.abc import Set
from typing import Protocol

from incidentlens.models import Confidence, Investigation, InvestigationTarget

# Direct behavioral evidence. "change" is temporal correlation and "memory" is historical similarity,
# so hypotheses resting on them have unverified causality and remain low confidence.
DIRECT_KINDS = {"metric", "log", "dependency"}
CORRELATIONAL_KINDS = {"change", "memory"}
CONFIDENCE_STRENGTH: dict[Confidence, int] = {"low": 0, "medium": 1, "high": 2}


def confidence_for(kinds: Set[str]) -> Confidence:
    """Compute confidence deterministically from independent direct evidence kinds, never from an LLM.

    - high: 2 or more independent direct evidence sources (with no unverified correlational leap)
    - medium: 1 direct evidence source (with no unverified correlational leap)
    - low: temporal correlation ("change"), historical similarity ("memory"), or no direct evidence
    """
    kind_set = set(kinds)
    if not kind_set or (kind_set & CORRELATIONAL_KINDS):
        return "low"
    direct = len(kind_set & DIRECT_KINDS)
    if direct >= 2:
        return "high"
    return "medium" if direct == 1 else "low"


class Investigator(Protocol):
    async def investigate(self, target: InvestigationTarget) -> Investigation | None: ...


class NoopInvestigator:
    async def investigate(self, target: InvestigationTarget) -> Investigation | None:
        return None
