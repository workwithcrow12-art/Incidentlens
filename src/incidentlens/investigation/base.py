"""Common investigation protocol and deterministic confidence scoring."""

from __future__ import annotations

from collections.abc import Set
from typing import Protocol

from incidentlens.models import Confidence, Investigation, InvestigationTarget

# Direct behavioral evidence. "change" is temporal correlation and "memory" is historical similarity,
# so neither counts toward direct behavioral confirmation.
DIRECT_KINDS = {"metric", "log", "dependency"}


def confidence_for(kinds: Set[str]) -> Confidence:
    """Compute confidence deterministically from independent direct evidence kinds, never from an LLM.

    - high: 2 or more independent direct evidence sources
    - medium: 1 direct evidence source
    - low: temporal correlation or historical similarity only
    """
    direct = len(set(kinds) & DIRECT_KINDS)
    if direct >= 2:
        return "high"
    return "medium" if direct == 1 else "low"


class Investigator(Protocol):
    async def investigate(self, target: InvestigationTarget) -> Investigation | None: ...


class NoopInvestigator:
    async def investigate(self, target: InvestigationTarget) -> Investigation | None:
        return None
