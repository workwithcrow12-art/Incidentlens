"""Che dữ liệu nhạy cảm trước khi đưa log vào bằng chứng hoặc gửi cho LLM."""

from __future__ import annotations

import re

SAFE_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$")


def is_safe_name(name: str) -> bool:
    """Tên dịch vụ đủ an toàn để chèn vào câu truy vấn hoặc lệnh (chống injection qua label)."""
    return bool(SAFE_NAME.fullmatch(name))


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return "[CARD]" if 13 <= len(digits) <= 19 and _luhn(digits) else match.group(0)


_RULES: list[tuple[re.Pattern, object]] = [
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "[JWT]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [TOKEN]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)\b"
                r"(\"?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"), r"\1\2[REDACTED]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[AWS_KEY]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"(?<![\w.])\d(?:[ -]?\d){12,18}(?![\w.])"), _card),
    (re.compile(r"(?<![\w.+])(?:\+\d{1,3}|0)(?:[ -]?\d){9,11}(?![\w.])"), "[PHONE]"),
]


def redact(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
