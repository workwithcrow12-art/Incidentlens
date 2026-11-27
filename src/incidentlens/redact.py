"""Redact sensitive values before including logs in evidence or sending text to an LLM."""

from __future__ import annotations

from collections.abc import Callable
import re

SAFE_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$")


def is_safe_name(name: str) -> bool:
    """Validate that a service name is safe to interpolate into queries or command arguments."""
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


def _card(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return "[CARD]" if 13 <= len(digits) <= 19 and _luhn(digits) else match.group(0)


_PLACEHOLDERS = {"[REDACTED]", "[TOKEN]", "[API_KEY]", "[GITHUB_TOKEN]", "[SLACK_TOKEN]", "[JWT]", "[AWS_KEY]"}


def _redact_userinfo(userinfo: str, host_and_path: str = "") -> str | None:
    if ":" in userinfo:
        user, password = userinfo.split(":", 1)
        if "/" in user or not password or password in _PLACEHOLDERS:
            return None
        if re.match(r"^\d{1,5}/", password) and re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", host_and_path):
            return None
        return f"{user}:[REDACTED]"
    if "/" not in userinfo and userinfo and userinfo not in _PLACEHOLDERS:
        return "[REDACTED]"
    return None


def _url_credentials(match: re.Match[str]) -> str:
    scheme, raw = match.group(1), match.group(2)
    trimmed = raw.rstrip("),.;]")
    suffix = raw[len(trimmed) :]
    qpos = min((trimmed.find(s) for s in ("?", "#") if s in trimmed), default=len(trimmed))
    authority_and_path, tail = trimmed[:qpos], trimmed[qpos:]
    if "@" not in authority_and_path:
        return match.group(0)
    userinfo, host_and_path = authority_and_path.rsplit("@", 1)
    if host_and_path and (redacted := _redact_userinfo(userinfo, host_and_path)):
        return f"{scheme}{redacted}@{host_and_path}{tail}{suffix}"
    authority, slash, rest_path = authority_and_path.partition("/")
    if "@" in authority:
        auth_user, host = authority.rsplit("@", 1)
        if host and (redacted := _redact_userinfo(auth_user)):
            return f"{scheme}{redacted}@{host}{slash}{rest_path}{tail}{suffix}"
    return match.group(0)


_AUTH_SCHEME = re.compile(r"(?i)^(bearer|basic|token|apikey|api-key|digest)\s+(.+)$")


def _auth_header(match: re.Match[str]) -> str:
    prefix, value = match.group(1), match.group(2)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        quote, inner = value[0], value[1:-1]
        m = _AUTH_SCHEME.match(inner)
        body = f"{m.group(1)} [TOKEN]" if m else "[TOKEN]"
        return f"{prefix}{quote}{body}{quote}"
    m = _AUTH_SCHEME.match(value)
    if m:
        return f"{prefix}{m.group(1)} [TOKEN]"
    return f"{prefix}[TOKEN]"


_NON_SECRET_SUFFIXES = {
    "count",
    "counts",
    "limit",
    "limits",
    "max",
    "min",
    "ttl",
    "age",
    "len",
    "length",
    "size",
    "bytes",
    "rate",
    "budget",
    "bucket",
    "type",
    "url",
    "uri",
    "endpoint",
    "host",
    "port",
    "service",
    "path",
    "file",
    "dir",
    "enabled",
    "disabled",
    "timeout",
    "interval",
    "seconds",
    "minutes",
    "hours",
    "days",
    "ms",
    "cost",
    "usage",
    "total",
}
_PASS_WORDS = {"password", "passwd", "pwd", "passphrase", "pass"}
_KEY_PREFIXES = {
    "api",
    "access",
    "private",
    "client",
    "auth",
    "signing",
    "encryption",
    "master",
    "secret",
    "webhook",
}
_DIRECT_KEYS = {"apikey", "accesskey", "privatekey", "clientkey", "authkey", "secretkey"}


def _is_secret_key(name: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name.strip("-")).lower()
    parts = [p for p in re.split(r"[_-]+", normalized) if p]
    if not parts or parts[-1] in _NON_SECRET_SUFFIXES:
        return False
    last = parts[-1]
    if last in _PASS_WORDS or last == "secret" or last == "token" or last in _DIRECT_KEYS:
        return True
    if (
        last in {"value", "val", "str", "hash"}
        and len(parts) >= 2
        and (parts[-2] in _PASS_WORDS or parts[-2] in {"secret", "token"})
    ):
        return True
    if last == "key" and len(parts) >= 2 and parts[-2] in _KEY_PREFIXES:
        return True
    return False


def _key_value(match: re.Match[str]) -> str:
    key, sep, value = match.group(1), match.group(2), match.group(3)
    if not _is_secret_key(key) or value in _PLACEHOLDERS:
        return match.group(0)
    return f"{key}{sep}[REDACTED]"


def _cli_flag(match: re.Match[str]) -> str:
    flag, sep, value = match.group(1), match.group(2), match.group(3)
    if not (flag.startswith("--") or len(flag) >= 4) or not _is_secret_key(flag) or value in _PLACEHOLDERS:
        return match.group(0)
    return f"{flag}{sep}[REDACTED]"


Replacement = str | Callable[[re.Match[str]], str]

_RULES: list[tuple[re.Pattern[str], Replacement]] = [
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "[JWT]"),
    (re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*://)([^\s\"'<>]+)"), _url_credentials),
    (re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})\b"), "[GITHUB_TOKEN]"),
    (re.compile(r"(?<![A-Za-z0-9])xox(?:e\.)?[baprs]-[A-Za-z0-9-]{6,}\b"), "[SLACK_TOKEN]"),
    (
        re.compile(
            r"(?<![A-Za-z0-9])"
            r"(?:sk-ant-[A-Za-z0-9_-]{4,}|sk[-_](?:proj[-_]|svcacct[-_]|live[-_]|test[-_])[A-Za-z0-9_-]{6,}|sk-[A-Za-z0-9]{20,})\b"
        ),
        "[API_KEY]",
    ),
    (
        re.compile(
            r"(?i)(?<![A-Za-z0-9_-])"
            r"((?:proxy[_-])?authorization[\"']?\s*[:=]\s*)"
            r"(\"[^\"]*\"|'[^']*'|(?:\b(?:bearer|basic|token|apikey|api-key|digest)\s+)?[^\s,;\"'}]+)"
        ),
        _auth_header,
    ),
    (re.compile(r"(?i)\b(bearer|basic)\s+(?!\[TOKEN\])[A-Za-z0-9._~+/=-]{8,}"), r"\1 [TOKEN]"),
    (
        re.compile(
            r"(?<![A-Za-z0-9_/-])"
            r"(--?[A-Za-z][A-Za-z0-9_-]*)"
            r"([ \t]+)(?!--)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&}\"']+)"
        ),
        _cli_flag,
    ),
    (
        re.compile(
            r"(?<![A-Za-z0-9_/])"
            r"(--?[A-Za-z][A-Za-z0-9_-]*|[A-Za-z][A-Za-z0-9_-]*)"
            r"([\"']?\s*[=:]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&}\"']+)"
        ),
        _key_value,
    ),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[AWS_KEY]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"(?<![\w.])\d(?:[ -]?\d){12,18}(?![\w.])"), _card),
    (re.compile(r"(?<![\w.+])(?:\+\d{1,3}|0)(?:[ -]?\d){9,11}(?![\w.])"), "[PHONE]"),
]


def redact(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
