"""Markdown escaping helpers to prevent link, image, and HTML injection from untrusted alert/log text."""

from __future__ import annotations

_MD_SPECIAL = str.maketrans(
    {
        "\\": r"\\",
        "[": r"\[",
        "]": r"\]",
        "<": r"\<",
        ">": r"\>",
    }
)

_URL_SPECIAL = str.maketrans(
    {
        " ": "%20",
        "(": "%28",
        ")": "%29",
        "[": "%5B",
        "]": "%5D",
        "<": "%3C",
        ">": "%3E",
    }
)


def md_text(text: str) -> str:
    """Escape Markdown link/HTML control characters and collapse newlines for inline text."""
    single_line = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return single_line.translate(_MD_SPECIAL)


def md_code(text: str) -> str:
    """Render untrusted text inside an inline Markdown code span that cannot be broken out of."""
    clean = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    ticks = "`"
    while ticks in clean:
        ticks += "`"
    pad = " " if not clean or clean.startswith("`") or clean.endswith("`") else ""
    return f"{ticks}{pad}{clean}{pad}{ticks}"


def md_url(url: str | None) -> str | None:
    """Sanitize a URL for Markdown `[label](url)` links; allows only http/https schemes."""
    if not url:
        return None
    cleaned = url.strip()
    if any(ch in cleaned for ch in ("\r", "\n", "\x00")):
        return None
    if not cleaned.lower().startswith(("http://", "https://")):
        return None
    return cleaned.translate(_URL_SPECIAL)


def md_link(text: str, url: str | None) -> str:
    """Render escaped inline Markdown text, linked when `url` is a safe http(s) URL."""
    desc = md_text(text)
    safe = md_url(url)
    return f"[{desc}]({safe})" if safe else desc
