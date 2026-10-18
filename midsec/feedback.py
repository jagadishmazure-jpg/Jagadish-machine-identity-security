"""PII scrubbing for free-text feedback before storage.

Phone patterns are scrubbed before generic digit runs so formatted numbers
are caught; bare dates like 2026-10-18 are explicitly left intact.
"""

from __future__ import annotations

import re

_PHONE = [
    re.compile(r"\+1\s*\(\d{3}\)\s*\d{3}-\d{4}"),   # +1 (555) 123-4567
    re.compile(r"\(\d{3}\)\s*\d{3}-\d{4}"),          # (555) 123-4567
    re.compile(r"\b\d{3}\.\d{3}\.\d{4}\b"),          # 555.123.4567
]
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")          # 123-45-6789
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")         # kept intact


def scrub(text: str) -> str:
    """Redact phones, SSNs and emails; leave ISO dates untouched."""
    dates = _DATE.findall(text)
    out = text
    for pat in _PHONE:
        out = pat.sub("[PHONE]", out)
    out = _SSN.sub("[SSN]", out)
    out = _EMAIL.sub("[EMAIL]", out)
    # ISO dates were never matched by the patterns above; assert they survive.
    for d in dates:
        assert d in out, f"date {d} was altered by scrubbing"
    return out


class FeedbackStore:
    """Stores only scrubbed feedback."""

    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, author: str, text: str) -> dict:
        item = {"author": author, "text": scrub(text)}
        self.items.append(item)
        return item
