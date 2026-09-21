"""Output sanitisation helpers (defence-in-depth against XSS).

The API returns JSON and sets ``Content-Type: application/json`` plus security
headers, so the browser will not execute injected markup. These helpers add a
second layer by neutralising HTML-significant characters in free-text fields
that may later be rendered in the admin/user interface.
"""
from __future__ import annotations

import html
import re

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sanitize_text(value: str | None, max_length: int = 2000) -> str:
    """Strip control characters and HTML-escape a free-text value."""
    if value is None:
        return ""
    value = _CONTROL_CHARS.sub("", str(value))[:max_length]
    return html.escape(value, quote=True)


def strip_tags(value: str | None, max_length: int = 2000) -> str:
    """Remove anything that looks like an HTML/JS tag (no escaping)."""
    if value is None:
        return ""
    value = re.sub(r"<[^>]*>", "", str(value))
    return _CONTROL_CHARS.sub("", value)[:max_length]
