"""Datetime helpers.

SQLite does not persist timezone info, so ORM datetime fields can come back
naive. All comparisons in the app use timezone-aware UTC; this helper normalises
values defensively.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_expired(dt: Optional[datetime]) -> bool:
    aware = as_aware(dt)
    return aware is None or aware < utcnow()
