"""In-memory sliding-window rate limiting.

Suitable for a single-process deployment. For multi-worker/multi-node
deployments, swap the backing store for Redis (the interface is unchanged).
Rate limiting protects authentication endpoints from brute force and the API
from abuse / excessive requests.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict

from fastapi import HTTPException, Request, status

from backend.config import settings
from backend.utils.request_context import get_client_ip


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int


class RateLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int) -> RateLimitResult:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = int(window - (now - bucket[0])) + 1
                return RateLimitResult(False, 0, retry_after)
            bucket.append(now)
            return RateLimitResult(True, limit - len(bucket), window)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


limiter = RateLimiter()


def check_rate_limit(
    request: Request,
    *,
    scope: str = "default",
    limit: int | None = None,
    window: int | None = None,
) -> RateLimitResult:
    """Apply a rate limit for the current request and raise 429 if exceeded."""
    limit = limit if limit is not None else settings.rate_limit_default
    window = window if window is not None else settings.rate_limit_window_seconds
    ip = get_client_ip(request)
    key = f"{scope}:{ip}"
    result = limiter.hit(key, limit, window)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please slow down and try again later.",
            headers={"Retry-After": str(result.retry_after)},
        )
    return result
