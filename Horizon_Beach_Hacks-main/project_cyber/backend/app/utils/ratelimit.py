"""
Contexta Backend - Rate limiting

Fixed-window counter. Uses Redis when REDIS_URL is configured and reachable,
otherwise falls back to a per-process in-memory counter.
"""

import time
from collections import defaultdict
from typing import Dict, Optional, Tuple

import structlog

from app.config import settings

logger = structlog.get_logger()

_memory: Dict[str, Tuple[int, int]] = defaultdict(lambda: (0, 0))
_redis = None
_redis_failed = False


async def _get_redis():
    global _redis, _redis_failed
    if _redis_failed or not settings.redis_url:
        return None
    if _redis is None:
        try:
            import redis.asyncio as aioredis

            _redis = aioredis.from_url(settings.redis_url, socket_connect_timeout=1)
            await _redis.ping()
        except Exception as exc:
            logger.warning("Redis unavailable, using in-memory rate limiting", error=str(exc))
            _redis_failed = True
            _redis = None
    return _redis


async def hit(key: str, limit: int, window_seconds: int = 60) -> Tuple[bool, int]:
    """Register a hit. Returns (allowed, retry_after_seconds)."""
    window = int(time.time() // window_seconds)
    r = await _get_redis()
    if r is not None:
        try:
            rkey = f"rl:{key}:{window}"
            count = await r.incr(rkey)
            if count == 1:
                await r.expire(rkey, window_seconds + 1)
            retry = window_seconds - int(time.time() % window_seconds)
            return count <= limit, retry
        except Exception as exc:
            logger.warning("Redis rate limit failed", error=str(exc))
    stored_window, count = _memory[key]
    if stored_window != window:
        stored_window, count = window, 0
    count += 1
    _memory[key] = (stored_window, count)
    if len(_memory) > 50_000:  # bound memory
        for k in [k for k, (w, _) in _memory.items() if w != window][:25_000]:
            _memory.pop(k, None)
    retry = window_seconds - int(time.time() % window_seconds)
    return count <= limit, retry


def reset() -> None:
    _memory.clear()
