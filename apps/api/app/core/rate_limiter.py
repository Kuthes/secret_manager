import asyncio
import time

from fastapi import HTTPException, status

from apps.api.app.core.config import settings

# In-memory storage for test/standalone environments: key -> (count, window_start)
_MEMORY_RATE_LIMITS: dict[str, tuple[int, float]] = {}
_MEMORY_LOCK = asyncio.Lock()


async def check_rate_limit(
    key: str,
    max_requests: int = 30,
    window_seconds: int = 60,
    error_message: str = "Rate limit exceeded. Please try again later.",
) -> None:
    """
    Enforces a rate limit for the given key (e.g., user_id or ip).
    Uses Redis if REDIS_URL is configured and available, otherwise falls back to memory.
    Raises HTTPException(429) if exceeded.
    """
    allowed = True
    redis_client = None

    if settings.REDIS_URL:
        try:
            import redis.asyncio as redis
            redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
            redis_key = f"ratelimit:{key}"
            current = await redis_client.incr(redis_key)
            if current == 1:
                await redis_client.expire(redis_key, window_seconds)
            if current > max_requests:
                allowed = False
        except Exception:
            # Fallback to in-memory if Redis connection fails
            redis_client = None
        finally:
            if redis_client:
                try:
                    await redis_client.aclose()
                except Exception:
                    pass

    if redis_client is None:
        async with _MEMORY_LOCK:
            now = time.time()
            if key in _MEMORY_RATE_LIMITS:
                count, window_start = _MEMORY_RATE_LIMITS[key]
                if now - window_start > window_seconds:
                    _MEMORY_RATE_LIMITS[key] = (1, now)
                else:
                    if count >= max_requests:
                        allowed = False
                    else:
                        _MEMORY_RATE_LIMITS[key] = (count + 1, window_start)
            else:
                _MEMORY_RATE_LIMITS[key] = (1, now)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error_message,
        )


def reset_memory_rate_limits() -> None:
    """Utility to reset in-memory rate limits between test cases."""
    _MEMORY_RATE_LIMITS.clear()
