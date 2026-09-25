import time
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from src.core.config import settings

class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = float(capacity)
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> Tuple[bool, int, float]:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            remaining = int(self.tokens)
            reset_time = (self.capacity - self.tokens) / self.refill_rate if self.refill_rate > 0 else 0
            return True, remaining, reset_time
        else:
            remaining = int(self.tokens)
            wait_time = (tokens - self.tokens) / self.refill_rate if self.refill_rate > 0 else 60.0
            return False, remaining, wait_time

class RateLimiter:
    def __init__(self):
        self.buckets: Dict[str, TokenBucket] = {}
        self.default_capacity = settings.RATE_LIMIT_DEFAULT_REQUESTS
        self.default_refill_rate = settings.RATE_LIMIT_DEFAULT_REQUESTS / settings.RATE_LIMIT_DEFAULT_WINDOW_SECONDS

    def get_client_identifier(self, request: Request, user_id: str = None) -> str:
        """Derive client rate-limiting key from authenticated identity or IP."""
        if user_id:
            return f"user:{user_id}"
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token.startswith("sk_live_"):
                return f"apikey:{token}"
        client_ip = request.client.host if request.client else "127.0.0.1"
        return f"ip:{client_ip}"

    def check_rate_limit(self, client_key: str, cost: int = 1) -> Tuple[int, int, float]:
        """
        Check if request is allowed.
        Returns: (status_allowed: bool, remaining: int, reset_or_wait: float)
        """
        if client_key not in self.buckets:
            self.buckets[client_key] = TokenBucket(
                capacity=self.default_capacity,
                refill_rate=self.default_refill_rate
            )
        
        allowed, remaining, wait_or_reset = self.buckets[client_key].consume(cost)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Too many requests. Please throttle your traffic.",
                headers={
                    "X-RateLimit-Limit": str(self.default_capacity),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(wait_or_reset)),
                    "Retry-After": str(int(wait_or_reset) or 1)
                }
            )
        return self.default_capacity, remaining, wait_or_reset

rate_limiter = RateLimiter()
