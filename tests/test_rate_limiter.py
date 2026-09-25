import pytest
from fastapi import HTTPException
from src.gateway.rate_limiter import TokenBucket, RateLimiter

def test_token_bucket_consume():
    bucket = TokenBucket(capacity=5, refill_rate=1.0)
    # Consume 3 tokens
    allowed, remaining, _ = bucket.consume(3)
    assert allowed is True
    assert remaining == 2

    # Consume remaining 2 tokens
    allowed, remaining, _ = bucket.consume(2)
    assert allowed is True
    assert remaining == 0

    # Next consumption should fail
    allowed, remaining, wait_time = bucket.consume(1)
    assert allowed is False
    assert remaining == 0
    assert wait_time > 0

def test_rate_limiter_exceeded():
    limiter = RateLimiter()
    client_key = "test-client-ip"
    limiter.buckets[client_key] = TokenBucket(capacity=2, refill_rate=0.1)

    # First two succeed
    limiter.check_rate_limit(client_key, cost=1)
    limiter.check_rate_limit(client_key, cost=1)

    # Third fails with 429 Too Many Requests
    with pytest.raises(HTTPException) as exc_info:
        limiter.check_rate_limit(client_key, cost=1)
    assert exc_info.value.status_code == 429
