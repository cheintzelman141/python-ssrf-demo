import os
import pytest
import httpx
from app.main import app

pytestmark = pytest.mark.asyncio


async def test_vulnerable_can_hit_internal_secret():
    os.environ["APP_ENV"] = "test"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        # SSRF into internal route (in test mode, outbound client routes back to ASGI app)
        r = await ac.get("/v1/fetch", params={"url": "http://testserver/internal/secret"})
        assert r.status_code == 200
        assert "INTERNAL_ONLY_TOKEN" in r.json()["body"]


async def test_safe_blocks_localhost():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        r = await ac.get("/v1/fetch-safe", params={"url": "http://localhost/internal/secret"})
        assert r.status_code == 400
        assert "Blocked" in r.json()["detail"]
