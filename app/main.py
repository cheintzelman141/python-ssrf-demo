import os
from fastapi import FastAPI, HTTPException, Query
import httpx

from .security import validate_outbound_url

app = FastAPI(title="FastAPI SSRF Demo")


@app.get("/internal/secret")
def internal_secret():
    return {"secret": "INTERNAL_ONLY_TOKEN=demo-secret"}


def get_outbound_client() -> httpx.AsyncClient:
    """
    For real usage: normal network client.
    For tests: route outbound requests back into this ASGI app to avoid real DNS/network.
    """
    if os.getenv("APP_ENV") == "test":
        transport = httpx.ASGITransport(app=app)
        return httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            follow_redirects=True,
            timeout=5.0,
        )
    return httpx.AsyncClient(follow_redirects=True, timeout=5.0)


@app.get("/v1/fetch")
async def fetch(url: str = Query(..., description="URL to fetch (vulnerable)")):
    try:
        async with get_outbound_client() as client:
            # nosemgrep: python-ssrf-user-controlled-url
            r = await client.get(url)
            return {"status": r.status_code, "body": r.text[:500]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Request failed: {e}")


@app.get("/v1/fetch-safe")
async def fetch_safe(url: str = Query(..., description="URL to fetch (safe)")):
    try:
        validate_outbound_url(url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        # Important: do NOT follow redirects automatically unless you revalidate each hop.
        async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
            r = await client.get(url)
            return {"status": r.status_code, "body": r.text[:500]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Request failed: {e}")
