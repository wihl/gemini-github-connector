"""FastAPI entrypoint for the Gemini GitHub MCP Proxy."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.mcp_proxy import close_http_client, get_http_client, router as mcp_router
from app.oauth import router as oauth_router


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    get_http_client()
    try:
        yield
    finally:
        await close_http_client()


app = FastAPI(
    title="Gemini GitHub MCP Proxy",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(oauth_router)
app.include_router(mcp_router)
