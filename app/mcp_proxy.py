"""Streamable HTTP MCP Proxy to GitHub's official remote MCP server."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from app.oauth import get_base_url, verify_signed_token

router = APIRouter()

UPSTREAM_MCP_URL = "https://api.githubcopilot.com/mcp/"

FORWARDED_REQUEST_HEADERS = (
    "content-type",
    "accept",
    "mcp-session-id",
    "last-event-id",
    "mcp-protocol-version",
)

FORWARDED_RESPONSE_HEADERS = (
    "mcp-session-id",
    "mcp-protocol-version",
    "cache-control",
)

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": (
        "Authorization, Content-Type, Accept, Mcp-Session-Id, "
        "Last-Event-ID, Mcp-Protocol-Version"
    ),
    "Access-Control-Expose-Headers": "Mcp-Session-Id, Mcp-Protocol-Version, WWW-Authenticate",
}

_shared_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Return the shared httpx.AsyncClient(http2=True, timeout=120.0)."""
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(http2=True, timeout=120.0)
    return _shared_client


async def close_http_client() -> None:
    """Close the shared httpx.AsyncClient on shutdown."""
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
    _shared_client = None


def _unauthorized_response(request: Request, detail: str = "Unauthorized") -> JSONResponse:
    base_url = get_base_url(request)
    resource_meta = f"{base_url}/.well-known/oauth-protected-resource"
    headers = {
        **CORS_HEADERS,
        "WWW-Authenticate": f'Bearer resource_metadata="{resource_meta}"',
    }
    return JSONResponse(
        content={"error": "unauthorized", "error_description": detail},
        status_code=401,
        headers=headers,
    )


@router.get("/")
@router.get("/health")
@router.get("/healthz")
async def healthz() -> JSONResponse:
    github_pat = os.environ.get("GITHUB_PAT", "").strip()
    admin_pin = os.environ.get("ADMIN_PIN", "").strip()
    signing_secret = os.environ.get("SIGNING_SECRET", "").strip()

    missing = [
        name
        for name, val in (
            ("GITHUB_PAT", github_pat),
            ("ADMIN_PIN", admin_pin),
            ("SIGNING_SECRET", signing_secret),
        )
        if not val
    ]
    if missing:
        return JSONResponse(
            content={"status": "error", "missing": missing},
            status_code=503,
        )
    return JSONResponse(content={"status": "ok"}, status_code=200)


@router.api_route(
    "/mcp",
    methods=["POST", "GET", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
@router.api_route(
    "/mcp/",
    methods=["POST", "GET", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
async def proxy_mcp(request: Request) -> Response:
    if request.method == "OPTIONS":
        return Response(status_code=204, headers=CORS_HEADERS)

    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return _unauthorized_response(request, "Missing Bearer token")

    token = auth_header[7:].strip()
    if not token:
        return _unauthorized_response(request, "Empty Bearer token")

    try:
        verify_signed_token(token)
    except Exception as exc:
        return _unauthorized_response(request, str(exc))

    github_pat = os.environ.get("GITHUB_PAT", "").strip()
    if not github_pat:
        return JSONResponse(
            content={"error": "server_error", "error_description": "GITHUB_PAT is not configured"},
            status_code=500,
            headers=CORS_HEADERS,
        )

    upstream_url = os.environ.get("UPSTREAM_MCP_URL", UPSTREAM_MCP_URL).strip() or UPSTREAM_MCP_URL

    upstream_headers: dict[str, str] = {
        "Authorization": f"Bearer {github_pat}",
    }
    for header_name in FORWARDED_REQUEST_HEADERS:
        val = request.headers.get(header_name)
        if val:
            upstream_headers[header_name] = val

    if "accept" not in upstream_headers:
        upstream_headers["Accept"] = "application/json, text/event-stream"

    body = await request.body()
    client = get_http_client()

    upstream_req = client.build_request(
        method=request.method,
        url=upstream_url,
        headers=upstream_headers,
        content=body if body else None,
    )
    upstream_resp = await client.send(upstream_req, stream=True)

    response_headers: dict[str, str] = {**CORS_HEADERS}
    for header_name in FORWARDED_RESPONSE_HEADERS:
        val = upstream_resp.headers.get(header_name)
        if val:
            # Preserve canonical header casing for Mcp-Session-Id
            if header_name == "mcp-session-id":
                response_headers["Mcp-Session-Id"] = val
            elif header_name == "mcp-protocol-version":
                response_headers["Mcp-Protocol-Version"] = val
            else:
                response_headers[header_name] = val

    content_type = upstream_resp.headers.get("content-type", "")

    if "text/event-stream" in content_type.lower():
        response_headers["Cache-Control"] = "no-cache"
        response_headers["X-Accel-Buffering"] = "no"

        async def stream_sse() -> AsyncIterator[bytes]:
            try:
                async for chunk in upstream_resp.aiter_raw():
                    yield chunk
            finally:
                await upstream_resp.aclose()

        return StreamingResponse(
            stream_sse(),
            status_code=upstream_resp.status_code,
            media_type="text/event-stream",
            headers=response_headers,
        )

    try:
        content = await upstream_resp.aread()
    finally:
        await upstream_resp.aclose()

    return Response(
        content=content,
        status_code=upstream_resp.status_code,
        media_type=content_type or None,
        headers=response_headers,
    )
