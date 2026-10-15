"""Stateless OAuth 2.1 + Dynamic Client Registration (DCR) + PKCE engine."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import secrets
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import jwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

router = APIRouter()

TEN_YEARS_SECONDS = 315360000
AUTH_CODE_TTL_SECONDS = 600
DEFAULT_SCOPE = "repo read:org gist project issues pull_requests"


def get_signing_secret() -> str:
    secret = os.environ.get("SIGNING_SECRET", "").strip()
    if not secret:
        raise HTTPException(status_code=500, detail="SIGNING_SECRET is not configured")
    return secret


def get_admin_pin() -> str:
    pin = os.environ.get("ADMIN_PIN", "").strip()
    if not pin:
        raise HTTPException(status_code=500, detail="ADMIN_PIN is not configured")
    return pin


def get_base_url(request: Request) -> str:
    """Resolve external base URL from X-Forwarded-Proto and Host headers."""
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto:
        proto = forwarded_proto.split(",")[0].strip()
    elif os.environ.get("K_SERVICE"):
        proto = "https"
    else:
        proto = request.url.scheme or "https"

    forwarded_host = request.headers.get("x-forwarded-host")
    if forwarded_host:
        host = forwarded_host.split(",")[0].strip()
    else:
        host = request.headers.get("host") or request.url.netloc

    return f"{proto}://{host}".rstrip("/")


def create_signed_token(payload: dict[str, Any], ttl_seconds: int) -> str:
    now = int(time.time())
    claims = {
        **payload,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(claims, get_signing_secret(), algorithm="HS256")


def verify_signed_token(token: str, expected_type: str | None = None) -> dict[str, Any]:
    try:
        decoded = jwt.decode(token, get_signing_secret(), algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise ValueError(f"Invalid or expired token: {exc}") from exc

    if expected_type and decoded.get("typ") != expected_type:
        raise ValueError(f"Unexpected token type: {decoded.get('typ')}")
    return decoded


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    method_upper = (method or "S256").upper()
    if method_upper == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return hmac.compare_digest(computed, code_challenge)
    if method_upper == "PLAIN":
        return hmac.compare_digest(code_verifier, code_challenge)
    return False


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
async def oauth_protected_resource(request: Request) -> JSONResponse:
    base_url = get_base_url(request)
    return JSONResponse(
        {
            "resource": f"{base_url}/mcp",
            "authorization_servers": [base_url],
            "bearer_methods_supported": ["header"],
        }
    )


@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/oauth-authorization-server/mcp")
@router.get("/.well-known/openid-configuration")
async def oauth_authorization_server(request: Request) -> JSONResponse:
    base_url = get_base_url(request)
    return JSONResponse(
        {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "registration_endpoint": f"{base_url}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
            ],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": ["S256", "plain"],
        }
    )


@router.post("/register", status_code=201)
async def register_client(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    client_id = f"mcp-client-{secrets.token_urlsafe(12)}"
    client_secret = secrets.token_urlsafe(24)
    redirect_uris = body.get("redirect_uris", [])
    grant_types = body.get(
        "grant_types", ["authorization_code", "refresh_token"]
    )
    response_types = body.get("response_types", ["code"])
    token_endpoint_auth_method = body.get(
        "token_endpoint_auth_method", "client_secret_post"
    )

    response_data: dict[str, Any] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": token_endpoint_auth_method,
    }
    if "client_name" in body:
        response_data["client_name"] = body["client_name"]

    return JSONResponse(content=response_data, status_code=201)


def _render_authorize_html(
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: str,
    error_message: str = "",
) -> str:
    error_block = (
        f'<div class="error">{html.escape(error_message)}</div>'
        if error_message
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize Gemini GitHub MCP</title>
  <style>
    :root {{
      color-scheme: light dark;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: #0d1117;
      color: #e6edf3;
      padding: 16px;
      box-sizing: border-box;
    }}
    .card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      max-width: 400px;
      width: 100%;
      padding: 28px 24px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }}
    h1 {{
      font-size: 1.25rem;
      margin: 0 0 8px 0;
    }}
    p {{
      color: #8b949e;
      font-size: 0.9rem;
      margin: 0 0 20px 0;
      line-height: 1.4;
    }}
    label {{
      display: block;
      font-size: 0.85rem;
      font-weight: 600;
      margin-bottom: 6px;
    }}
    input[type="password"] {{
      width: 100%;
      padding: 12px;
      border-radius: 8px;
      border: 1px solid #30363d;
      background: #0d1117;
      color: #e6edf3;
      font-size: 1rem;
      box-sizing: border-box;
      margin-bottom: 16px;
    }}
    button {{
      width: 100%;
      padding: 12px;
      border-radius: 8px;
      border: none;
      background: #238636;
      color: #ffffff;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
    }}
    button:hover {{
      background: #2ea043;
    }}
    .error {{
      background: rgba(248, 81, 73, 0.15);
      border: 1px solid #f85149;
      color: #ff7b72;
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 0.85rem;
      margin-bottom: 16px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>GitHub MCP Authorization</h1>
    <p>Enter your Admin PIN to grant Gemini access to your GitHub MCP Proxy.</p>
    {error_block}
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="{html.escape(client_id)}" />
      <input type="hidden" name="redirect_uri" value="{html.escape(redirect_uri)}" />
      <input type="hidden" name="state" value="{html.escape(state)}" />
      <input type="hidden" name="code_challenge" value="{html.escape(code_challenge)}" />
      <input type="hidden" name="code_challenge_method" value="{html.escape(code_challenge_method)}" />
      <input type="hidden" name="scope" value="{html.escape(scope)}" />
      <label for="pin">Admin PIN</label>
      <input type="password" id="pin" name="pin" required autofocus autocomplete="current-password" placeholder="Enter ADMIN_PIN" />
      <button type="submit">Approve Gemini Access</button>
    </form>
  </div>
</body>
</html>"""


@router.get("/authorize", response_class=HTMLResponse)
async def authorize_get(
    request: Request,
    client_id: str = "",
    redirect_uri: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = DEFAULT_SCOPE,
) -> HTMLResponse:
    page = _render_authorize_html(
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
    )
    return HTMLResponse(content=page, status_code=200)


@router.post("/authorize")
async def authorize_post(request: Request):
    form = await request.form()
    pin = str(form.get("pin") or form.get("admin_pin") or "").strip()
    client_id = str(form.get("client_id") or request.query_params.get("client_id") or "")
    redirect_uri = str(form.get("redirect_uri") or request.query_params.get("redirect_uri") or "")
    state = str(form.get("state") or request.query_params.get("state") or "")
    code_challenge = str(form.get("code_challenge") or request.query_params.get("code_challenge") or "")
    code_challenge_method = str(
        form.get("code_challenge_method")
        or request.query_params.get("code_challenge_method")
        or "S256"
    )
    scope = str(form.get("scope") or request.query_params.get("scope") or DEFAULT_SCOPE)

    expected_pin = get_admin_pin()
    if not pin or not hmac.compare_digest(pin.encode("utf-8"), expected_pin.encode("utf-8")):
        page = _render_authorize_html(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            error_message="Invalid Admin PIN. Please try again.",
        )
        return HTMLResponse(content=page, status_code=401)

    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Missing redirect_uri")

    code = create_signed_token(
        {
            "typ": "auth_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "scope": scope or DEFAULT_SCOPE,
        },
        ttl_seconds=AUTH_CODE_TTL_SECONDS,
    )

    parsed = urlparse(redirect_uri)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query_params["code"] = code
    if state:
        query_params["state"] = state
    target_url = urlunparse(parsed._replace(query=urlencode(query_params)))
    return RedirectResponse(url=target_url, status_code=302)


async def _parse_token_request(request: Request) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "").lower()
    data: dict[str, Any] = {}
    if "application/json" in content_type:
        try:
            body = await request.json()
            if isinstance(body, dict):
                data.update(body)
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            for k, v in form.items():
                data[k] = str(v)
        except Exception:
            pass
        if not data:
            try:
                body = await request.json()
                if isinstance(body, dict):
                    data.update(body)
            except Exception:
                pass
    return data


@router.post("/token")
async def token_endpoint(request: Request) -> JSONResponse:
    data = await _parse_token_request(request)
    grant_type = str(data.get("grant_type") or "")

    token_headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }

    if grant_type == "authorization_code":
        code = str(data.get("code") or "")
        code_verifier = str(data.get("code_verifier") or "")
        if not code:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing authorization code"},
                status_code=400,
                headers=token_headers,
            )
        try:
            claims = verify_signed_token(code, expected_type="auth_code")
        except ValueError as exc:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": str(exc)},
                status_code=400,
                headers=token_headers,
            )

        code_challenge = str(claims.get("code_challenge") or "")
        code_challenge_method = str(claims.get("code_challenge_method") or "S256")
        if code_challenge:
            if not code_verifier or not verify_pkce(
                code_verifier, code_challenge, code_challenge_method
            ):
                return JSONResponse(
                    {
                        "error": "invalid_grant",
                        "error_description": "PKCE verification failed",
                    },
                    status_code=400,
                    headers=token_headers,
                )

        client_id = str(claims.get("client_id") or data.get("client_id") or "gemini")
        scope = str(claims.get("scope") or DEFAULT_SCOPE)

    elif grant_type == "refresh_token":
        refresh_token = str(data.get("refresh_token") or "")
        if not refresh_token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing refresh_token"},
                status_code=400,
                headers=token_headers,
            )
        try:
            claims = verify_signed_token(refresh_token, expected_type="refresh")
        except ValueError as exc:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": str(exc)},
                status_code=400,
                headers=token_headers,
            )
        client_id = str(claims.get("client_id") or "gemini")
        scope = str(claims.get("scope") or DEFAULT_SCOPE)

    elif grant_type == "client_credentials":
        client_secret = str(data.get("client_secret") or "")
        expected_pin = get_admin_pin()
        if not client_secret or not hmac.compare_digest(
            client_secret.encode("utf-8"), expected_pin.encode("utf-8")
        ):
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Invalid client credentials"},
                status_code=401,
                headers=token_headers,
            )
        client_id = str(data.get("client_id") or "gemini")
        scope = str(data.get("scope") or DEFAULT_SCOPE)

    else:
        return JSONResponse(
            {
                "error": "unsupported_grant_type",
                "error_description": f"Unsupported grant_type: {grant_type}",
            },
            status_code=400,
            headers=token_headers,
        )

    access_token = create_signed_token(
        {"typ": "access", "sub": client_id, "client_id": client_id, "scope": scope},
        ttl_seconds=TEN_YEARS_SECONDS,
    )
    new_refresh_token = create_signed_token(
        {"typ": "refresh", "sub": client_id, "client_id": client_id, "scope": scope},
        ttl_seconds=TEN_YEARS_SECONDS,
    )

    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TEN_YEARS_SECONDS,
            "refresh_token": new_refresh_token,
            "scope": DEFAULT_SCOPE,
        },
        status_code=200,
        headers=token_headers,
    )
