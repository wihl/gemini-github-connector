"""Automated tests for the Gemini GitHub MCP Proxy."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from app.main import app
from app.mcp_proxy import UPSTREAM_MCP_URL, close_http_client

TEST_PAT = "ghp_test_secret_pat_1234567890"
TEST_PIN = "654321"
TEST_SIGNING_SECRET = "a" * 64


@pytest.fixture(autouse=True)
async def setup_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GITHUB_PAT", TEST_PAT)
    monkeypatch.setenv("ADMIN_PIN", TEST_PIN)
    monkeypatch.setenv("SIGNING_SECRET", TEST_SIGNING_SECRET)
    await close_http_client()
    yield
    await close_http_client()


@pytest.fixture
async def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://example-proxy.run.app",
        headers={"X-Forwarded-Proto": "https", "Host": "example-proxy.run.app"},
    ) as ac:
        yield ac


async def test_well_known_metadata(client: httpx.AsyncClient) -> None:
    res_pr = await client.get("/.well-known/oauth-protected-resource")
    assert res_pr.status_code == 200
    assert res_pr.json() == {
        "resource": "https://example-proxy.run.app/mcp",
        "authorization_servers": ["https://example-proxy.run.app"],
        "bearer_methods_supported": ["header"],
    }

    res_pr_mcp = await client.get("/.well-known/oauth-protected-resource/mcp")
    assert res_pr_mcp.status_code == 200
    assert res_pr_mcp.json()["resource"] == "https://example-proxy.run.app/mcp"

    res_as = await client.get("/.well-known/oauth-authorization-server")
    assert res_as.status_code == 200
    as_data = res_as.json()
    assert as_data["issuer"] == "https://example-proxy.run.app"
    assert as_data["authorization_endpoint"] == "https://example-proxy.run.app/authorize"
    assert as_data["token_endpoint"] == "https://example-proxy.run.app/token"
    assert as_data["registration_endpoint"] == "https://example-proxy.run.app/register"
    assert "S256" in as_data["code_challenge_methods_supported"]


async def test_unauthenticated_mcp_returns_401_with_www_authenticate(
    client: httpx.AsyncClient,
) -> None:
    resp = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert resp.status_code == 401
    www_auth = resp.headers.get("www-authenticate", "")
    assert (
        www_auth
        == 'Bearer resource_metadata="https://example-proxy.run.app/.well-known/oauth-protected-resource"'
    )


async def test_full_oauth_dcr_pkce_and_refresh_flow(client: httpx.AsyncClient) -> None:
    # 1. Dynamic Client Registration (POST /register)
    reg_resp = await client.post(
        "/register",
        json={
            "client_name": "Google Gemini",
            "redirect_uris": ["https://gemini.google.com/oauth/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
        },
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    client_id = reg_data["client_id"]
    assert client_id
    assert reg_data["client_secret"]
    assert reg_data["client_secret_expires_at"] == 0
    assert reg_data["redirect_uris"] == ["https://gemini.google.com/oauth/callback"]

    # 2. Prepare PKCE S256 verifier & challenge
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    # 3. GET /authorize
    auth_get = await client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "state": "xyz-state-123",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        },
    )
    assert auth_get.status_code == 200
    assert "Approve Gemini Access" in auth_get.text
    assert client_id in auth_get.text

    # 4. POST /authorize with wrong PIN fails
    bad_post = await client.post(
        "/authorize",
        data={
            "pin": "000000",
            "client_id": client_id,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "state": "xyz-state-123",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert bad_post.status_code == 401

    # 5. POST /authorize with valid ADMIN_PIN returns 302 with code & state
    auth_post = await client.post(
        "/authorize",
        data={
            "pin": TEST_PIN,
            "client_id": client_id,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "state": "xyz-state-123",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert auth_post.status_code == 302
    location = auth_post.headers["location"]
    parsed_loc = urlparse(location)
    assert f"{parsed_loc.scheme}://{parsed_loc.netloc}{parsed_loc.path}" == (
        "https://gemini.google.com/oauth/callback"
    )
    qs = parse_qs(parsed_loc.query)
    assert qs["state"] == ["xyz-state-123"]
    auth_code = qs["code"][0]

    # 6. POST /token with wrong code_verifier fails
    bad_token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "client_id": client_id,
            "code_verifier": "wrong_verifier",
        },
    )
    assert bad_token_resp.status_code == 400

    # 7. POST /token with valid code_verifier succeeds
    token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "client_id": client_id,
            "code_verifier": code_verifier,
        },
    )
    assert token_resp.status_code == 200
    assert token_resp.headers.get("cache-control") == "no-store"
    assert token_resp.headers.get("pragma") == "no-cache"
    token_data = token_resp.json()
    assert token_data["token_type"] == "Bearer"
    assert token_data["expires_in"] == 315360000
    assert token_data["access_token"]
    assert token_data["refresh_token"]

    # 8. POST /token with refresh_token
    refresh_resp = await client.post(
        "/token",
        json={
            "grant_type": "refresh_token",
            "refresh_token": token_data["refresh_token"],
        },
    )
    assert refresh_resp.status_code == 200
    refreshed_data = refresh_resp.json()
    assert refreshed_data["access_token"]
    assert refreshed_data["refresh_token"]
    assert refreshed_data["access_token"] != token_data["access_token"]


async def test_authenticated_mcp_forwarding_and_header_replacement(
    client: httpx.AsyncClient,
) -> None:
    # Obtain valid access token via OAuth flow
    auth_post = await client.post(
        "/authorize",
        data={
            "pin": TEST_PIN,
            "client_id": "test-client",
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "state": "state1",
        },
        follow_redirects=False,
    )
    code = parse_qs(urlparse(auth_post.headers["location"]).query)["code"][0]
    token_resp = await client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": code},
    )
    access_token = token_resp.json()["access_token"]
    assert access_token != TEST_PAT

    captured_headers: list[httpx.Headers] = []

    def mock_upstream(request: httpx.Request) -> httpx.Response:
        captured_headers.append(request.headers)
        body = request.read().decode("utf-8")
        if '"initialize"' in body:
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "application/json",
                    "Mcp-Session-Id": "gh-session-abc",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "serverInfo": {"name": "github-mcp-server", "version": "1.0.0"},
                    },
                },
            )
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/event-stream",
                "Mcp-Session-Id": "gh-session-abc",
            },
            content=(
                b'event: message\n'
                b'data: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_issue"}]}}\n\n'
            ),
        )

    with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.post(UPSTREAM_MCP_URL).mock(side_effect=mock_upstream)

        # Call initialize (JSON response)
        init_resp = await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {}},
            },
        )
        assert init_resp.status_code == 200
        assert init_resp.headers.get("mcp-session-id") == "gh-session-abc"
        assert init_resp.json()["result"]["serverInfo"]["name"] == "github-mcp-server"

        # Call tools/list (SSE streaming response)
        tools_resp = await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Mcp-Session-Id": "gh-session-abc",
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools_resp.status_code == 200
        assert "text/event-stream" in tools_resp.headers.get("content-type", "")
        assert "get_issue" in tools_resp.text

    # Verify proxy token was stripped and replaced with GITHUB_PAT
    assert len(captured_headers) == 2
    for hdrs in captured_headers:
        assert hdrs.get("authorization") == f"Bearer {TEST_PAT}"
        assert access_token not in hdrs.get("authorization", "")
    assert captured_headers[1].get("mcp-session-id") == "gh-session-abc"


async def test_healthz(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    monkeypatch.delenv("GITHUB_PAT")
    resp_err = await client.get("/healthz")
    assert resp_err.status_code == 503
    assert "GITHUB_PAT" in resp_err.json()["missing"]
