#!/usr/bin/env python3
"""Live end-to-end verification script against the deployed Cloud Run MCP Proxy."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx


def parse_repo(repo_input: str) -> tuple[str, str]:
    """Parse 'owner/repo' or 'https://github.com/owner/repo' into (owner, repo)."""
    cleaned = repo_input.strip().rstrip("/")
    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        parts = [p for p in parsed.path.strip("/").split("/") if p]
    else:
        parts = [p for p in cleaned.split("/") if p]

    if len(parts) < 2:
        raise ValueError(
            f"Invalid repository identifier '{repo_input}'. Expected 'owner/repo' or GitHub URL."
        )
    owner, repo = parts[-2], parts[-1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def parse_mcp_payload(resp: httpx.Response) -> dict[str, Any]:
    """Parse either application/json or text/event-stream JSON-RPC response."""
    content_type = resp.headers.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        last_json: dict[str, Any] = {}
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                raw = line[5:].strip()
                if raw:
                    try:
                        parsed = json.loads(raw)
                        if isinstance(parsed, dict):
                            last_json = parsed
                            if "result" in parsed or "error" in parsed:
                                return parsed
                    except json.JSONDecodeError:
                        continue
        if last_json:
            return last_json
        raise RuntimeError(f"Could not parse SSE response: {resp.text[:500]}")
    return resp.json()


async def run_verification(
    service_url: str,
    admin_pin: str,
    repo_str: str,
    issue_number: int,
) -> None:
    base_url = service_url.rstrip("/")
    owner, repo = parse_repo(repo_str)

    async with httpx.AsyncClient(http2=True, timeout=60.0) as client:
        print(f"==> [1/5] Checking OAuth discovery and 401 challenge on {base_url} ...")
        unauth_mcp = await client.post(
            f"{base_url}/mcp",
            json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
        )
        assert unauth_mcp.status_code == 401, (
            f"Expected 401 from unauthenticated /mcp, got {unauth_mcp.status_code}"
        )
        assert "resource_metadata=" in unauth_mcp.headers.get("www-authenticate", "")

        pr_resp = await client.get(f"{base_url}/.well-known/oauth-protected-resource")
        pr_resp.raise_for_status()
        pr_data = pr_resp.json()
        assert pr_data["resource"] == f"{base_url}/mcp", f"Mismatch resource: {pr_data}"

        as_resp = await client.get(f"{base_url}/.well-known/oauth-authorization-server")
        as_resp.raise_for_status()
        as_data = as_resp.json()
        assert as_data["issuer"] == base_url, f"Mismatch issuer: {as_data}"
        print("    OAuth discovery metadata verified.")

        print("==> [2/5] Executing OAuth 2.1 DCR + PKCE (S256) + Refresh flow ...")
        redirect_uri = "https://gemini.google.com/oauth/callback"
        reg_resp = await client.post(
            as_data["registration_endpoint"],
            json={
                "client_name": "E2E Verifier",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
            },
        )
        assert reg_resp.status_code == 201, f"DCR failed: {reg_resp.text}"
        client_id = reg_resp.json()["client_id"]

        verifier = secrets.token_urlsafe(32)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        state = secrets.token_hex(8)

        auth_get = await client.get(
            as_data["authorization_endpoint"],
            params={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_type": "code",
            },
        )
        assert auth_get.status_code == 200

        auth_post = await client.post(
            as_data["authorization_endpoint"],
            data={
                "pin": admin_pin,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert auth_post.status_code == 302, f"Authorize POST failed: {auth_post.text}"
        loc = auth_post.headers["location"]
        qs = parse_qs(urlparse(loc).query)
        assert qs.get("state") == [state]
        code = qs["code"][0]

        token_resp = await client.post(
            as_data["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        assert token_resp.status_code == 200, f"Token exchange failed: {token_resp.text}"
        tokens = token_resp.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        refresh_resp = await client.post(
            as_data["token_endpoint"],
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
        assert refresh_resp.status_code == 200, f"Token refresh failed: {refresh_resp.text}"
        access_token = refresh_resp.json()["access_token"]
        print("    OAuth 2.1 DCR + PKCE + Refresh token exchange succeeded.")

        mcp_url = f"{base_url}/mcp"
        mcp_headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

        print("==> [3/5] Sending MCP 'initialize' request ...")
        init_resp = await client.post(
            mcp_url,
            headers=mcp_headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "gemini-mcp-e2e-verifier", "version": "0.1.0"},
                },
            },
        )
        assert init_resp.status_code == 200, (
            f"MCP initialize failed ({init_resp.status_code}): {init_resp.text}"
        )
        session_id = init_resp.headers.get("mcp-session-id")
        if session_id:
            mcp_headers["Mcp-Session-Id"] = session_id

        init_data = parse_mcp_payload(init_resp)
        server_info = init_data.get("result", {}).get("serverInfo", {})
        print(f"    Connected to upstream MCP server: {server_info} (Session: {session_id})")

        # Send initialized notification
        await client.post(
            mcp_url,
            headers=mcp_headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

        print("==> [4/5] Requesting 'tools/list' ...")
        tools_resp = await client.post(
            mcp_url,
            headers=mcp_headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools_resp.status_code == 200, (
            f"MCP tools/list failed ({tools_resp.status_code}): {tools_resp.text}"
        )
        tools_data = parse_mcp_payload(tools_resp)
        tools = tools_data.get("result", {}).get("tools", [])
        tool_ByName = {t["name"]: t for t in tools if isinstance(t, dict) and "name" in t}
        print(f"    Retrieved {len(tool_ByName)} tools from GitHub MCP.")

        expected_sample = {"get_file_contents", "list_issues"}
        found_sample = expected_sample.intersection(tool_ByName.keys())
        assert found_sample, f"Expected GitHub tools not found in: {list(tool_ByName.keys())[:20]}"

        # Determine issue tool name and arguments
        if "get_issue" in tool_ByName:
            issue_tool = "get_issue"
            issue_args: dict[str, Any] = {
                "owner": owner,
                "repo": repo,
                "issue_number": issue_number,
            }
        elif "issue_read" in tool_ByName:
            issue_tool = "issue_read"
            issue_args = {
                "method": "get",
                "owner": owner,
                "repo": repo,
                "issue_number": issue_number,
            }
        else:
            raise RuntimeError(
                f"Neither 'get_issue' nor 'issue_read' found in tools: {sorted(tool_ByName.keys())}"
            )

        print(f"==> [5/5] Calling '{issue_tool}' for {owner}/{repo}#{issue_number} ...")
        call_resp = await client.post(
            mcp_url,
            headers=mcp_headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": issue_tool,
                    "arguments": issue_args,
                },
            },
        )
        assert call_resp.status_code == 200, (
            f"MCP tools/call failed ({call_resp.status_code}): {call_resp.text}"
        )
        call_data = parse_mcp_payload(call_resp)
        if "error" in call_data:
            raise RuntimeError(f"MCP tool error: {call_data['error']}")

        content_blocks = call_data.get("result", {}).get("content", [])
        text_blobs = [b.get("text", "") for b in content_blocks if isinstance(b, dict)]
        combined_text = "\n".join(text_blobs)

        issue_title = None
        issue_body = None
        issue_state = None
        for blob in text_blobs:
            try:
                parsed_issue = json.loads(blob)
                if isinstance(parsed_issue, dict) and "title" in parsed_issue:
                    issue_title = parsed_issue.get("title")
                    issue_body = parsed_issue.get("body")
                    issue_state = parsed_issue.get("state")
                    break
            except json.JSONDecodeError:
                continue

        print("\n============================================================")
        print("LIVE END-TO-END VERIFICATION PASSED!")
        print(f"Repository : {owner}/{repo}")
        print(f"Issue #    : {issue_number}")
        if issue_title:
            print(f"Title      : {issue_title}")
            print(f"State      : {issue_state}")
            if issue_body:
                summary = " ".join(str(issue_body).strip().splitlines())[:300]
                print(f"Summary    : {summary}")
        else:
            print(f"Raw Output : {combined_text[:500]}")
        print("============================================================")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify live Cloud Run GitHub MCP Proxy.")
    parser.add_argument(
        "--service-url",
        default=os.environ.get("SERVICE_URL", ""),
        help="Cloud Run base URL (or set SERVICE_URL)",
    )
    parser.add_argument(
        "--admin-pin",
        default=os.environ.get("ADMIN_PIN", ""),
        help="Admin PIN (or set ADMIN_PIN)",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("TEST_GITHUB_REPO", ""),
        help="GitHub repository URL or owner/repo (or set TEST_GITHUB_REPO)",
    )
    parser.add_argument(
        "--issue-number",
        type=int,
        default=int(os.environ.get("TEST_ISSUE_NUMBER", "1")),
        help="Issue number to fetch (or set TEST_ISSUE_NUMBER)",
    )
    args = parser.parse_args()

    if not args.service_url or not args.admin_pin or not args.repo:
        parser.error(
            "--service-url (SERVICE_URL), --admin-pin (ADMIN_PIN), and --repo (TEST_GITHUB_REPO) are required."
        )

    try:
        asyncio.run(
            run_verification(
                service_url=args.service_url,
                admin_pin=args.admin_pin,
                repo_str=args.repo,
                issue_number=args.issue_number,
            )
        )
    except Exception as exc:
        print(f"ERROR: Verification failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
