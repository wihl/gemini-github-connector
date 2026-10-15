# Gemini GitHub MCP Proxy (`gemini-github-mcp-proxy`)

A standalone, serverless **GitHub MCP Proxy** for Google Cloud Run that bridges Google Gemini's Custom Apps connector (`gemini.google.com` and Gemini Mobile) with GitHub's official remote MCP server (`https://api.githubcopilot.com/mcp/`).

## Features

- **RFC 9728 Protected Resource Metadata**: `GET /.well-known/oauth-protected-resource`
- **RFC 8414 Authorization Server Metadata**: `GET /.well-known/oauth-authorization-server`
- **RFC 7591 Dynamic Client Registration (DCR)**: `POST /register` (zero-config setup in Gemini without manually entering a Client ID/Secret)
- **Stateless OAuth 2.1 + PKCE (`S256`) + Refresh Tokens**:
  - `GET /authorize` & `POST /authorize` protected by an `ADMIN_PIN` stored in GCP Secret Manager
  - `POST /token` issuing stateless HMAC-SHA256 (`SIGNING_SECRET`) access and refresh tokens (`expires_in: 315360000`)
- **Streamable HTTP MCP Proxy (`/mcp`)**:
  - Validates the proxy Bearer token and returns `401 Unauthorized` with `WWW-Authenticate` discovery metadata when unauthenticated
  - Strips the proxy JWT and injects `Authorization: Bearer <GITHUB_PAT>` for upstream requests to `https://api.githubcopilot.com/mcp/`
  - Supports both `application/json` and `text/event-stream` (SSE) responses

## Local Development & Testing

```bash
uv sync
uv run pytest -v
```

## Deployment to Google Cloud Run

Ensure `gcloud` is authenticated with an active project and `gh auth token` returns a valid GitHub Personal Access Token with `repo` scope:

```bash
./scripts/deploy.sh
```

## Live End-to-End Verification

```bash
SERVICE_URL="https://<your-cloud-run-url>" \
ADMIN_PIN="<your-admin-pin>" \
TEST_GITHUB_REPO="owner/repo" \
TEST_ISSUE_NUMBER="1" \
uv run python scripts/verify_live.py
```
