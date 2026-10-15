# Agent Task: Build & Deploy a Bulletproof Personal GitHub MCP Proxy for Gemini Mobile/Web

## Objective
Build, test, and deploy a standalone, serverless **GitHub MCP Proxy** (`gemini-github-mcp-proxy`) to Google Cloud Run.

### Context & Why This Exists
Google Gemini's "Custom apps" connector (`gemini.google.com` -> Settings -> Connected Apps -> Custom apps, which syncs to the iOS Gemini mobile app via `@`) requires remote MCP servers to implement the full MCP Authorization Specification:
1. **RFC 9728** (`/.well-known/oauth-protected-resource`)
2. **RFC 8414** (`/.well-known/oauth-authorization-server`)
3. **RFC 7591 Dynamic Client Registration (DCR)** (`POST /register`)
4. **OAuth 2.1 Authorization Code + PKCE + Refresh Token flows** (`GET /authorize`, `POST /token`) returning strict `application/json` responses with non-expiring or seamlessly refreshing tokens.
5. **MCP Streamable HTTP transport** (`POST /mcp`, `GET /mcp`, `DELETE /mcp`).

GitHub's official remote MCP server (`https://api.githubcopilot.com/mcp/`) does **not** support Dynamic Client Registration and its OAuth apps do not issue standard OIDC refresh tokens by default, causing Gemini Web/Mobile to silently drop or disable the custom app after ~24 hours.

Your job is to build and deploy a **stateless Cloud Run proxy** that:
1. Implements a compliant, zero-friction OAuth 2.1 + DCR layer facing Gemini (so I don't need to open "Advanced Settings" or enter a Client ID/Secret when adding the Custom App in Gemini).
2. Protects the `/authorize` screen with a single `ADMIN_PIN` (stored in GCP Secret Manager) so only I can authorize Gemini to connect.
3. Issues **stateless HMAC-SHA256 signed tokens** (derived from `SIGNING_SECRET` in Secret Manager) so **zero database is required** and Cloud Run container restarts or scale-to-zero events never invalidate Gemini's access or refresh tokens.
4. Proxies all `/mcp` Streamable HTTP requests directly to `https://api.githubcopilot.com/mcp/`, stripping the proxy's JWT and injecting `Authorization: Bearer <GITHUB_PAT>` from GCP Secret Manager.

---

## Execution Rules
1. **Work autonomously end-to-end.** Create the git repository, write all code and tests, run local container validation, provision GCP resources, deploy to Cloud Run, and run live E2E verification against the deployed Cloud Run URL.
2. **Only pause to ask me for input** if you cannot discover my `GCP_PROJECT_ID` from `gcloud config get-value project` or my `GITHUB_PAT` from `gh auth token` / environment variables.
3. **Use `uv` for Python dependency management** (`Python 3.12+`) and a multi-stage `Dockerfile` for a fast, hermetic Linux build.

---

## Architecture & Technical Specifications

### 1. Repository Setup
- Create a new directory and Git repository: `~/dev/gemini-github-mcp-proxy` (or in the current working directory if already inside an empty repo folder).
- Initialize with `uv init` (Python 3.12), `FastAPI`, `uvicorn`, `httpx[http2]`, `pyjwt`, `python-multipart`, and dev dependencies `pytest`, `pytest-asyncio`, and `respx`.

### 2. Stateless OAuth 2.1 + DCR Engine (`app/oauth.py`)
Implement full compatibility with Gemini's MCP OAuth client:
- **Dynamic Host Resolution:** Always determine `<base_url>` from `X-Forwarded-Proto` (defaulting to `https` on Cloud Run) and `Host` headers.
- **`GET /.well-known/oauth-protected-resource`** and **`GET /.well-known/oauth-protected-resource/mcp`**:
  Return RFC 9728 JSON:
    {
      "resource": "<base_url>/mcp",
      "authorization_servers": ["<base_url>"],
      "bearer_methods_supported": ["header"]
    }
- **`GET /.well-known/oauth-authorization-server`**:
  Return RFC 8414 metadata:
    {
      "issuer": "<base_url>",
      "authorization_endpoint": "<base_url>/authorize",
      "token_endpoint": "<base_url>/token",
      "registration_endpoint": "<base_url>/register",
      "response_types_supported": ["code"],
      "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
      "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
      "code_challenge_methods_supported": ["S256", "plain"]
    }
- **`POST /register` (Dynamic Client Registration - RFC 7591)**:
  Accept any JSON registration payload from Google/Gemini. Generate a stateless `client_id` and `client_secret` and return HTTP `201 Created` echoing `redirect_uris`, `grant_types`, `client_id`, `client_secret`, and `client_secret_expires_at: 0`.
- **`GET /authorize` & `POST /authorize`**:
  - Render a clean, mobile-friendly HTML page asking for `ADMIN_PIN` (password input + "Approve Gemini Access" button).
  - Preserve `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`, and `scope` as hidden form fields.
  - On `POST /authorize`, verify `ADMIN_PIN` using `hmac.compare_digest`. If valid, generate a stateless JWT authorization `code` signed with `SIGNING_SECRET` encoding `{client_id, redirect_uri, code_challenge, code_challenge_method, exp: now + 600}` and return HTTP `302 Found` redirecting to `redirect_uri?code=<code>&state=<state>`.
- **`POST /token`**:
  Accept both `application/x-www-form-urlencoded` and `application/json` bodies (and accept any `client_secret_basic` Authorization header).
  - For `grant_type == "authorization_code"`:
    - Verify the JWT `code`.
    - If `code_challenge` was present in the `code` and `code_verifier` is provided, verify PKCE (`S256` -> `BASE64URL-ENCODE(SHA256(verifier)) == challenge`).
    - Issue a stateless JWT `access_token` (`exp: now + 315360000`, 10 years) and a stateless JWT `refresh_token` (`exp: now + 315360000`).
  - For `grant_type == "refresh_token"`:
    - Verify the JWT `refresh_token` and issue a fresh `access_token` and `refresh_token`.
  - Always return strict `application/json` with headers `Cache-Control: no-store` and `Pragma: no-cache`:
    {
      "access_token": "<signed_jwt>",
      "token_type": "Bearer",
      "expires_in": 315360000,
      "refresh_token": "<signed_refresh_jwt>",
      "scope": "repo read:org gist project issues pull_requests"
    }

### 3. Streamable HTTP MCP Proxy (`app/mcp_proxy.py`)
- Expose `/mcp` and `/mcp/` supporting `POST`, `GET`, `DELETE`, and `OPTIONS` (with permissive CORS headers and exposed `Mcp-Session-Id` header).
- **Authentication check:**
  - Validate `Authorization: Bearer <token>` using `SIGNING_SECRET`.
  - If missing or invalid, return `HTTP 401 Unauthorized` with the exact header required by the MCP spec so Gemini automatically triggers OAuth discovery:
    `WWW-Authenticate: Bearer resource_metadata="<base_url>/.well-known/oauth-protected-resource"`
- **Upstream Forwarding to GitHub MCP (`https://api.githubcopilot.com/mcp/`)**:
  - Use a shared async `httpx.AsyncClient(http2=True, timeout=120.0)`.
  - Forward the request method, body, and relevant MCP headers (`Content-Type`, `Accept`, `Mcp-Session-Id`, `Last-Event-ID`, `Mcp-Protocol-Version`).
  - Replace the incoming `Authorization` header with `Authorization: Bearer <GITHUB_PAT>`.
  - Support both `application/json` responses and streaming `text/event-stream` (SSE) responses using `StreamingResponse`, preserving upstream status codes and `Mcp-Session-Id` response headers.
- **Health Check:**
  - Expose `GET /healthz` returning `200 OK` (`{"status": "ok"}`) and verifying that `GITHUB_PAT`, `ADMIN_PIN`, and `SIGNING_SECRET` are loaded.

---

## Step-by-Step Verification & Deployment Plan

### Phase 1: Local Automated Tests (`pytest`)
Write and run `tests/test_proxy.py` validating:
1. `GET /.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server` return valid HTTPS URLs when `X-Forwarded-Proto: https` is passed.
2. Unauthenticated `POST /mcp` returns `401` with a valid `WWW-Authenticate` header.
3. Full OAuth 2.1 DCR + PKCE (`S256`) flow: `POST /register` -> `GET /authorize` -> `POST /authorize` (with `ADMIN_PIN`) -> `POST /token` (with `code_verifier`) -> `POST /token` (with `grant_type=refresh_token`).
4. Authenticated `POST /mcp` (`initialize` and `tools/list` JSON-RPC 2.0 payloads) strips the proxy token and sends `Authorization: Bearer <GITHUB_PAT>` to the mocked upstream `https://api.githubcopilot.com/mcp/`.

### Phase 2: Hermetic Container Build (`Dockerfile`)
Create a multi-stage `Dockerfile` using `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` that compiles bytecode (`UV_COMPILE_BYTECODE=1`), runs `uv sync --locked --no-dev`, runs as a non-root user, and binds `uvicorn` to `0.0.0.0:${PORT:-8080}`.

### Phase 3: GCP Provisioning & Cloud Run Deployment (`scripts/deploy.sh`)
Write an idempotent deployment script `scripts/deploy.sh` and execute it:
1. Check `gcloud auth list` and current GCP project (`gcloud config get-value project`).
2. Obtain the GitHub token from `gh auth token` (verify it has `repo` scope via `https://api.github.com/user`).
3. Generate a strong random 32-byte hex `SIGNING_SECRET` and a 6-digit `ADMIN_PIN`.
4. Enable required GCP APIs: `run.googleapis.com`, `secretmanager.googleapis.com`, `cloudbuild.googleapis.com`, `artifactregistry.googleapis.com`.
5. Create/update secrets in **Google Cloud Secret Manager** (`gemini-mcp-github-pat`, `gemini-mcp-admin-pin`, `gemini-mcp-signing-secret`) and grant the Cloud Run runtime service account `roles/secretmanager.secretAccessor`.
6. Deploy to Cloud Run in `us-east1` with `--allow-unauthenticated`, `--min-instances 0`, `--max-instances 3`, `--memory 512Mi`, `--timeout 300`, and `--set-secrets` bound to the three secrets.

### Phase 4: Live End-to-End Smoke Test Against a private repo
Write and run `scripts/verify_live.py` against the deployed `https://gemini-github-mcp-<hash>.run.app` URL that:
1. Executes the full OAuth flow (`/.well-known/*` -> `/register` -> `/authorize` -> `/token`) against the live Cloud Run URL.
2. Sends a real MCP `initialize` request to `https://<cloud-run-url>/mcp` using the issued proxy JWT.
3. Sends a real MCP `tools/list` request and confirms GitHub tools (`get_issue`, `list_issues`, `get_file_contents`, etc.) are returned.
4. Calls `tools/call` for `get_issue` on a private repo TEST_GITHUB_REPO (Issue `#<TEST_ISSUE_NUMBER`) through the live Cloud Run proxy and prints the retrieved issue title to prove end-to-end private repo access works.

### Phase 5: Final Output
Once Phase 4 passes 100%, print a summary box with:
1. **Custom App MCP URL for Gemini (`gemini.google.com/apps`)**: `https://<cloud-run-url>/mcp`
2. **My `ADMIN_PIN`** to enter once on the consent screen (leaving Gemini's "Advanced Settings / OAuth Client ID" blank).
3. Confirmation of the title and summary of Issue #TEST_ISSUE_NUMBER from TEST_GITHUB_REPO.
