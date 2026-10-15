#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-gemini-github-mcp-proxy}"
REGION="${REGION:-us-east1}"

echo "==> [1/6] Checking gcloud authentication and active project..."
ACTIVE_ACCOUNT="$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" | head -n 1)"
if [[ -z "${ACTIVE_ACCOUNT}" ]]; then
  echo "ERROR: No active gcloud account found. Run 'gcloud auth login'." >&2
  exit 1
fi

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "(unset)" ]]; then
  echo "ERROR: No GCP project configured. Set GCP_PROJECT_ID or run 'gcloud config set project <id>'." >&2
  exit 1
fi
echo "    Active GCP Project: ${PROJECT_ID}"

echo "==> [2/6] Obtaining and verifying GitHub token..."
GITHUB_PAT="${GITHUB_PAT:-$(gh auth token)}"
if [[ -z "${GITHUB_PAT}" ]]; then
  echo "ERROR: Could not obtain GITHUB_PAT from environment or 'gh auth token'." >&2
  exit 1
fi

GH_HEADERS="$(curl -sSI -H "Authorization: Bearer ${GITHUB_PAT}" https://api.github.com/user)"
GH_STATUS="$(echo "${GH_HEADERS}" | head -n 1 | awk '{print $2}')"
if [[ "${GH_STATUS}" != "200" ]]; then
  echo "ERROR: GitHub token validation failed with HTTP status ${GH_STATUS}." >&2
  exit 1
fi

GH_SCOPES="$(echo "${GH_HEADERS}" | grep -i '^x-oauth-scopes:' || true)"
if [[ -n "${GH_SCOPES}" ]] && ! echo "${GH_SCOPES}" | grep -qi 'repo'; then
  echo "ERROR: GitHub token is missing required 'repo' scope (${GH_SCOPES})." >&2
  exit 1
fi
echo "    GitHub token verified (${GH_SCOPES:-fine-grained PAT})."

echo "==> [3/6] Enabling required GCP APIs..."
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  --project="${PROJECT_ID}" \
  --quiet

echo "==> [4/6] Preparing secrets in Secret Manager..."
upsert_secret() {
  local secret_name="$1"
  local secret_value="$2"

  if ! gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud secrets create "${secret_name}" \
      --replication-policy="automatic" \
      --project="${PROJECT_ID}" \
      --quiet
  fi

  printf "%s" "${secret_value}" | gcloud secrets versions add "${secret_name}" \
    --data-file=- \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
}

get_or_create_secret() {
  local secret_name="$1"
  local default_value="$2"
  local existing=""

  if gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    existing="$(gcloud secrets versions access latest --secret="${secret_name}" --project="${PROJECT_ID}" 2>/dev/null || true)"
  fi

  if [[ -n "${existing}" && "${FORCE_ROTATE_SECRETS:-0}" != "1" ]]; then
    printf "%s" "${existing}"
  else
    upsert_secret "${secret_name}" "${default_value}"
    printf "%s" "${default_value}"
  fi
}

upsert_secret "gemini-mcp-github-pat" "${GITHUB_PAT}"

GENERATED_SECRET="$(openssl rand -hex 32)"
SIGNING_SECRET="${SIGNING_SECRET:-$(get_or_create_secret "gemini-mcp-signing-secret" "${GENERATED_SECRET}")}"

GENERATED_PIN="$(python3 -c 'import secrets; print(f"{secrets.randbelow(900000) + 100000:06d}")')"
ADMIN_PIN="${ADMIN_PIN:-$(get_or_create_secret "gemini-mcp-admin-pin" "${GENERATED_PIN}")}"

echo "==> [5/6] Granting Secret Manager access to Cloud Run runtime service account..."
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")"
RUNTIME_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

for secret_name in gemini-mcp-github-pat gemini-mcp-admin-pin gemini-mcp-signing-secret; do
  gcloud secrets add-iam-policy-binding "${secret_name}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
done

echo "==> [6/6] Deploying ${SERVICE_NAME} to Cloud Run (${REGION})..."
gcloud run deploy "${SERVICE_NAME}" \
  --source . \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --platform=managed \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=3 \
  --memory=512Mi \
  --timeout=300 \
  --set-secrets="GITHUB_PAT=gemini-mcp-github-pat:latest,ADMIN_PIN=gemini-mcp-admin-pin:latest,SIGNING_SECRET=gemini-mcp-signing-secret:latest" \
  --quiet

SERVICE_URL="$(gcloud run services describe "${SERVICE_NAME}" --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)")"
echo ""
echo "============================================================"
echo "Deployment Complete!"
echo "Service URL: ${SERVICE_URL}"
echo "MCP Endpoint: ${SERVICE_URL}/mcp"
echo "============================================================"
