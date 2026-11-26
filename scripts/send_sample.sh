#!/usr/bin/env bash
# Send 3 sample alerts to a running server, list open incidents, and trigger a digest immediately.
set -euo pipefail
URL="${URL:-http://localhost:8000}"
AUTH=()
if [[ -n "${IL_WEBHOOK_TOKEN:-}" ]]; then AUTH=(-H "Authorization: Bearer ${IL_WEBHOOK_TOKEN}"); fi

echo "== Sending sample alerts";  curl -sS -X POST "$URL/webhooks/alertmanager" "${AUTH[@]}" \
  -H "Content-Type: application/json" --data @examples/alertmanager_payload.json; echo
sleep 1
echo "== Open incidents";         curl -sS "$URL/incidents" "${AUTH[@]}"; echo
echo "== Running digest";         curl -sS -X POST "$URL/digest/run" "${AUTH[@]}"; echo
