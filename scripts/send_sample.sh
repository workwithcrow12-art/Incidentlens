#!/usr/bin/env bash
# Gửi 3 cảnh báo mẫu tới server đang chạy, xem sự cố vừa mở, rồi tạo digest ngay.
set -euo pipefail
URL="${URL:-http://localhost:8000}"
AUTH=()
if [[ -n "${IL_WEBHOOK_TOKEN:-}" ]]; then AUTH=(-H "Authorization: Bearer ${IL_WEBHOOK_TOKEN}"); fi

echo "== Gửi cảnh báo";  curl -sS -X POST "$URL/webhooks/alertmanager" "${AUTH[@]}" \
  -H "Content-Type: application/json" --data @examples/alertmanager_payload.json; echo
sleep 1
echo "== Sự cố đã mở";   curl -sS "$URL/incidents" "${AUTH[@]}"; echo
echo "== Tạo digest";    curl -sS -X POST "$URL/digest/run" "${AUTH[@]}"; echo
