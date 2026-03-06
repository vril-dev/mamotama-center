#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: center_revoke.sh <center_url> <device_id> [reason]" >&2
  exit 1
fi

center_url="$1"
device_id="$2"
reason="${3:-compromised}"

load_license_key() {
  if [ -n "${CENTER_LICENSE_KEY_FILE:-}" ]; then
    if [ ! -s "$CENTER_LICENSE_KEY_FILE" ]; then
      echo "license key file is missing or empty: $CENTER_LICENSE_KEY_FILE" >&2
      exit 1
    fi
    tr -d '\r\n' < "$CENTER_LICENSE_KEY_FILE"
    return
  fi

  if [ -n "${CENTER_LICENSE_KEY:-}" ]; then
    printf "%s" "$CENTER_LICENSE_KEY"
    return
  fi

  if [ -t 0 ]; then
    read -r -s -p "Center license key: " key
    echo >&2
    if [ -z "$key" ]; then
      echo "license key is empty" >&2
      exit 1
    fi
    printf "%s" "$key"
    return
  fi

  echo "license key is required (set CENTER_LICENSE_KEY_FILE, CENTER_LICENSE_KEY, or run interactively)" >&2
  exit 1
}

trimmed_center="${center_url%/}"
if [[ "$trimmed_center" != https://* ]]; then
  if [ "${CENTER_ALLOW_INSECURE_HTTP:-0}" != "1" ]; then
    echo "center_url must use https (set CENTER_ALLOW_INSECURE_HTTP=1 only for local dev)" >&2
    exit 1
  fi
fi
if [ -z "$device_id" ]; then
  echo "device_id is required" >&2
  exit 1
fi

license_key="$(load_license_key)"
revoke_url="${trimmed_center}/v1/devices/${device_id}:revoke"
reason_escaped="${reason//\\/\\\\}"
reason_escaped="${reason_escaped//\"/\\\"}"
payload="$(printf '{"reason":"%s"}' "$reason_escaped")"

curl -fsS \
  -X POST "$revoke_url" \
  -H "Content-Type: application/json" \
  -H "X-License-Key: $license_key" \
  --data "$payload"

echo
echo "device key revoke request sent for device_id=$device_id"
