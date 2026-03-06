#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  echo "usage: center_policy_download.sh <center_url> <device_id> [state] [output_file]" >&2
  exit 1
fi

center_url="$1"
device_id="$2"
state="${3:-desired}"
output_file="${4:-}"
format="${POLICY_FORMAT:-raw}"

load_admin_api_key() {
  if [ -n "${CENTER_ADMIN_API_KEY_FILE:-}" ]; then
    if [ ! -s "$CENTER_ADMIN_API_KEY_FILE" ]; then
      echo "admin api key file is missing or empty: $CENTER_ADMIN_API_KEY_FILE" >&2
      exit 1
    fi
    tr -d '\r\n' < "$CENTER_ADMIN_API_KEY_FILE"
    return
  fi

  if [ -n "${CENTER_ADMIN_API_KEY:-}" ]; then
    printf "%s" "$CENTER_ADMIN_API_KEY"
    return
  fi

  if [ -t 0 ]; then
    read -r -s -p "Center admin api key: " key
    echo >&2
    if [ -z "$key" ]; then
      echo "admin api key is empty" >&2
      exit 1
    fi
    printf "%s" "$key"
    return
  fi

  echo "admin api key is required (set CENTER_ADMIN_API_KEY_FILE, CENTER_ADMIN_API_KEY, or run interactively)" >&2
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

state="$(echo "$state" | tr '[:upper:]' '[:lower:]')"
if [ "$state" != "desired" ] && [ "$state" != "current" ]; then
  echo "state must be desired or current" >&2
  exit 1
fi

format="$(echo "$format" | tr '[:upper:]' '[:lower:]')"
if [ "$format" != "raw" ] && [ "$format" != "json" ]; then
  echo "POLICY_FORMAT must be raw or json" >&2
  exit 1
fi

if [ -z "$output_file" ]; then
  ext="waf"
  if [ "$format" = "json" ]; then
    ext="json"
  fi
  output_file="${device_id}-${state}.${ext}"
fi

admin_api_key="$(load_admin_api_key)"
url="${trimmed_center}/v1/devices/${device_id}:download-policy?state=${state}&format=${format}"

curl -fsS \
  -X GET "$url" \
  -H "X-API-Key: $admin_api_key" \
  -o "$output_file"

echo "policy downloaded: ${output_file}"
