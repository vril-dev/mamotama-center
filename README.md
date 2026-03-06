# mamotama-center

Control plane for mamotama-edge.

`mamotama-center` is a single-binary service for:
- edge device enrollment
- heartbeat verification
- persistent device registry management

## Current Scope (0.1.x)

- `POST /v1/enroll`
  - header `X-License-Key` required
  - requires signed payload fields: `device_id`, `key_id`, `timestamp`, `nonce`, `body_hash`, `signature_b64`
  - registers `device_id -> (key_id, public_key)`
  - key rotation is rejected by default for existing `device_id`
  - set `X-Allow-Key-Rotation: true` to rotate key for existing `device_id`
  - rejects same public key registration under another `device_id`
- `POST /v1/heartbeat`
  - requires signed payload fields: `device_id`, `key_id`, `timestamp`, `nonce`, `body_hash`, `signature_b64`
  - verifies Ed25519 signature using enrolled public key
  - applies timestamp skew and replay checks (`timestamp` + `nonce`)
- `POST /v1/devices/{device_id}:revoke`
  - header `X-License-Key` required
  - revokes active key for the device (heartbeat is rejected until re-enroll)
- `GET /v1/devices`
  - returns device list with status flags
- `GET /v1/devices/{device_id}`
  - returns one device with status flags
- `POST /v1/devices/{device_id}:retire`
  - header `X-License-Key` required
  - marks a device as retired (heartbeat is rejected after retire)
- `GET /healthz`
- file-backed registry (`storage.path`) with atomic write

## Quick Start

1. Copy config:

```bash
cp center.config.example.json center.config.json
```

2. Edit `center.config.json`:
- set `auth.enrollment_license_keys` (16+ chars, one or more keys)
- keep `auth.require_tls=true` for production
- if TLS terminates at a trusted proxy/LB, set `auth.trust_forwarded_proto=true`
- set `storage.path` (persistent file path)
- optional: tune `heartbeat.max_clock_skew`
- optional: tune `heartbeat.expected_interval`
- optional: tune `heartbeat.missed_heartbeats_for_offline`
- optional: tune `heartbeat.stale_after`

3. Build and run:

```bash
make build
make run CONFIG=./center.config.json
```

Validation only:

```bash
make config-check CONFIG=./center.config.json
```

## Request Signature Format

Both `POST /v1/enroll` and `POST /v1/heartbeat` use:

1) `body_hash = sha256_hex(canonical_body_string)`

2) `signature_b64 = Base64(Ed25519Sign(private_key, envelope_message))`

envelope message:

```text
device_id + "\n" + key_id + "\n" + timestamp + "\n" + nonce + "\n" + body_hash
```

Canonical body strings:

`enroll`:

```text
device_id + "\n" + key_id + "\n" + public_key_pem_b64 + "\n" + public_key_fingerprint_sha256 + "\n" + timestamp + "\n" + nonce
```

`heartbeat`:

```text
device_id + "\n" + key_id + "\n" + timestamp + "\n" + nonce + "\n" + status_hash
```

## Device Status Flags

`GET /v1/devices` computes status by heartbeat age:

- `pending`: enrolled but no heartbeat yet (within offline threshold)
- `online`: heartbeat is within `heartbeat.expected_interval`
- `degraded`: heartbeat delay is over expected interval but below offline threshold
- `offline`: heartbeat delay exceeded `expected_interval * missed_heartbeats_for_offline`
- `stale`: heartbeat delay exceeded `heartbeat.stale_after`
- `retired`: device was retired via admin API

`degraded` / `offline` / `stale` / `retired` are returned with `flagged=true`.

## Re-enrollment Guardrails

- Existing `device_id` with different key:
  - default: `409 Conflict`
  - allow only with `X-Allow-Key-Rotation: true`
- Existing public key with another `device_id`:
  - always `409 Conflict`
- Re-enroll for retired `device_id`:
  - allowed with valid license key
  - response includes `reactivated=true`

## Build Targets

- `make build`
- `make run`
- `make config-check`
- `make check`

## Next Planned Features

- rule distribution API
- policy/version rollout control
- log ingest pipeline
- device management dashboard

## Related Project

`mamotama-edge`  
https://github.com/vril-dev/mamotama-edge
