# mamotama-center

Control plane for mamotama-edge.

`mamotama-center` is a single-binary service for:
- edge device enrollment
- heartbeat verification
- persistent device registry management

## Current Scope (0.1.x)

- `POST /v1/enroll`
  - header `X-License-Key` required
  - registers `device_id` + edge public key
  - key rotation is rejected by default for existing `device_id`
  - set `X-Allow-Key-Rotation: true` to rotate key for existing `device_id`
  - rejects same public key registration under another `device_id`
- `POST /v1/heartbeat`
  - verifies Ed25519 signature using enrolled public key
  - applies timestamp skew and replay checks
- `GET /v1/devices`
  - returns device list with status flags
- `GET /v1/devices/{device_id}`
  - returns one device with status flags
- `GET /healthz`
- file-backed registry (`storage.path`) with atomic write

## Quick Start

1. Copy config:

```bash
cp center.config.example.json center.config.json
```

2. Edit `center.config.json`:
- set `auth.enrollment_license_keys` (16+ chars, one or more keys)
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

## Heartbeat Signature Format

Edge signs this message with its private key:

```text
device_id + "\n" + timestamp + "\n" + nonce + "\n" + status_hash
```

`signature_b64` is Base64(Ed25519 signature bytes).

## Device Status Flags

`GET /v1/devices` computes status by heartbeat age:

- `pending`: enrolled but no heartbeat yet (within offline threshold)
- `online`: heartbeat is within `heartbeat.expected_interval`
- `degraded`: heartbeat delay is over expected interval but below offline threshold
- `offline`: heartbeat delay exceeded `expected_interval * missed_heartbeats_for_offline`
- `stale`: heartbeat delay exceeded `heartbeat.stale_after`

`degraded` / `offline` / `stale` are returned with `flagged=true`.

## Re-enrollment Guardrails

- Existing `device_id` with different key:
  - default: `409 Conflict`
  - allow only with `X-Allow-Key-Rotation: true`
- Existing public key with another `device_id`:
  - always `409 Conflict`

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
