# mamotama-center (日本語)

`mamotama-edge` 向けのコントロールプレーンです。

[English](README.md) | [日本語](README.ja.md)

`mamotama-center` は単一バイナリで動作し、主に次を提供します。
- edge 端末登録
- heartbeat 検証
- 永続的な端末レジストリ管理

## 現在のスコープ (0.2.x)

- `POST /v1/enroll`
  - ヘッダー `X-License-Key` 必須
  - 署名付きペイロード項目 `device_id`, `key_id`, `timestamp`, `nonce`, `body_hash`, `signature_b64` が必要
  - `device_id -> (key_id, public_key)` を登録
  - 既存 `device_id` の鍵ローテーションは既定で拒否
  - `X-Allow-Key-Rotation: true` で既存 `device_id` の鍵ローテーションを許可
  - 同一公開鍵を別 `device_id` で登録する操作は拒否
- `POST /v1/heartbeat`
  - 署名付きペイロード項目 `device_id`, `key_id`, `timestamp`, `nonce`, `body_hash`, `signature_b64` が必要
  - 登録済み公開鍵で Ed25519 署名を検証
  - timestamp skew とリプレイ (`timestamp` + `nonce`) を検証
  - edge 報告の `current_policy_version`, `current_policy_sha256` を受理
  - desired/current の policy 状態と release 状態、`update_required` を返却
- `GET /v1/policies`
  - ヘッダー `X-API-Key` 必須
  - ポリシーバージョン一覧と desired/current 使用状況サマリを返却
- `POST /v1/policies`
  - ヘッダー `X-API-Key` 必須
  - 不変な policy version ペイロード（`version`, `waf_raw` または `waf_raw_template`, 任意 `waf_rule_files`, `sha256`, `bundle_tgz_b64`, `bundle_sha256`, `note`）を `draft` として upsert
  - `waf_raw_template=bundle_default` で bundle から `waf_raw` を生成（`${MAMOTAMA_POLICY_ACTIVE}/...`）
- `POST /v1/policies:inspect-bundle`
  - ヘッダー `X-API-Key` 必須
  - bundle を解析し `.conf` 一覧と template 用の推奨デフォルトを返却
- `POST /v1/policies/{version}:approve`
  - ヘッダー `X-API-Key` 必須
  - policy を `approved` に遷移（assign 前提）
- `GET /v1/releases`
  - ヘッダー `X-API-Key` 必須
  - release バージョン一覧と desired/current 使用状況サマリを返却
- `POST /v1/releases`
  - ヘッダー `X-API-Key` 必須
  - 不変な release ペイロード（`version`, `platform`, `binary_b64`, 任意 `sha256`, `note`）を `draft` として upsert
- `POST /v1/releases/{version}:approve`
  - ヘッダー `X-API-Key` 必須
  - release を `approved` に遷移（assign 前提）
- `GET /v1/releases/{version}`
  - ヘッダー `X-API-Key` 必須
  - 単一 release と端末使用カウンタを返却
- `PUT /v1/releases/{version}`
  - ヘッダー `X-API-Key` 必須
  - release 内容を `draft` として上書き（未使用時のみ）
- `DELETE /v1/releases/{version}`
  - ヘッダー `X-API-Key` 必須
  - release を削除（未使用時のみ）
- `GET /v1/policies/{version}`
  - ヘッダー `X-API-Key` 必須
  - 単一 policy と端末使用カウンタを返却
- `PUT /v1/policies/{version}`
  - ヘッダー `X-API-Key` 必須
  - policy 内容を `draft` として上書き（未使用時のみ、任意 bundle 更新 / template 生成を含む）
- `DELETE /v1/policies/{version}`
  - ヘッダー `X-API-Key` 必須
  - policy を削除（未使用時のみ）
- `POST /v1/devices/{device_id}:assign-policy`
  - ヘッダー `X-API-Key` 必須
  - 端末の desired policy version を設定（`approved` policy のみ）
- `POST /v1/devices/{device_id}:assign-release`
  - ヘッダー `X-API-Key` 必須
  - 端末の desired release version を設定（`approved` release のみ）
  - 任意 `apply_at`（RFC3339）で `update_required=true` の返却開始時刻を遅延可能
- `GET /v1/devices/{device_id}:download-policy`
  - ヘッダー `X-API-Key` 必須
  - 端末 policy ルールをダウンロード（`state=desired|current`, `format=raw|json`）
- `POST /v1/policy/pull`
  - 署名付き edge リクエストで、更新必要時に割り当て policy を取得（`waf_raw` + 任意 bundle）
- `POST /v1/policy/ack`
  - 署名付き edge リクエストで、`applied|failed|rolled_back` を報告
- `POST /v1/release/pull`
  - 署名付き edge リクエストで、更新必要時に割り当て release を取得（`platform`, `sha256`, `binary_b64`）
- `POST /v1/release/ack`
  - 署名付き edge リクエストで、release 適用結果 `applied|failed` を報告
- `POST /v1/logs/push`
  - 署名付き edge リクエストで、gzip 圧縮 NDJSON ログバッチをアップロード
- `POST /v1/reputation/pull`
  - 署名付き edge リクエストで、直近 security ログから生成した shared reputation feed を取得
- `POST /v1/devices/{device_id}:revoke`
  - ヘッダー `X-API-Key` 必須
  - 端末のアクティブ鍵を失効（再 enroll まで heartbeat 拒否）
- `GET /v1/devices`
  - ヘッダー `X-API-Key` 必須
  - ステータスフラグ付き端末一覧を返却
- `GET /v1/devices/{device_id}`
  - ヘッダー `X-API-Key` 必須
  - ステータスフラグ付き端末詳細を返却
- `POST /v1/devices/{device_id}:retire`
  - ヘッダー `X-API-Key` 必須
  - 端末を retired に設定（以後 heartbeat 拒否）
- `GET /v1/admin/logs/devices`
  - ヘッダー `X-API-Key` 必須
  - ログバッチが存在する端末一覧を返却
- `GET /v1/admin/logs`
  - ヘッダー `X-API-Key` 必須
  - `device_id` 単位で `from/to/cursor/limit/kind/level` を指定してログ検索
- `GET /v1/admin/logs/summary`
  - ヘッダー `X-API-Key` 必須
  - 任意 `device_id` / `from` / `to` / `kind` / `level` でログ集計
- `GET /v1/admin/logs/download`
  - ヘッダー `X-API-Key` 必須
  - フィルタ済みログを NDJSON でダウンロード（任意 `gzip=1`）
- `GET /v1/admin/metrics`
  - ヘッダー `X-API-Key` 必須
  - devices / policies / releases / log devices / reputation summary を Prometheus 形式で出力
- `GET /admin/logs`
  - TLS 前提の最小管理ページ（ログ端末一覧、集計、検索、ダウンロード）
- `GET /admin/devices`
  - TLS 前提の最小管理ページ（端末一覧、policy 操作）
  - bundle `.conf` 検査/選択、選択端末 `rule_files` 差分（current/desired/target）を表示
  - placeholder 展開プレビュー（`${MAMOTAMA_POLICY_ACTIVE}` / `${POLICY_ACTIVE_LINK}`）
  - `Policy Active Base` のプレビュー値を端末別に localStorage へ保存
  - 端末別 `Policy Active Base` マップの JSON export/import をサポート
  - profile ベースの base-map 切り替え（例: staging / production）をサポート
  - profile 間 base-map 差分を端末キー単位で表示
  - 差分フィルタ（all / changed-only / missing-in-current / missing-in-compare）をサポート
  - 差分テーブルで検索/ソートをサポート
  - edge ログ由来の upstream backend health（healthy/unhealthy、endpoint、失敗回数、最終遷移）を可視化
- `GET /healthz`
- 原子的書き込みによる file-backed レジストリ（`storage.path`）

`POST /v1/reputation/pull` が返す blocklist は、直近 `kind=security` ログの重み付きスコアを元に生成します。同一 IP が複数 edge で観測された場合は追加ボーナスが入り、fleet 共有の精度を高めます。

## 管理 UI スクリーンショット

`/admin/devices`:

![center admin devices](docs/images/center_admin_devices.png)

`/admin/logs`:

![center admin logs](docs/images/center_admin_logs.png)

## クイックスタート

1. 設定ファイルをコピー

```bash
cp center.config.example.json center.config.json
```

2. `center.config.json` を編集
- `auth.enrollment_license_keys` を設定（16文字以上、1つ以上）
- `auth.admin_read_api_keys` を設定（16文字以上、read/download/list API 用）
- `auth.admin_write_api_keys` を設定（16文字以上、write/mutate API 用）
- 後方互換として任意で `auth.admin_api_keys` も設定可能（write スコープ扱い）
- 本番は `auth.require_tls=true` を維持
- TLS 終端が信頼できる proxy/LB 側にある場合は `auth.trust_forwarded_proto=true` を設定
- リプレイ制御 `auth.nonce_ttl`, `auth.max_nonces_per_device` を調整
- `storage.path`（永続ファイルパス）を設定
- `storage.backend`（`file` または `sqlite`、既定 `file`）を設定
- `storage.sqlite_path`（DB init/check/migrate 用 SQLite パス）を設定
- 任意で `storage.log_retention` を設定（既定 `720h` = 30日、`0` で期限削除無効）
- 任意で `storage.log_max_bytes` を設定（既定 `5368709120` = 5 GiB、`0` で容量削除無効）
- 任意で `server.max_header_bytes`, `server.max_concurrent_requests` を調整
- 任意で `runtime.gomaxprocs`, `runtime.memory_limit_mb` を調整
- 任意で `heartbeat.max_clock_skew` を調整
- 任意で `heartbeat.expected_interval` を調整
- 任意で `heartbeat.missed_heartbeats_for_offline` を調整
- 任意で `heartbeat.stale_after` を調整

3. ビルドして起動

```bash
make build
make run CONFIG=./center.config.json
```

設定検証のみ:

```bash
make config-check CONFIG=./center.config.json
```

SQLite スキーマ管理:

```bash
make db-init CONFIG=./center.config.json
make db-check CONFIG=./center.config.json
make db-migrate CONFIG=./center.config.json
```

ストア移行（双方向）:

```bash
make db-file-to-sqlite CONFIG=./center.config.json
make db-sqlite-to-file CONFIG=./center.config.json
# 出力先上書きを許可
make db-file-to-sqlite CONFIG=./center.config.json OVERWRITE=1
```

## リクエスト署名フォーマット

`POST /v1/enroll` と `POST /v1/heartbeat` は共通で次を使用します。

1) `body_hash = sha256_hex(canonical_body_string)`

2) `signature_b64 = Base64(Ed25519Sign(private_key, envelope_message))`

envelope message:

```text
device_id + "\n" + key_id + "\n" + timestamp + "\n" + nonce + "\n" + body_hash
```

canonical body string:

`enroll`:

```text
device_id + "\n" + key_id + "\n" + public_key_pem_b64 + "\n" + public_key_fingerprint_sha256 + "\n" + timestamp + "\n" + nonce
```

`heartbeat`:

```text
device_id + "\n" + key_id + "\n" + timestamp + "\n" + nonce + "\n" + status_hash + "\n" + current_policy_version + "\n" + current_policy_sha256
```

## 端末ステータスフラグ

`GET /v1/devices` は heartbeat 経過時間からステータスを計算します。

- `pending`: enroll 済みだが heartbeat 未到達（offline 閾値以内）
- `online`: heartbeat が `heartbeat.expected_interval` 以内
- `degraded`: expected_interval 超過かつ offline 閾値未満
- `offline`: `expected_interval * missed_heartbeats_for_offline` を超過
- `stale`: `heartbeat.stale_after` を超過
- `retired`: 管理 API で retired 済み

`degraded` / `offline` / `stale` / `retired` は `flagged=true` で返却されます。

## ログ保持

- `POST /v1/logs/push` で受けたログバッチは `<storage.path dir>/logs/<device_id>/` に保存
- 削除（pruning）は各ログ push 時に自動実行
- 削除順序:
  - 先に `storage.log_retention` より古いファイルを削除
  - その後、合計サイズが `storage.log_max_bytes` を超える場合は古い順に削除（最新バッチは保持）

## Admin API キースコープ

- read スコープ:
  - `GET /v1/policies`, `GET /v1/policies/{version}`
  - `GET /v1/devices`, `GET /v1/devices/{device_id}`
  - `GET /v1/admin/logs/*`
  - `GET /v1/devices/{device_id}:download-policy`
- write スコープ:
  - `POST /v1/policies`
  - `POST /v1/policies/{version}:approve`
  - `PUT /v1/policies/{version}`
  - `DELETE /v1/policies/{version}`
  - `POST /v1/devices/{device_id}:assign-policy`
  - `POST /v1/devices/{device_id}:revoke`
  - `POST /v1/devices/{device_id}:retire`

`auth.admin_api_keys` は引き続きサポートされ、write スコープとして扱われます。

## ポリシー承認ワークフロー

- `POST /v1/policies` で新規 policy を作ると `status=draft`
- `PUT /v1/policies/{version}`（未使用時のみ）で内容調整すると `status=draft`
- `POST /v1/policies/{version}:approve` で `status=approved`
- `POST /v1/devices/{device_id}:assign-policy` は `approved` のみ受け付け
- 未使用 policy は `DELETE /v1/policies/{version}` で削除可能
- status を持たない旧データはロード時に `approved` 扱い

## 管理ログ API

管理ログ API は、`GET /admin/logs`（UI シェル）を除き HTTPS/TLS と `X-API-Key` が必要です。

`GET /v1/admin/logs/summary` のクエリ:
- 任意 `device_id`（未指定時は全端末集計）
- 任意 RFC3339 `from`, `to`
- 任意 `kind`: `access|security|system`
- 任意 `level`: `info|warn|error`

`GET /v1/admin/logs/summary` のレスポンス:
- `summary.total_entries`
- `summary.latest_timestamp`
- `summary.by_device[]`（`device_id`, `entries`, `latest_timestamp`）
- `summary.by_kind`
- `summary.by_level`
- `filters`（正規化済みリクエストフィルタ）
- `storage_policy`（`log_retention`, `log_max_bytes`）

`GET /v1/devices/{device_id}:download-policy` のクエリ:
- 任意 `state`: `desired`（既定）または `current`
- 任意 `format`: `raw`（既定、`text/plain` 添付）または `json`

## 再登録ガードレール

- 既存 `device_id` に異なる鍵を登録:
  - 既定は `409 Conflict`
  - `X-Allow-Key-Rotation: true` のときのみ許可
- 既存公開鍵を別 `device_id` へ登録:
  - 常に `409 Conflict`
- retired 済み `device_id` の再 enroll:
  - 正しい license key があれば許可
  - レスポンスに `reactivated=true` を含む

## Revoke ランブック

鍵漏えい時は次の固定手順で対応します。

1. center 側でアクティブ鍵を失効:

```bash
make device-revoke \
  CENTER_URL=https://center.example.com \
  DEVICE_ID=device-001 \
  REASON=compromised \
  CENTER_ADMIN_API_KEY_FILE=./center-admin-api.key
```

2. edge 側で鍵をローテーション（新規 keypair 生成）。
3. `X-Allow-Key-Rotation: true` 付きで edge を再 enroll（edge の `make center-register` フロー）。
4. 新しい署名 heartbeat が受理されることを確認。

補足:
- 失効中は `POST /v1/heartbeat` が対象端末に `410 Gone` を返却。
- `scripts/center_revoke.sh` は既定で HTTPS を強制（ローカル開発のみ `CENTER_ALLOW_INSECURE_HTTP=1`）。

## ポリシーダウンロード ランブック

1端末分の policy（desired/current）を raw ルールテキストでダウンロード:

```bash
make device-policy-download \
  CENTER_URL=https://center.example.com \
  DEVICE_ID=device-001 \
  POLICY_STATE=desired \
  POLICY_FORMAT=raw \
  OUT=./device-001-desired.waf \
  CENTER_ADMIN_API_KEY_FILE=./center-admin-api.key
```

補足:
- `POLICY_STATE=current` で現在適用中スナップショットを取得。
- `POLICY_FORMAT=json` で `waf_raw` を含むメタデータ付き JSON を取得。
- `scripts/center_policy_download.sh` は既定で HTTPS を強制（ローカル開発のみ `CENTER_ALLOW_INSECURE_HTTP=1`）。

## ビルドターゲット

- `make build`
- `make run`
- `make config-check`
- `make db-init`
- `make db-check`
- `make db-migrate`
- `make db-file-to-sqlite`
- `make db-sqlite-to-file`
- `make device-policy-download`
- `make check`
- 統合フローテスト:
  - `go test ./internal/center -run TestEndToEndEnrollHeartbeatRevokeReEnrollFlow`

## 関連プロジェクト

`mamotama-edge`  
https://github.com/vril-dev/mamotama-edge

## mamotama とは？

**mamotama** は日本語の **「護りたまえ」 (mamoritamae)** に由来し、
「どうか護ってください」や「護りを与えてください」という意味を持ちます。

この名前には、edge / IoT インフラを守るというプロジェクトの目的を込めています。

## ライセンス

Apache License 2.0。詳細は [LICENSE](LICENSE) を参照してください。
