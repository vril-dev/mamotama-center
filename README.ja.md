# mamotama-center (日本語)

`mamotama-edge` 向けのコントロールプレーンです。

- English: `README.md`
- 日本語: `README.ja.md`

## 概要

`mamotama-center` は単一バイナリで動作し、主に次を提供します。

- edge 端末登録（`device_id -> public key`）
- 署名付き heartbeat 検証（timestamp/nonce リプレイ対策含む）
- ポリシー配布（WAF raw + 任意 bundle）
- edge からのログ収集
- 管理 API / 管理 UI（`/admin/devices`, `/admin/logs`）

## 現在の主な API (0.1.x)

- `POST /v1/enroll`
  - `X-License-Key` 必須
  - 署名付き登録
- `POST /v1/heartbeat`
  - 署名付き heartbeat
  - desired/current ポリシー状態と `update_required` を返却
- `POST /v1/policy/pull`
  - edge が割り当てポリシーを取得（`waf_raw` + 任意 bundle）
- `POST /v1/policy/ack`
  - edge が適用結果（`applied|failed|rolled_back`）を通知
- `POST /v1/logs/push`
  - gzip ndjson ログをアップロード
- `GET/POST/PUT/DELETE /v1/policies*`
  - 管理者向けポリシー操作（draft/approve/assign 運用）
- `POST /v1/policies:inspect-bundle`
  - bundle 内 `.conf` 一覧と推奨 rule file を返却
- `GET /v1/devices`, `GET /v1/devices/{id}`
  - 端末状態一覧/詳細
- `POST /v1/devices/{id}:assign-policy|revoke|retire`
  - 割り当て/失効/退役
- `GET /v1/admin/logs/*`
  - ログ一覧/集計/ダウンロード

## 管理 UI (`/admin/devices`) の主な機能

- 端末一覧、ポリシー一覧、割り当て、ダウンロード
- bundle アップロードと `.conf` 検査
- `waf_raw_template=bundle_default` 生成補助
- 選択端末の `rule_files` 差分表示
  - current / desired / target(edit)
  - placeholder 展開プレビュー（`${MAMOTAMA_POLICY_ACTIVE}`, `${POLICY_ACTIVE_LINK}`）
- Policy Active Base の端末別保存（ブラウザ localStorage）
- Base map プロファイル管理
  - プロファイル切替、Save As、削除
  - JSON export/import（旧形式互換あり）
- プロファイル間差分
  - 端末キーごとの差分をテーブル表示
  - filter: `all`, `changed`, `missing_current`, `missing_compare`
  - 検索 / ソート

## 管理 UI スクリーンショット

`/admin/devices`:

![center admin devices](docs/images/center_admin_devices.png)

`/admin/logs`:

![center admin logs](docs/images/center_admin_logs.png)

## クイックスタート

1. 設定をコピー

```bash
cp center.config.example.json center.config.json
```

2. `center.config.json` を編集

- `auth.enrollment_license_keys` を設定
- `auth.admin_read_api_keys` / `auth.admin_write_api_keys` を設定
- 本番は `auth.require_tls=true` を維持
- 永続化先 `storage.path` を設定

3. ビルドと起動

```bash
make build
make run CONFIG=./center.config.json
```

設定検証のみ:

```bash
make config-check CONFIG=./center.config.json
```

## 署名方式（要点）

`enroll` / `heartbeat` / `policy pull/ack` / `logs push` はすべて署名付きです。

- `body_hash = sha256_hex(canonical_body)`
- `signature_b64 = Base64(Ed25519Sign(private_key, envelope_message))`
- envelope:
  - `device_id + "\n" + key_id + "\n" + timestamp + "\n" + nonce + "\n" + body_hash`

## 補足

- 詳細な API 仕様・例は `README.md`（英語版）を参照してください。
- ストレージは現状ファイルベースです（将来 DB 移行を想定した設計）。
