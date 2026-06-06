# Copyright (c) 2026 hidemi-k
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

# SASE/IBN API 仕様書 (v9.1)
# Identity, Priority-Aware QoS, Flow-Control, Ticket-Issuance & Observability
# main.go (v9.1) & main.rs (eBPF Kernel-space) 完全仕様リファレンス
# AI/ML Orchestrator 向け - Native/Generic XDP Mode 対応

"""
## SASE/Identity-Based API 仕様 (v9.1)

このAPIは、XDP (eBPF) カーネル層で「動的認証」「優先度付き帯域制御スライシング」
「フロー管理」「運用チケット」を統合管理し、Go Agent が出力する構造化イベントログを
AI/ML が解釈することで、高度な自律制御が可能です。

---

## 【v9.1 変更点】（v8.3 からの変更）

### 破壊的変更

1. **/auth/ticket レスポンス変更**
   - 旧: `Ticket 0xdeadbeef active.`（magic 値が平文で返っていた）
   - 新: `Ticket active (hash=sha256:XXXXXXXXXXXXXXXX)`
     発行された magic の SHA-256 ハッシュ（先頭8バイト=16文字）のみ返る。
     元の magic 値はレスポンスに含まれない。

2. **/auth/logs フィールド変更（破壊的）**
   - 旧: `magic` フィールドに平文 hex 値（`"0xdeadbeef"`）
   - 新: `magic_hash` フィールドに SHA-256 ハッシュ（`"sha256:ab12cd34ef56gh78"`）
   - 平文 magic 値はログに一切記録されない。

3. **/config レスポンス変更（破壊的）**
   - 旧: `current_magic_ticket`（hex 文字列）
   - 新: `magic_status`（`"active"` / `"consumed"` / `"unset"`）
   - 追加: `auth_port`（u16: 認証受付ポート番号。デフォルト 8888）

4. **書き込み系エンドポイントに API キー認証を追加**
   - 環境変数 `AGENT_API_KEY` が設定されている場合、書き込み系エンドポイントで
     `X-API-Key` ヘッダが必須になる。
   - 未設定の場合はヘッダなしでも動作（開発環境向け・起動ログに ⚠️ 警告）。
   - 認証失敗時: `401 Unauthorized`

### 非破壊的変更

5. **認証ポートの動的化**
   - 旧: UDP:8888 ハードコード（main.rs）
   - 新: `CONFIG_MAP[2]` に格納。起動時デフォルト 8888。main.rs の `get_auth_port()` が取得。
   - `/config` の `auth_port` フィールドから現在値を確認できる。

6. **`BLACKLIST_DURATION_SEC` 環境変数対応**
   - ブラックリスト保持時間を環境変数で変更可能（デフォルト 600秒 = 10分）。
   - 旧: 10分ハードコード。

7. **`ticketLockOnce` 削除**
   - 宣言のみで未使用だった `sync.Once` を削除。`ticketLocked` + `ticketMu` で機能維持。

8. **バージョン番号更新**: `version` フィールドが `"1.1.0"` になった

9. **`/auth/priority` レスポンス変更**
   - 旧: `Successfully set X to Priority Y`
   - 新: `Set X → Priority Y`

10. **`/qos/set` レスポンス変更**
    - 旧: `QoS Applied: X (Y B/s)`
    - 新: `QoS applied: X (Y B/s)`（大文字 A → 小文字 a）

11. **`/auth/revoke` レスポンス変更**
    - 旧: `Revoked and blacklisted: X (for 10m0s)`
    - 新: `Revoked and blacklisted: X (10m0s)`（"for " を削除）

12. **`/auth/lock` レスポンス変更**
    - 旧: `Ticket issuance locked. No new tickets will be accepted until agent restart.`
    - 新: `Ticket issuance locked until agent restart.`（短縮）

13. **認証ポート宛 UDP を XDP_PASS に変更（main.rs）**
    - 旧: magic 不一致の認証ポート宛パケットを XDP_DROP
    - 新: 認証ポート宛パケットは一致・不一致問わず XDP_PASS
    - 理由: 不一致で DROP すると正規クライアントが認証ループに陥るため。
      失敗ログは Go 側で記録する。

---

## 📌 XDP Mode Selection

### 起動時のモード指定

```bash
# デフォルト（推奨）：自動フォールバック
sudo ./sase-agent -iface eth0

# Native XDP を強制（最高パフォーマンス）
sudo ./sase-agent -iface eth0 -xdp-mode native

# Generic XDP を強制（互換性重視）
sudo ./sase-agent -iface eth0 -xdp-mode generic
```

### Native Mode vs Generic Mode

| 特性 | Native | Generic |
|------|--------|---------|
| 速度 | 非常に高速 | 低速 |
| ドライバ依存 | あり（対応必須） | なし |
| パフォーマンス | > 1M pps | > 100K pps |
| veth 対応 | 不可 | 可能 |
| PoC 環境 | △ | ✅ |

---

## ✅ XDP 機能仕様（main.rs 凍結）

### ✅ XDP に実装済みの機能

1. **マジックナンバー認証**
   - 認証ポートは `CONFIG_MAP[2]` から動的取得（`get_auth_port()`）。デフォルト UDP:8888。
   - UDP ペイロード先頭8バイト（u64 BE）を `CONFIG_MAP[0]` と比較。
   - 一致 → `AUTH_IPS[src_ip]` に登録、`CONFIG_MAP[0] = u64::MAX`（使用済み番兵）。
   - 認証ポート宛パケットは一致・不一致問わず XDP_PASS（ループ防止）。

2. **SYN 攻撃検知（Go 側）**
   - 3 秒周期の SYN ΔCount 監視。Delta >= 300 を 2 回連続検知で Level 1 に格下げ。
   - 隔離から 1 分経過で Level 2 に自動復帰（SYN スパイク継続中でも復旧チェックを実行）。

3. **優先度管理**
   - 3 段階優先度（1=Bulk, 2=Normal, 3=VIP）
   - 認証時デフォルト: Level 2

4. **基本統計情報**
   - パケット数、バイト数、SYN/RST/ACK カウント
   - フロー開始時刻、継続時間、ユーザーID、優先度、L7 プロトコルラベル

5. **トークンバケット QoS**
   - Priority 1: 補充レート × 1、Priority 2: × 10、Priority 3: バイパス

6. **マイクロセグメンテーション**
   - L4 レベル（IP + Protocol + Port）でのフロー制御

### CONFIG_MAP キー割り当て（main.rs / main.go 共通）

| キー | 用途 | デフォルト |
|------|------|----------|
| 0 (`CFG_MAGIC`) | magic チケット値（u64）。0=未設定、u64::MAX=使用済み | 0 |
| 1 (`CFG_DURATION`) | 認証有効期限（ns）| 300,000,000,000（300秒）|
| 2 (`CFG_PORT`) | 認証受付ポート（u16 下位16bit）| 8888 |

---

## 🔴 Data-Plane Authentication（物理認証プロトコル）

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Admin 端末 → GET /auth/ticket?magic=0x{HEX}                 │
│    ヘッダ: X-API-Key: {AGENT_API_KEY}  ※設定時のみ必須        │
│    ※ magic=0 は拒否。ロック中は 403 を返す。                  │
│    ※ ブラックリスト中の発行元 IP は 403 を返す。             │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│ 2. Go Agent が CONFIG_MAP[0] = magic にセット                   │
│    /auth/logs に magic_hash（sha256 先頭8バイト）を記録        │
│    レスポンス: Ticket active (hash=sha256:XXXXXXXXXXXXXXXX)    │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│ 3. 事前に /config で auth_port を確認する（推奨）               │
│    GET /config → { "auth_port": 8888, ... }                    │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│ 4. クライアント端末 → UDP:{auth_port} にマジックナンバー送信   │
│    送信フォーマット: [IP Header][UDP Header][8バイト整数 BE]   │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│ 5. eBPF カーネル層（XDP）                                       │
│    - CONFIG_MAP[2] から auth_port を取得                       │
│    - CONFIG_MAP[0] との一致判定                                │
│    - 0 または u64::MAX の場合は認証不可                        │
│    - 一致 → AUTH_IPS[src_ip] 登録 + CONFIG_MAP[0] = u64::MAX  │
│    - 認証ポート宛は一致・不一致問わず XDP_PASS（ループ防止）  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📡 API エンドポイント仕様

### 認証ルール

```
環境変数 AGENT_API_KEY が設定されている場合:
  書き込み系エンドポイントには X-API-Key ヘッダが必須
  不一致: 401 Unauthorized

AGENT_API_KEY が未設定の場合:
  全エンドポイントが認証なしで動作（開発環境向け）
  起動ログに ⚠️  AGENT_API_KEY is not set — write APIs are unprotected (dev mode) を出力
```

| エンドポイント | 種別 | 認証 |
|---|---|---|
| GET /info | 読み取り | なし |
| GET /stats | 読み取り | なし |
| GET /top | 読み取り | なし |
| GET /config | 読み取り | なし |
| GET /auth/logs | 読み取り | なし |
| GET /auth/identities | 読み取り | なし |
| GET /auth/blacklist | 読み取り | なし |
| GET /drop/list | 読み取り | なし |
| GET /auth/ticket | **書き込み** | **X-API-Key 必須** |
| GET /auth/revoke | **書き込み** | **X-API-Key 必須** |
| GET /auth/lock | **書き込み** | **X-API-Key 必須** |
| GET /auth/priority | **書き込み** | **X-API-Key 必須** |
| GET /drop/block | **書き込み** | **X-API-Key 必須** |
| GET /drop/unblock | **書き込み** | **X-API-Key 必須** |
| GET /qos/set | **書き込み** | **X-API-Key 必須** |

---

### 1. GET /info

**レスポンス (JSON)**:
```json
{
  "interface": "eth3",
  "xdp_mode":  "generic",
  "timestamp": 1706123456,
  "version":   "1.1.0",
  "note":      "VPP determines zero-copy or copy mode via af_xdp based on NIC capabilities"
}
```

---

### 2. GET /auth/ticket

**パラメータ**: `magic=0x{HexValue}` または `magic={HexValue}`

**ヘッダ（AGENT_API_KEY 設定時必須）**: `X-API-Key: {key}`

**レスポンス（v9.1）**:
```
Ticket active (hash=sha256:ab12cd34ef56gh78)
```
※ 元の magic 値はレスポンスに含まれない。SHA-256 ハッシュのみ返る。

**エラーレスポンス**:
```
400 magic=0 is reserved
400 Invalid hex format
403 Ticket issuance is locked. Restart agent to unlock.
403 Source IP is blacklisted
401 Unauthorized
500 Failed to write magic
```

**内部処理**:
1. `X-API-Key` ヘッダを検証（AGENT_API_KEY 設定時）
2. ロック中の場合は 403 を返す
3. リクエスト送信元 IP がブラックリスト中の場合は 403 を返す
4. magic=0 の場合は 400 を返す
5. `CONFIG_MAP[0] = magic` に設定
6. `/auth/logs` に `magic_hash`（sha256 先頭8バイト）を記録（平文は保存しない）
7. ログ: `🎫 Ticket issued: hash=sha256:XXXX remote=X.X.X.X:PPPPP`

---

### 3. GET /auth/logs

**レスポンス (JSON) v9.1**:
```json
[
  {
    "timestamp":  "2026-06-06T19:50:32.123456789+09:00",
    "remote_ip":  "127.0.0.1:37038",
    "magic_hash": "sha256:0cb1308e85bd5416",
    "action":     "TICKET_ISSUED"
  },
  {
    "timestamp":  "2026-06-06T19:50:49.000000000+09:00",
    "remote_ip":  "127.0.0.1:00000",
    "magic_hash": "-",
    "action":     "REVOKED_AND_BLACKLISTED:10.0.5.100"
  }
]
```

**フィールド説明**:
- `magic_hash`: `"sha256:XXXXXXXXXXXXXXXX"` 形式（TICKET_ISSUED 時）。revoke ログは `"-"`。
- `action`: `"TICKET_ISSUED"` または `"REVOKED_AND_BLACKLISTED:{ip}"`
- `timestamp`: time.Time 型（Go の JSON エンコード → ISO 8601、JST タイムゾーン付き、ナノ秒精度）

**⚠️ v9.1 破壊的変更**:
- 旧 `magic` フィールドは廃止。`magic_hash` を使用すること。
- ハッシュは不可逆のため、元の magic 値への逆算は不可能。

**タイムスタンプのパース（Python）**:
```python
import re
from datetime import datetime, timezone

def parse_log_ts(ts_str: str):
    # ナノ秒（7桁以上）をマイクロ秒（6桁）に切り詰めてから fromisoformat
    s = re.sub(r'(\.\d{6})\d+', r'\1', ts_str)
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)
```

**AI 向けポイント**:
- TICKET_ISSUED の頻度と remote_ip の関連性を分析
- 短時間での大量 TICKET_ISSUED は攻撃の兆候 → `/auth/lock` で封鎖

---

### 4. GET /config

**レスポンス (JSON) v9.1**:
```json
{
  "magic_status":     "consumed",
  "auth_duration_ns": 300000000000,
  "auth_port":        8888
}
```

**フィールド説明**:
- `magic_status`:
  - `"unset"`:    未発行（CONFIG_MAP[0] = 0）
  - `"active"`:   有効なチケットが待機中（クライアントの UDP 認証待ち）
  - `"consumed"`: 認証後リセット済み（u64::MAX 番兵値。次の発行を待つ状態。正常）
- `auth_duration_ns`: 認証有効期限（ナノ秒）。デフォルト 300秒。
- `auth_port`: 現在の認証受付ポート番号。デフォルト 8888。

**⚠️ v9.1 破壊的変更**:
- 旧 `current_magic_ticket`（hex 文字列）は廃止。`magic_status` を使用すること。
- `"consumed"` は正常な認証完了後の状態（エラーではない）。

---

### 5. GET /auth/priority

**パラメータ**: `ip={IPv4}&level={1, 2, or 3}`

**ヘッダ（AGENT_API_KEY 設定時必須）**: `X-API-Key: {key}`

**レスポンス（v9.1）**:
```
Set 10.0.5.100 → Priority 1
```

**エラーレスポンス**:
```
400 invalid ip
400 level must be 1(Bulk), 2(Normal), or 3(VIP)
404 Identity not found
```

**優先度定義**:

#### Level 1 (Bulk / 最低優先度)
- QoS 補充レート: `limit × 1`
- Go Agent が SYN スパイク検知時に自動格下げ
- 自動復帰: 隔離から 1 分経過後に Level 2 に復帰（v8.3 修正: スパイク継続中でも復旧）

#### Level 2 (Normal / 標準優先度)
- QoS 補充レート: `limit × 10`（Bulk の 10 倍）
- チケット発行時のデフォルト

#### Level 3 (VIP / Platinum)
- QoS 制御を完全にバイパス → VPP へ直接リダイレクト
- `apply_qos()` を呼ばない

**Go ログ**: `[EVENT] TYPE=PRIORITY_CHANGE IP=X.X.X.X LEVEL=Y`

---

### 6. GET /auth/revoke

**パラメータ**: `ip={IPv4}`

**ヘッダ（AGENT_API_KEY 設定時必須）**: `X-API-Key: {key}`

**レスポンス（v9.1）**:
```
Revoked and blacklisted: 10.0.5.100 (10m0s)
```
※ ブラックリスト保持時間は `BLACKLIST_DURATION_SEC` 環境変数で変更可能（デフォルト 600秒）。

**内部処理**:
1. `AUTH_IPS` から該当 IP を削除
2. ブラックリストに登録（`blacklistDuration` 秒間）
3. `/auth/logs` に `REVOKED_AND_BLACKLISTED:{ip}` を `magic_hash: "-"` で記録

**Go ログ**: `🚫 Revoked+blacklisted: X.X.X.X (duration: 10m0s)`

---

### 6b. GET /auth/lock

**ヘッダ（AGENT_API_KEY 設定時必須）**: `X-API-Key: {key}`

**レスポンス（v9.1）**:
```
Ticket issuance locked until agent restart.
```

**内部処理**:
1. `ticketLocked = true`（`ticketMu` で保護）
2. 以降の `/auth/ticket` は 403 を返す
3. 解除は Go エージェントの再起動のみ

**Go ログ**: `🔒 Ticket issuance LOCKED by X.X.X.X:PPPPP`

---

### 6c. GET /auth/blacklist

**レスポンス (JSON)**:
```json
[
  {
    "ip":        "10.0.5.100",
    "revoked_at": "2026-06-06T19:50:49+09:00",
    "expires_in": "9m30s"
  }
]
```

---

### 6d. GET /auth/identities

**レスポンス (JSON)**:
```json
{
  "10.0.5.100": {
    "expiry":   1706123456789000000,
    "priority": 2,
    "user_id":  167837028
  }
}
```
- `user_id`: src_ip を u32 に変換した値（v8.2 以降 src_ip と同値）

---

### 7. GET /stats

**レスポンス (JSON) サンプル**:
```json
[
  {
    "ip":       "10.0.5.100",
    "port":     22,
    "protocol": "tcp",
    "stats": {
      "packets":         16495,
      "bytes":           567540,
      "dropped_packets": 5985,
      "syn_packets":     16495,
      "rst_packets":     0,
      "ack_packets":     0,
      "last_ts":         13712613094917,
      "flow_start_ns":   13694722529183,
      "user_id":         167837028,
      "policy_status":   1,
      "l7_proto_label":  3,
      "pkt_min":         54,
      "pkt_max":         54
    }
  }
]
```

**AI/ML 推論用フィールド詳細**:
- `ack / (syn+1)` < 0.5 → ハーフオープン / SYN Flood
- `(last_ts - flow_start_ns) / 1e9` > 3600 → 長期フロー / DLP 疑い
- `dropped_packets / packets` > 0.1 → QoS / DROP_LIST が効いている
- `policy_status`: 1=Bulk（制限）, 2=Normal（標準）, 3=VIP（無制限）
- `l7_proto_label`: 1=HTTP/HTTPS(80,443), 2=DNS(53), 3=SSH(22), 0=その他

---

### 8. GET /top

**説明**: packets 降順の上位 10 件を返す。`/stats` と同形式。

---

### 9. GET /qos/set

**パラメータ**: `ip={IPv4}&limit={Bytes/sec}`

**ヘッダ（AGENT_API_KEY 設定時必須）**: `X-API-Key: {key}`

**レスポンス（v9.1）**:
```
QoS applied: 10.0.5.100 (10000 B/s)
```

**実効レート（eBPF カーネル内）**:
```
Priority 1 (Bulk)   → 実効レート = limit × 1
Priority 2 (Normal) → 実効レート = limit × 10
Priority 3 (VIP)    → QoS バイパス（無制限）
```

---

### 10. GET /drop/block

**パラメータ**: `ip={IPv4}&proto={tcp/udp/icmp}&port={PortNum}`

**ヘッダ（AGENT_API_KEY 設定時必須）**: `X-API-Key: {key}`

**レスポンス**:
```
Blocked: tcp 10.0.1.30:22
```

---

### 11. GET /drop/unblock

**パラメータ**: `/drop/block` と同じ形式

**ヘッダ（AGENT_API_KEY 設定時必須）**: `X-API-Key: {key}`

**レスポンス**:
```
Unblocked
```

---

### 12. GET /drop/list

**レスポンス (JSON)**:
```json
{
  "10.0.1.30:22 [tcp]":   "BLOCKED",
  "10.0.1.30:8080 [tcp]": "BLOCKED"
}
```

---

## 🤖 Autonomous Defense Logic（Go Agent 自律防御）

### A. 自動隔離 (Isolation)

**実装**: `runDefenseLoop()`（goroutine、3秒 Ticker）

**トリガー条件**: 同一 FlowKey に対して SYN ΔCount > 300 を 2 回連続観測

**アクション**: Priority を Level 1 に格下げ + `isolatedAt` に記録

**Go ログ**: `[Defense] 🚨 Isolated X.X.X.X port=Y delta=Z`

### B. 自動復旧 (Recovery)

**トリガー条件**: `isolatedAt` からの経過時間 > 1分（SYN スパイク継続中でも評価）

**アクション**: Priority を Level 2 に復帰 + `isolatedAt` から削除

**Go ログ**: `[Recovery] ✅ Restored X.X.X.X`

---

## 💡 推奨される AI/ML 推論フロー

### Python での実装例（v9.1 対応）

```python
import requests
import json
import os
import re
from datetime import datetime, timezone

class XDPOrchestrator:
    def __init__(self, sase_api_url="http://localhost:8080"):
        self.api_url  = sase_api_url
        self.api_key  = os.getenv("AGENT_API_KEY", "")
        self._revoke_counts = {}

    def _write_headers(self) -> dict:
        # X-API-Key ヘッダを返す（AGENT_API_KEY 設定時のみ）
        return {"X-API-Key": self.api_key} if self.api_key else {}

    def get_auth_port(self) -> int:
        # 認証ポートを /config から取得（v9.1: auth_port フィールド）
        try:
            r = requests.get(f"{self.api_url}/config", timeout=5)
            return int(r.json().get("auth_port", 8888))
        except Exception:
            return 8888

    def get_magic_status(self) -> str:
        # チケット状態を取得（v9.1: magic_status フィールド）
        try:
            r = requests.get(f"{self.api_url}/config", timeout=5)
            return r.json().get("magic_status", "unset")
        except Exception:
            return "unknown"

    def issue_ticket(self, magic_hex: str) -> str:
        # チケット発行（X-API-Key ヘッダ付き）
        r = requests.get(
            f"{self.api_url}/auth/ticket",
            params={"magic": magic_hex},
            headers=self._write_headers(),
            timeout=5
        )
        return r.text.strip()

    def get_all_stats(self):
        r = requests.get(f"{self.api_url}/stats", timeout=5)
        return r.json()

    def parse_log_ts(self, ts_str: str):
        # JST+ナノ秒付きタイムスタンプのパース
        s = re.sub(r'(\.\d{6})\d+', r'\1', ts_str)
        s = s.replace("Z", "+00:00")
        return datetime.fromisoformat(s)

    def analyze_flow(self, flow):
        d            = flow['stats']
        duration     = (d['last_ts'] - d['flow_start_ns']) / 1e9
        ack_ratio    = d['ack_packets'] / (d['syn_packets'] + 1)
        throughput   = d['bytes'] / (duration + 1) if duration > 0 else 0
        anomaly      = 0
        if d['syn_packets'] > 1000:                         anomaly += 0.3
        if ack_ratio < 0.5:                                 anomaly += 0.3
        if duration > 7200:                                 anomaly += 0.2
        if d['policy_status'] == 3 and throughput > 1e8:   anomaly += 0.2
        return {
            'ip': flow['ip'], 'port': flow['port'],
            'protocol': flow['protocol'],
            'anomaly_score': anomaly,
            'metrics': {'duration_sec': duration, 'ack_ratio': ack_ratio,
                        'throughput_bps': throughput}
        }

    def execute_response(self, analysis):
        ip = analysis['ip']
        if analysis['anomaly_score'] > 0.7:
            requests.get(
                f"{self.api_url}/auth/revoke",
                params={"ip": ip},
                headers=self._write_headers(),
                timeout=5
            )
            print(f"[AI] Revoked {ip}")
            self._revoke_counts[ip] = self._revoke_counts.get(ip, 0) + 1
            if self._revoke_counts[ip] >= 3:
                resp = requests.get(
                    f"{self.api_url}/auth/lock",
                    headers=self._write_headers(),
                    timeout=5
                )
                print(f"[AI] Locked: {resp.text.strip()}")
        elif analysis['metrics']['ack_ratio'] < 0.3:
            requests.get(
                f"{self.api_url}/auth/priority",
                params={"ip": ip, "level": 1},
                headers=self._write_headers(),
                timeout=5
            )
            print(f"[AI] Downgraded {ip} to Level 1")

# 使用例
import time
orc = XDPOrchestrator()
print(f"Auth port: {orc.get_auth_port()}")
while True:
    for flow in orc.get_all_stats():
        a = orc.analyze_flow(flow)
        if a['anomaly_score'] > 0:
            orc.execute_response(a)
    time.sleep(60)
```

---

## 📋 統計フィールド完全マッピング表

| フィールド | 型 | 追加バージョン | 用途 | 計算式/推奨 |
|---|---|---|---|---|
| packets | u64 | v8.0 | トラフィック総量 | N/A |
| bytes | u64 | v8.0 | バイト総量（DROP されたパケットは計上なし）| N/A |
| dropped_packets | u64 | v8.0 | 破棄パケット | `if >= packets/10 → 異常` |
| syn_packets | u64 | v8.0 | SYN 数 | `if > 1000 → SYN Flood 疑い` |
| rst_packets | u64 | v8.0 | RST 数 | `if high → 接続不安定またはターゲット応答` |
| ack_packets | u64 | v8.1 | ACK 数 | `ratio = ack / (syn+1)` |
| last_ts | u64 | v8.0 | 最終観測時刻（カーネル ns）| `now() - last_ts → 非アクティブ判定` |
| flow_start_ns | u64 | v8.1 | フロー開始時刻 | `duration = (last_ts - flow_start_ns) / 1e9` |
| user_id | u32 | v8.1 / v8.2変更 | src_ip の u32 表現 | ユーザー単位の異常追跡 |
| policy_status | u32 | v8.1 | 優先度 | `1=Bulk, 2=Normal, 3=VIP` |
| l7_proto_label | u32 | v8.1 | L7 プロトコル推測 | `1=HTTP/S, 2=DNS, 3=SSH, 0=Other` |
| pkt_min / pkt_max | u32 | v8.0 | パケットサイズ | `if pkt_max > MTU → 異常` |

---

## 🔒 セキュリティ上の注意点

1. **API キー管理**
   - `AGENT_API_KEY` は 32 バイト以上のランダム文字列を推奨
   - ログやコードにハードコードしないこと
   - Cloud Run 等に公開する場合は必ず設定すること
   - `export AGENT_API_KEY=$(openssl rand -hex 32)`

2. **チケットの安全性**
   - チケット発行は TLS/HTTPS 経由で行うこと（現行は平文 HTTP）
   - magic 値はログに平文で残らない（v9.1 以降は SHA-256 ハッシュのみ）
   - **magic=0 は絶対に使用しないこと**

3. **ブラックリストの限界**
   - `sase_agent`（Python）が localhost（127.0.0.1）からチケットを発行する場合は
     ブラックリストをすり抜ける
   - 根本的な封鎖には `/auth/lock` が必須

4. **eBPF サンドボックス**
   - カーネル内で実行されるためユーザー空間より高速・安全
   - eBPF には命令数上限と関数呼び出し制限がある

---

## 📝 実装確認チェックリスト

### XDP 側（v9.1 実装済み・凍結）
- [x] main.go が全エンドポイント実装
- [x] main.rs が認証・SYN 検知・優先度管理実装
- [x] Native/Generic/Auto モード選択機能
- [x] 統計情報（全 13 フィールド）記録機能
- [x] 自動隔離ロジック（SYN Delta > 300 を 2 回連続）
- [x] 自動復旧ロジック（1 分後・スパイク継続中でも復旧）
- [x] /auth/lock エンドポイント（チケット発行恒久禁止）
- [x] /auth/blacklist エンドポイント（revoke 済み IP 一覧・残り時間）
- [x] /auth/revoke がブラックリスト登録を兼ねる
- [x] magic=0 の発行拒否
- [x] eBPF: 認証後 CONFIG_MAP[0] を u64::MAX でリセット
- [x] eBPF: user_id = src_ip（magic 下位32bit 流用を廃止）
- [x] eBPF: 認証ポート宛を XDP_PASS（ループ防止）
- [x] eBPF: CONFIG_MAP[2] から認証ポートを動的取得
- [x] AGENT_API_KEY による書き込み系 API 認証
- [x] /auth/logs の magic_hash 化（平文保存廃止）
- [x] /config の magic_status・auth_port フィールド
- [x] BLACKLIST_DURATION_SEC 環境変数対応
- [x] version = "1.1.0"

### AI/ML オーケストレータ側（推奨実装）
- [x] X-API-Key ヘッダを書き込み系 API に付与
- [x] /config の magic_status を参照（current_magic_ticket 廃止）
- [x] /auth/logs の magic_hash フィールドを参照（magic 廃止）
- [x] /config から auth_port を動的取得
- [x] タイムスタンプのナノ秒・JST 対応パース
- [ ] /stats からのメトリクス計算・異常スコアリング
- [ ] 自動応答ロジック
- [ ] インシデントログ記録

### VPP 側（次フェーズ）
- [ ] af_xdp インターフェース統合
- [ ] 優先度に基づく QoS 適用
- [ ] DSCP/VLAN 書き換え

---

## 🎯 フェーズ進行状況

| フェーズ | 担当 | 完了 | 次アクション |
|---------|------|------|----------|
| Phase 1 | XDP (Go + Rust) v9.1 | ✅ | - |
| Phase 2 | VPP REST API (Python) | ⏳ | af_xdp 統合 |
| Phase 3 | LLM Orchestrator (Python) | ⏳ | 異常検知・自動応答 |

**XDP 機能追加はありません。追加要件は VPP 側または LLM オーケストレータ側で実装してください。**
"""
