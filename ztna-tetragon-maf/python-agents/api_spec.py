# SASE/IBN API 仕様書 (v8.2) - セキュリティ修正版
# Identity, Priority-Aware QoS, Flow-Control, Ticket-Issuance & Observability
# main.go (修正版) & main.rs (eBPF Kernel-space) 完全仕様リファレンス
# AI/ML Orchestrator向け - Native/Generic XDP Mode対応

"""
## SASE/Identity-Based API 仕様 (v8.2) - Magic Auth Security Fix

このAPIは、XDP (eBPF) カーネル層で「動的認証」「優先度付き帯域制御スライシング」「フロー管理」「運用チケット」を統合管理し、
Go Agent が出力する構造化イベントログを AI/ML が解釈することで、高度な自律制御が可能です。

【v8.2 変更点】
- マジック認証のセキュリティ脆弱性を修正（v8.1 からの破壊的変更あり）
  1. /auth/ticket?magic=0x0 による偽無効化の廃止 → /auth/lock に統一
  2. revoke 済みIPのブラックリスト機能を追加（/auth/blacklist）
  3. eBPF: user_id を magic の下位32bit から src_ip(送信元IP) に変更
  4. eBPF: 認証後の CONFIG_MAP[0] リセットを 0 → u64::MAX（番兵値）に変更
  5. /config レスポンスの current_magic_ticket が 0xffffffffffffffff の場合は
     「認証後リセット済み（再発行待ち）」を意味する（v8.1では 0x0 がその役割だったが誤り）

【v8.1 変更点】（参考）
- XDP モード選択機能を追加（Native/Generic/Auto）
- VPP連携の明確化（Zero-copy/Copy はVPP側で自動選択）
- eBPF側の実装を凍結（XDP機能追加は今後なし）
- LLMオーケストレータはVPP REST APIを経由して制御

---

## 📌 XDP Mode Selection (v8.1 新規)

### 起動時のモード指定

XDP プログラムはNativeモードまたはGenericモードで動作します。
起動時に以下のフラグで指定してください。

```bash
# デフォルト（推奨）：自動フォールバック
sudo ./sase-agent -iface eth0

# Native XDPを強制（最高パフォーマンス）
sudo ./sase-agent -iface eth0 -xdp-mode native

# Generic XDPを強制（互換性重視）
sudo ./sase-agent -iface eth0 -xdp-mode generic

# ヘルプ表示
sudo ./sase-agent -help
```

### Native Mode vs Generic Mode

| 特性 | Native | Generic |
|------|--------|---------|
| 速度 | 非常に高速 | 低速 |
| ドライバ依存 | あり（対応必須） | なし |
| パフォーマンス | > 1M pps | > 100K pps |
| veth対応 | 不可 | 可能 |
| POC環境 | △ | ✅ |

**デフォルト（Auto）動作**：
1. Native モード試行
2. 失敗時 → Generic モードに自動フォールバック
3. ログで動作モードを確認可能

### Zero-copy / Copy モード の選択

**重要**: XDP側では指定しません。VPP側で自動選択されます。

```bash
# VPP側で af_xdp インターフェース作成時、NIC仕様に応じて自動選択
vppctl create interface af_xdp host-if eth0 name afxdp0

# Zero-copy or Copy を確認
vppctl show interface afxdp0 detail
```

- **Zero-copy**: NICが対応している場合のみ使用
- **Copy**: NIC非対応時またはveth使用時は自動フォールバック

XDPプログラム側は「Native/Generic」を選択するだけで、
パケット処理のZero-copy/CopyはすべてVPP側で判定・実行されます。

---

## ✅ XDP 機能仕様（凍結）

以下の機能はv8.1で凍結されます。今後追加実装はありません。

### ✅ XDP に実装済みの機能

1. **マジックナンバー認証**
   - 単純な比較ロジック（Time-based Magic Number 不要）
   - UDP:8888 でのワンタイム認証

2. **SYN 攻撃検知**
   - 3秒周期のカウンタ増加監視
   - 閾値（Delta >= 300）超過で自動隔離

3. **優先度管理**
   - 3段階優先度（1=Bulk, 2=Normal, 3=VIP）
   - 自動降格・復帰ロジック

4. **基本統計情報**
   - パケット数、バイト数、SYN/RST/ACK カウント
   - フロー開始時刻、継続時間
   - ユーザーID、優先度ステータス、L7プロトコルラベル

5. **トークンバケット QoS**
   - Priority に基づくレート制限
   - Early Drop 確率制御

6. **マイクロセグメンテーション**
   - L4 レベル（IP+Protocol+Port）でのフロー制御

### ❌ XDP には実装しない機能（VPP側で実装）

- Time-based Magic Number（TOTP等の時間ベース認証）
- DSCP/VLAN 書き換え
- マルチレベル ポリシー（複雑な ACL）
- Deep Packet Inspection（L7 解析）
- XDP Metadata（拡張機能）

---

## 🔴 Data-Plane Authentication (物理認証プロトコル)

API では発行された「チケット(マジックナンバー)」を使用し、以下の手順で認証とフロー制御を実現します。

**認証フロー（高レベル図）**:
```
┌─────────────────────────────────────────────────────────────┐
│ 1. Admin端末 → GET /auth/ticket?magic=0x{HEX}              │
│    （チケット発行リクエスト）                              │
│    ※ magic=0 は拒否。ロック中は 403 を返す。             │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ 2. Go Agent が CONFIG_MAP[0] = 0x{HEX} にセット             │
│    （eBPFカーネルに値を配布）                              │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ 3. クライアント端末 → UDP:8888にマジックナンバー(BigEndian) │
│    送信フォーマット: [IP Header][UDP Header][8バイト整数]  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ 4. eBPF カーネル層（XDP）                                    │
│    - CONFIG_MAP[0] との一致判定                             │
│    - 値が 0 または u64::MAX（番兵値）の場合は認証不可       │
│    - 一致 → AUTH_IPS[src_ip] に登録                        │
│             Priority: 2 (Normal/デフォルト)                 │
│             user_id: src_ip（送信元IPアドレス）[v8.2変更]  │
│    - 認証後 → CONFIG_MAP[0] = u64::MAX（番兵値）にリセット  │
│             ワンタイム消費完了（再利用不可）                │
│    - 不一致 → XDP_DROP（即時破棄）                          │
└─────────────────────────────────────────────────────────────┘
```

**重要**: 認証されていない IP からのパケット（UDP 8888番ポート以外）はすべて XDP_DROP されます。

---

## 📡 API エンドポイント仕様

### 1. GET /info

**説明**: 現在のXDP設定情報を取得

**レスポンス (JSON)**:
```json
{
  "interface": "eth0",
  "xdp_mode": "native",
  "timestamp": 1706123456,
  "version": "1.0.0",
  "note": "VPP determines zero-copy or copy mode automatically via af_xdp based on NIC capabilities"
}
```

**フィールド説明**:
- `interface`: XDP が動作しているインターフェース名
- `xdp_mode`: "native" or "generic" or "auto"（実際の動作モード）
- `timestamp`: API クエリ時刻（Unix タイムスタンプ）
- `version`: Go Agent のバージョン
- `note`: VPP側での処理についての補足

**AI 向けポイント**:
- XDP モード確認用。構成管理に使用

---

### 2. GET /auth/ticket

**説明**: 新しい「入場用マジックナンバー」を発行し、カーネルにセット。
リプレイ攻撃を防ぐため、チケットは 1回限りの消費（ワンタイム）。

**パラメータ**: `magic=0x{HexValue}` または `magic={HexValue}`

**例**:
```
GET /auth/ticket?magic=0xdeadbeefcafebabe
GET /auth/ticket?magic=deadbeefcafebabe
```

**レスポンス**:
```
Ticket 0xdeadbeefcafebabe active.
```

**エラーレスポンス（v8.2 新規）**:
```
400 magic=0 is reserved and cannot be issued as a ticket
403 Ticket issuance is locked. Restart agent to unlock.
403 Source IP is blacklisted
```

**内部処理**:
1. Go Agent がリクエストを受け取る
2. `/auth/lock` 呼び出し済みの場合は 403 を返す（発行禁止）
3. リクエスト送信元IPがブラックリスト中の場合は 403 を返す
4. magic=0 の場合は 400 を返す（番兵値との衝突防止）
5. `CONFIG_MAP[0] = magic` に設定（既存値を上書き）
6. クライアント が UDP:8888 にこのナンバーを送信
7. eBPF が一致判定し、一致したら即座に `CONFIG_MAP[0] = u64::MAX`（番兵値）にリセット
8. その IP へ `Priority: 2 (Normal)` で `AUTH_IPS[src_ip]` を作成（user_id = src_ip）

**AI 向けポイント**:
- チケット発行イベントは `/auth/logs` に記録
- リプレイ攻撃を防ぐため、定期的に新チケットを発行
- **magic=0 は絶対に指定しないこと**（旧実装の偽無効化パターン）
- 攻撃検知時は `/auth/lock` でロックし、チケット発行経路を完全に封じること

---

### 3. GET /auth/logs

**説明**: 「どのマジックナンバーが発行されたか」「いつ」の履歴を取得。
監査とセキュリティ分析に使用。

**レスポンス (JSON)**:
```json
[
  {
    "timestamp": "2024-01-25T12:34:56Z",
    "remote_ip": "192.168.1.1:54321",
    "magic": "0xdeadbeefcafebabe",
    "action": "TICKET_ISSUED"
  },
  {
    "timestamp": "2024-01-25T12:35:10Z",
    "remote_ip": "10.0.0.50:55555",
    "magic": "0x1234567890abcdef",
    "action": "TICKET_ISSUED"
  }
]
```

**AI 向けポイント**:
- チケット発行の頻度と IP の関連性を分析
- 突然の大量発行は管理者の指示可能性 or 攻撃

---

### 4. GET /auth/priority

**説明**: 認証済みIP に対して、通信の優先度を動的に変更します。

**パラメータ**: `ip={IPv4}&level={1, 2, or 3}`

**例**:
```
GET /auth/priority?ip=192.168.1.100&level=1
```

**優先度定義**:

#### Level 1 (Bulk / 最低優先度)
- **用途**: 大容量データ転送、ログ送信など重要度低
- **QoS 帯域制御レート**: `設定値 × 1` (乗数なし)
- **Early Drop**: トークンが MAX_TOKENS/2 以下の場合、カーネルが30%の確率でランダムドロップ
- **実効利用**: 帯域制御は「厳しく」、優先度は「最低」
- **リカバリ時間**: `/stats` で Delta が 300未満になった後、1分間安定で Level 2 に自動復帰

#### Level 2 (Normal / 標準優先度)
- **用途**: 通常の Web 通信、SSH など
- **QoS 帯域制御レート**: `設定値 × 10` (Bulk の 10倍)
- **Early Drop**: トークン残量が多い場合、ドロップ確率は低い
- **実効利用**: 帯域制御は「緩い」、優先度は「中程度」
- **デフォルト**: ticket 発行時のデフォルト優先度

#### Level 3 (VIP / Platinum)
- **用途**: 経営層、重要業務、SLA保証対象
- **QoS 制御**: **完全無制限** - トークンバケット計算をバイパス
- **Early Drop**: なし（常に XDP_PASS）
- **実効利用**: ハードウェアの物理線速度まで通信を許可
- **ネットワークボトルネック**: 他の Level 1/2 ユーザーの QoS に影響

**AI 向けポイント**:
- `/stats` の `policy_status` フィールドが現在の優先度を記録
- DDoS/SYN Flood 時、Level を下げて効果的に制限
- ユーザーの「通常の優先度」と「現在の優先度」の乖離は異常兆候

---

### 5. GET /auth/revoke

**説明**: 特定の IP の認証権を取り消し（ログアウト）し、ブラックリストに登録します。

**パラメータ**: `ip={IPv4}`

**例**:
```
GET /auth/revoke?ip=192.168.1.100
```

**レスポンス（v8.2 変更）**:
```
Revoked and blacklisted: 192.168.1.100 (for 10m0s)
```

**内部処理（v8.2 変更）**:
1. `AUTH_IPS` から該当IPを削除
2. **ブラックリストに登録**（デフォルト10分間）
3. `/auth/logs` に `REVOKED_AND_BLACKLISTED:{ip}` を記録

**AI 向けポイント**:
- このエンドポイント呼び出し → ネットワークから即座にその IP を排除
- revoke 後はブラックリスト期間中 `/auth/ticket` 経由での再認証も不可
- ブラックリスト有効期間は `/auth/blacklist` で確認可能

---

### 5b. GET /auth/lock  *(v8.2 新規)*

**説明**: チケット発行を恒久的にロックします。一度ロックするとエージェント再起動まで解除不可。
攻撃者の `sase_agent` が連続的に `/auth/ticket` を呼び出す攻撃への根本的な対策。

**パラメータ**: なし

**例**:
```
GET /auth/lock
```

**レスポンス**:
```
Ticket issuance locked. No new tickets will be accepted until agent restart.
```

**内部処理**:
1. `ticketLocked = true` をセット（メモリ上のフラグ）
2. 以降の `/auth/ticket` リクエストはすべて 403 を返す
3. 解除は Go エージェントの再起動のみ

**AI 向けポイント**:
- チケット大量発行攻撃を検知したら即座に呼び出す
- ロック後は `/auth/blacklist` でブラックリストを確認し、必要に応じて手動対応
- ロック状態でも `/auth/revoke`、`/stats`、`/drop/block` は引き続き利用可能

---

### 5c. GET /auth/blacklist  *(v8.2 新規)*

**説明**: `/auth/revoke` によってブラックリスト登録されたIPとその有効期限一覧を返す。

**パラメータ**: なし

**レスポンス (JSON)**:
```json
[
  {
    "ip": "192.168.1.100",
    "revoked_at": "2024-01-25T12:34:56Z",
    "expires_in": "9m30s"
  }
]
```

**フィールド説明**:
- `ip`: ブラックリスト中のIPアドレス
- `revoked_at`: revoke が実行された時刻（RFC3339）
- `expires_in`: ブラックリスト残り時間（デフォルト10分、経過後は自動削除）

**AI 向けポイント**:
- ブラックリスト期間中は `/auth/ticket` 経由でも再認証不可
- 期限切れ後は自動的にリストから削除される（再認証を試みることが可能になる）
- 継続的な脅威に対しては `/auth/lock` と組み合わせて使用

---

**説明**: カーネル内部状態（現在のマジックナンバー、認証有効期限）を確認。

**レスポンス (JSON)**:
```json
{
  "current_magic_ticket": "0xdeadbeefcafebabe",
  "auth_duration_ns": 300000000000
}
```

**フィールド説明**:
- `current_magic_ticket`: 現在有効なチケット（16進数）
  - `0x0`: 未発行
  - `0xffffffffffffffff`: 認証後リセット済み（番兵値）。次の `/auth/ticket` 呼び出しを待つ状態。
  - それ以外: 有効なチケットが待機中（クライアントによる UDP:8888 認証待ち）
- `auth_duration_ns`: チケット認証から有効期限までのナノ秒数
  （デフォルト: 300秒 = 300,000,000,000 ns）

**⚠️ v8.2 変更点（破壊的変更）**:
- v8.1 では認証後に `current_magic_ticket = 0x0` だったが、これは「未発行」と区別できなかった
- v8.2 からは認証後のリセット値が `0xffffffffffffffff`（u64::MAX）になった
- AI が `0x0` を「発行済み・認証待ち」と判定していた場合は修正が必要

**AI 向けポイント**:
- `0xffffffffffffffff` は正常な認証完了後の状態（エラーではない）
- チケット発行履歴と照合して、認証タイムアウトを予測

---

### 7. GET /stats

**説明**: **FlowKey (IP, Port, Protocol) 単位** の詳細な通信統計を取得します。

**レスポンス (JSON) サンプル**:
```json
[
  {
    "ip": "192.168.1.100",
    "port": 443,
    "protocol": "tcp",
    "stats": {
      "packets": 15234,
      "bytes": 5123456,
      "dropped_packets": 120,
      "syn_packets": 45,
      "rst_packets": 3,
      "ack_packets": 14988,
      "last_ts": 1706123456789000000,
      "flow_start_ns": 1706120000000000000,
      "user_id": 12345,
      "policy_status": 2,
      "l7_proto_label": 1,
      "pkt_min": 64,
      "pkt_max": 1500
    }
  }
]
```

**フィールド詳細説明**:

#### 【基本フィールド】
- `packets` (u64): 通過した全パケット数
- `bytes` (u64): 通過したバイト数（ドロップされたパケットは計上されない）
- `dropped_packets` (u64): 破棄されたパケット数（Block/QoS制御/未認証 の合計）
- `syn_packets` (u64): TCP SYN フラグが立ったパケット数
  - ここが急増 → "SYN Flood" 疑い
- `rst_packets` (u64): TCP RST フラグが立ったパケット数（接続強制終了）
- `ack_packets` (u64): TCP ACK フラグが立ったパケット数
  - 用途: `ack_packets / (syn_packets + 1)` で「ハーフオープン接続」を検知
  - 比率 < 0.5 → 接続確立に失敗している疑い or SYN Flood
  - 比率 = 1.0 → 正常な確立・維持フェーズ
- `last_ts` (u64): 最後にこのフローが観測された時刻（ナノ秒、カーネル時間）
- `pkt_min` / `pkt_max` (u32): 通過パケットの最小/最大サイズ

#### 【AI/ML 推論用フィールド】
- `flow_start_ns` (u64): このフロー統計の作成時刻（ナノ秒）
  - 用途: `duration = (last_ts - flow_start_ns) / 1e9` で継続期間（秒）を計算
  - < 1秒: バースト/DoS 疑い
  - 1-3600秒: 通常
  - > 3600秒: 長期データ転送 or DLP（データ流出）

- `user_id` (u32): 認証時に割り当てられたユーザーID
  - **v8.2 変更**: 送信元IPアドレス（src_ip）がそのまま格納される
  - v8.1 以前は magic 値の下位32bit だったが、攻撃者が任意のIDを偽装できる脆弱性があった
  - 用途: IP が変わっても同じユーザー起源のフローを追跡可能（現実装では IP と一致）

- `policy_status` (u32): 現在適用されている優先度ステータス
  - 1 = Bulk（制限厳しい）
  - 2 = Normal（標準）
  - 3 = VIP（無制限）
  - 用途: ユーザーの「権限レベル」と「通信パターン」の矛盾を検知

- `l7_proto_label` (u32): ポート番号から推測されるアプリケーションプロトコル
  - 1 = HTTP/HTTPS (port 80, 443)
  - 2 = DNS (port 53)
  - 3 = SSH (port 22)
  - 0 = その他（未分類）
  - 用途: 「このユーザーは DNS しか使わないはずなのに SSH を使用」→ 異常

---

### 8. GET /top

**説明**: 通信量(packets)が多い順に上位10件のフロー情報を返却。
ホットスポット IP の特定と、重要度の低い Identity の優先度引き下げに利用。

**レスポンス**: `/stats` と同形式（ただし上位10件に制限）

**AI 向けポイント**:
- 予期しない IP がランク上位 → 侵害の可能性
- DDoS 対象の IP がランクイン → 実攻撃中

---

### 9. GET /qos/set

**説明**: IP 単位で「トークンバケット方式」の帯域制御を適用します。
実効帯域制御レートは `設定値 × (Priority に応じた乗数)` になります。

**パラメータ**: `ip={IPv4}&limit={Bytes/sec}`

**例**:
```
GET /qos/set?ip=192.168.1.100&limit=1000000
```
→ 192.168.1.100 に対して、1 Mbps (1,000,000 Bytes/sec) の基本レートを設定

**実効レート計算（eBPF カーネル内）**:
```
Priority 1 (Bulk)  → 実効レート = limit × 1 = limit
Priority 2 (Normal) → 実効レート = limit × 10 = 10 × limit
Priority 3 (VIP)    → QoS制御を完全にバイパス（無制限）
```

**トークンバケットの動作**:
1. 定期的に `tokens = min(MAX_TOKENS, tokens + elapsed × limit × multiplier / 1s)` でリフィル
2. パケット到着 → `if tokens >= pkt_size { tokens -= pkt_size; PASS } else { DROP }`
3. Priority 1 かつ tokens < MAX_TOKENS/2 → 30% 確率で Early Drop

**AI 向けポイント**:
- `/stats` の `dropped_packets` が増加 → QoS 制御が効いている証拠
- `bytes` が増加しないのに `packets` が増加 → パケットが小さい = 制御下

---

### 10. GET /drop/block

**説明**: L4 レベル（IP + Protocol + Port）単位の即時フロー破棄。
最も粒度の細かいマイクロセグメンテーション。

**パラメータ**: `ip={IPv4}&proto={tcp/udp/icmp}&port={PortNum}`

**例**:
```
GET /drop/block?ip=192.168.1.100&proto=tcp&port=3389
```
→ 192.168.1.100 からの RDP (TCP:3389) をすべてドロップ

**AI 向けポイント**:
- サービス単位（例：SSH:22 ポートのみ）のピンポイント制御
- ポートスキャン検知後、スキャン対象ポートすべてを一括ブロック可能

---

### 11. GET /drop/unblock

**説明**: `/drop/block` で設定したルールを削除し、通信を再度許可。

**パラメータ**: `/drop/block` と同じ形式

**例**:
```
GET /drop/unblock?ip=192.168.1.100&proto=tcp&port=3389
```

---

### 12. GET /drop/list

**説明**: 現在 `/drop/block` によって設定されているフロー制御ルール一覧を表示。

**レスポンス (JSON)**:
```json
{
  "192.168.1.100:3389 [tcp]": "BLOCKED",
  "10.0.0.50:22 [tcp]": "BLOCKED"
}
```

---

## 🤖 Autonomous Defense Logic (Go Agent の自律防御・復旧規則)

**説明**: Go エージェントは AI の指示を待たず、以下の「即時防御」的なルールを自動実行します。
ただし最終的な判断・承認は AI が行います。

### A. 自動隔離 (Isolation) - 3秒周期の SYN Flood 検知

**トリガー条件**:
- 同一の FlowKey に対して **3秒間**に **SYN ΔCount >= 300** を観測した状態が **2回連続**
  - ΔCount = 「前回測定」から「今回測定」への増加量
  - 例: SYN_packets が 100 → 450 なら ΔCount = 350

**自動アクション**:
- 該当 IP の `Priority` を強制的に **Level 1 (Bulk)** に引き下げ
- 帯域制御が「厳しく」なり、Early Drop 確率が上昇
- **ログ出力**: `[Defense] 🛡 Isolated {IP}: Persistent SYN Spike on port {PORT} (Delta: {DELTA})`

**狙い**: SYN Flood 攻撃の影響をカーネル層で最小化

### B. 自動復旧 (Recovery) - 安定化による Level 復帰

**トリガー条件**:
- 隔離状態(Level 1)の IP において、**ΔCount < 300** な状態が成立し、**隔離から 30秒以上経過**

**自動アクション**:
- 該当 IP の `Priority` を **Level 2 (Normal)** に自動復帰
- ログ出力: `[Defense] ✓ Restored {IP}: Auto-recovery after 30s`

**狙い**: 正常化した IP を素早く復帰させ、ユーザー体験を損なわない

---

## 💡 推奨される AI/ML 推論フロー

### Python での実装例

```python
import requests
import json
from datetime import datetime

class XDPOrchestrator:
    def __init__(self, sase_api_url="http://localhost:8080"):
        self.api_url = sase_api_url
        self._revoke_counts = {}  # ip → revoke回数
    
    def get_all_stats(self):
        """全フロー統計を取得"""
        response = requests.get(f"{self.api_url}/stats")
        return response.json()
    
    def analyze_flow(self, flow):
        """フロー異常スコアリング"""
        flow_data = flow['stats']
        
        # メトリクス計算
        flow_duration = (flow_data['last_ts'] - flow_data['flow_start_ns']) / 1e9
        ack_ratio = flow_data['ack_packets'] / (flow_data['syn_packets'] + 1)
        throughput = flow_data['bytes'] / (flow_duration + 1) if flow_duration > 0 else 0
        
        # 異常スコアリング
        anomaly_score = 0
        
        # SYN Flood 検知
        if flow_data['syn_packets'] > 1000:
            anomaly_score += 0.3
        
        # Connection failure 検知
        if ack_ratio < 0.5:
            anomaly_score += 0.3
        
        # Long-lived フロー検知
        if flow_duration > 7200:
            anomaly_score += 0.2
        
        # VIP の過度な利用
        if flow_data['policy_status'] == 3 and throughput > 100_000_000:
            anomaly_score += 0.2
        
        return {
            'ip': flow['ip'],
            'port': flow['port'],
            'protocol': flow['protocol'],
            'anomaly_score': anomaly_score,
            'metrics': {
                'duration_sec': flow_duration,
                'ack_ratio': ack_ratio,
                'throughput_bps': throughput
            }
        }
    
    def execute_response(self, analysis):
        """異常検知に基づいて応答を実行"""
        if analysis['anomaly_score'] > 0.7:
            ip = analysis['ip']
            requests.get(f"{self.api_url}/auth/revoke?ip={ip}")
            print(f"[AI] Revoked {ip} due to high anomaly score")

            # 同一IPが繰り返し revoke されている場合は /auth/lock で根本封鎖
            # （revoke → 再認証 → revoke のループを防ぐ）
            # 注意: /auth/lock は再起動まで解除不可。確実な攻撃判断時のみ使用。
            self._revoke_counts[ip] = self._revoke_counts.get(ip, 0) + 1
            if self._revoke_counts[ip] >= 3:
                resp = requests.get(f"{self.api_url}/auth/lock")
                print(f"[AI] Locked ticket issuance (repeated revoke on {ip}): {resp.text.strip()}")
        
        elif analysis['metrics']['ack_ratio'] < 0.3:
            ip = analysis['ip']
            requests.get(f"{self.api_url}/auth/priority?ip={ip}&level=1")
            print(f"[AI] Downgraded {ip} to Level 1 due to low ACK ratio")
        
        elif analysis['anomaly_score'] > 0.5:
            print(f"[AI] Warning: {analysis['ip']} has anomaly score {analysis['anomaly_score']}")

# 使用例
orchestrator = XDPOrchestrator()

while True:
    stats = orchestrator.get_all_stats()
    for flow in stats:
        analysis = orchestrator.analyze_flow(flow)
        if analysis['anomaly_score'] > 0:
            orchestrator.execute_response(analysis)
    
    # 1分ごとに分析
    import time
    time.sleep(60)
```

---

## 📋 統計フィールド完全マッピング表

| フィールド | 型 | 追加バージョン | 用途 | 計算式/推奨 |
|---|---|---|---|---|
| packets | u64 | v8.0 | トラフィック総量 | N/A |
| bytes | u64 | v8.0 | バイト総量 | N/A |
| dropped_packets | u64 | v8.0 | 破棄パケット | `if >= packets/10 → 異常` |
| syn_packets | u64 | v8.0 | SYN数 | `if > 1000 → SYN Flood疑い` |
| rst_packets | u64 | v8.0 | RST数 | `if high → 接続不安定` |
| ack_packets | u64 | v8.1 | ACK数 | `ratio = ack / (syn+1)` |
| last_ts | u64 | v8.0 | 最終観測時刻 | `now() - last_ts → 非アクティブ判定` |
| flow_start_ns | u64 | v8.1 | フロー開始時刻 | `duration = (last_ts - flow_start_ns) / 1e9` |
| user_id | u32 | v8.1 / **v8.2変更** | ユーザーID（v8.2以降 = src_ip と同値） | `ユーザー単位の異常追跡` |
| policy_status | u32 | v8.1 | 優先度 | `1=制限, 2=標準, 3=無制限` |
| l7_proto_label | u32 | v8.1 | L7プロトコル推測 | `1=HTTP, 2=DNS, 3=SSH, 0=Other` |
| pkt_min / pkt_max | u32 | v8.0 | パケットサイズ | `if pkt_max > MTU → 異常` |

---

## 🔒 セキュリティ上の注意点

1. **チケット（マジックナンバー）の安全性**
   - チケットは必ず TLS/HTTPS で転送
   - 平文 UDP で流さない（中間者攻撃の危険）
   - チケット値はランダムに生成（予測不可）
   - **magic=0 は絶対に使用しない**（Go が 400 で拒否。旧実装の偽無効化パターン）

2. **API エンドポイント保護**
   - `/auth/ticket` は信頼できる管理者ネットワークからのみアクセス可能に
   - `/auth/lock` は一度呼ぶと再起動まで解除不可。誤呼び出しに注意
   - `/auth/priority`, `/drop/block`, `/auth/revoke` は認可チェック実装

3. **eBPF サンドボックス**
   - カーネル内で実行されるため、ユーザー空間コードより高速・安全
   - ただし eBPF には命令数上限と関数呼び出し制限がある

4. **ブラックリストの限界（v8.2 実動作確認済み）**
   - `/auth/revoke` のブラックリストは「その IP からの `/auth/ticket` 呼び出し」を拒否する
   - `sase_agent` が localhost（127.0.0.1）からチケットを発行する場合はブラックリストをすり抜ける
   - **根本的な封鎖には `/auth/lock` が必須**。再遮断が繰り返される場合は必ず呼び出すこと

---

## 📝 実装確認チェックリスト

### XDP 側（v8.2 セキュリティ修正済み・凍結）
- [x] main.go が全エンドポイント実装
- [x] main.rs が認証・SYN検知・優先度管理実装
- [x] Native/Generic/Auto モード選択機能
- [x] 統計情報（全13フィールド）記録機能
- [x] 自動隔離・復帰ロジック
- [x] /auth/lock エンドポイント（チケット発行恒久禁止）
- [x] /auth/blacklist エンドポイント（revoke済みIP一覧・残り時間）
- [x] /auth/revoke がブラックリスト登録を兼ねるよう変更
- [x] magic=0 の発行拒否（番兵値衝突防止）
- [x] eBPF: 認証後 CONFIG_MAP[0] を u64::MAX（番兵値）でリセット
- [x] eBPF: user_id を src_ip から取得（magic値の下位32bit流用を廃止）

### VPP 側（次フェーズ）
- [ ] af_xdp インターフェース統合
- [ ] メタデータ読取・処理
- [ ] 優先度に基づく QoS 適用
- [ ] DSCP/VLAN 書き換え

### LLM オーケストレータ側（推奨実装）
- [ ] `/stats` からのメトリクス計算
- [ ] 異常スコアリング実装
- [ ] 自動応答ロジック
- [ ] インシデント ログ記録

---

## 🎯 結論：XDP v8.2 仕様確定

**XDP 側は v8.2 で完全凍結されます。**

以下のフェーズで進行します：

| フェーズ | 担当 | 完了 | 次アクション |
|---------|------|------|----------|
| Phase 1 | XDP (Go + Rust) v8.2 | ✅ | - |
| Phase 2 | VPP REST API (Python) | ⏳ | af_xdp 統合 |
| Phase 3 | LLM Orchestrator (Python) | ⏳ | 異常検知・自動応答 |

**今後の XDP 機能追加はありません。**
追加要件は **VPP 側** または **LLM オーケストレータ側** で実装してください。
"""
