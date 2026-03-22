# Copyright (c) 2026 hidemi-k
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

# XDP Firewall API 仕様書 (v9.1) - FW Edition
# Flow-Control, QoS, Observability, Auto-Mitigation
# main.go (FW版) & main.rs (eBPF Kernel-space FW版) 完全仕様リファレンス
# LLMオーケストレータ向け - Native/Generic XDP Mode対応

"""
## XDP Firewall API 仕様 (v9.1) - FW Edition

【v9.0 → v9.1 変更点】
- Go Agent に SYN スパイク自動ミティゲーション機能を追加
  - SYN Delta >= 300 が 2回連続 → QOS_MAP[src_ip] = 10KB/s を自動設定
  - 2分間安定後 → QOS_MAP から自動削除（復旧）
- 新規エンドポイント追加:
  - GET /qos/list  : 現在適用中の全 QoS ポリシー一覧
  - GET /qos/get   : 特定 IP の QoS ポリシー確認

---

## 📌 起動方法

```bash
sudo ./sase-agent -iface eth0
sudo ./sase-agent -iface eth0 -xdp-mode native
sudo ./sase-agent -iface eth0 -xdp-mode generic
```

---

## ✅ XDP 機能仕様（FW版）

### ✅ 実装済み機能

1. **ブロックリスト（DROP_LIST）**
   - L4レベル（IP + Protocol + Port）単位の即時フロー遮断

2. **トークンバケット QoS（QOS_MAP）**
   - IP単位のレート制限
   - MAX_TOKENS = 10,000,000 bytes（バースト上限）
   - トークン不足時 → XDP_DROP

3. **通信統計（STATS_MAP）**
   - FlowKey (IP + Port + Protocol) 単位での統計記録

4. **SYNスパイク自動ミティゲーション（Go Agent）**
   - 3秒周期で SYN Delta を計測
   - Delta >= 300 を 2回連続検知 → QOS_MAP[src_ip] = 10KB/s 自動設定
   - 2分間 Delta < 300 が続いたら QOS_MAP から自動削除（復旧）
   - ログ例:
     [Defense] 🛡️  Mitigated 10.0.1.30: QoS set to 10000 B/s (SYN spike x2)
     [Recovery] ✅ Restored 10.0.1.30: QoS mitigation lifted after 2m0s

---

## 📡 API エンドポイント仕様

### 1. GET /info

**説明**: 現在のXDP設定情報を取得

**レスポンス (JSON)**:
```json
{
  "interface": "eth0",
  "xdp_mode": "generic",
  "timestamp": 1706123456,
  "version": "1.0.0"
}
```

---

### 2. GET /stats

**説明**: FlowKey (IP + Port + Protocol) 単位の詳細な通信統計を取得

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
      "user_id": 0,
      "policy_status": 0,
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
- `bytes` (u64): 通過したバイト数（ドロップパケットは計上されない）
- `dropped_packets` (u64): 破棄されたパケット数（Block / QoS制御 の合計）
- `syn_packets` (u64): TCP SYN フラグのパケット数
- `rst_packets` (u64): TCP RST フラグのパケット数
  - SYN Flood 時: ターゲットが SYN に対して RST を返すため syn ≒ rst となる
  - 「SYN大量 かつ ACK=0 かつ rst >= syn×30%」→ SYN Flood の兆候
- `ack_packets` (u64): TCP ACK フラグのパケット数
  - `ack_packets / (syn_packets + 1) < 0.5` → ハーフオープン接続
- `last_ts` (u64): 最後にこのフローが観測された時刻（ナノ秒）
- `flow_start_ns` (u64): このフロー統計の作成時刻（ナノ秒）
  - `duration = (last_ts - flow_start_ns) / 1e9` で継続期間（秒）を計算
- `pkt_min` / `pkt_max` (u32): パケットサイズの最小/最大

#### 【参考フィールド（FW版では固定値）】
- `user_id` (u32): FW版では常に 0
- `policy_status` (u32): FW版では常に 0
- `l7_proto_label` (u32): 1=HTTP/S, 2=DNS, 3=SSH, 0=Other

---

### 3. GET /top

**説明**: 通信量(packets)が多い順に上位10件のフロー情報を返却

**レスポンス**: `/stats` と同形式（上位10件）

---

### 4. GET /qos/set

**説明**: IP単位でトークンバケット方式の帯域制御を手動適用

**パラメータ**: `ip={IPv4}&limit={Bytes/sec}`

**例**:
```
GET /qos/set?ip=192.168.1.100&limit=1000000
```

**トークンバケットの動作**:
1. `tokens = min(10_000_000, tokens + elapsed × limit / 1s)` でリフィル
2. パケット到着 → `if tokens >= pkt_size { PASS } else { DROP }`

**LLM向けポイント**:
- 自動ミティゲーション（10KB/s）より強い制限をかけたい場合に使用
- 例: `limit=1000`（1 KB/s）でほぼ完全遮断

---

### 5. GET /qos/list

**説明**: 現在 QOS_MAP に設定されている全 IP の QoS ポリシー一覧を返却
自動ミティゲーションの適用確認に使用する。

**レスポンス (JSON)**:
```json
{
  "10.0.1.30": {
    "limit_bytes_per_sec": 10000,
    "tokens": 9341417,
    "last_updated": 3260748270632
  }
}
```

**フィールド説明**:
- `limit_bytes_per_sec`: 設定された帯域上限 (B/s)
  - 10000 = 自動ミティゲーション適用中
  - その他 = 手動で /qos/set により設定
- `tokens`: 現在のトークン残量
  - 0 に近い → 攻撃継続中でドロップ発生
  - MAX(10_000_000) に近い → 帯域に余裕あり or 攻撃停止後
- `last_updated`: 最終更新時刻（カーネルナノ秒タイムスタンプ）

**LLM向けポイント**:
- 空({}) → ミティゲーション未適用、または復旧済み
- エントリあり → ミティゲーション適用中
- `tokens` が 0 に近い → QoS が実際にドロップを起こしている証拠

---

### 6. GET /qos/get

**説明**: 特定 IP の QoS ポリシーを取得

**パラメータ**: `ip={IPv4}`

**例**:
```
GET /qos/get?ip=10.0.1.30
```

**レスポンス例（適用中）**:
```json
{
  "ip": "10.0.1.30",
  "limit_bytes_per_sec": 10000,
  "tokens": 4567,
  "last_updated": 3260748270632
}
```

**レスポンス例（未適用）**:
```json
{
  "ip": "10.0.1.30",
  "status": "no QoS policy"
}
```

---

### 7. GET /drop/block

**説明**: L4レベル（IP + Protocol + Port）単位の即時フロー遮断

**パラメータ**: `ip={IPv4}&proto={tcp/udp/icmp}&port={PortNum}`

**例**:
```
GET /drop/block?ip=192.168.1.100&proto=tcp&port=3389
```

---

### 8. GET /drop/unblock

**説明**: `/drop/block` で設定したルールを削除し、通信を再度許可

**パラメータ**: `/drop/block` と同じ形式

---

### 9. GET /drop/list

**説明**: 現在のブロックルール一覧

**レスポンス (JSON)**:
```json
{
  "192.168.1.100:3389 [tcp]": "BLOCKED",
  "10.0.0.50:22 [tcp]": "BLOCKED"
}
```

---

## 🤖 自動ミティゲーション仕様（Go Agent）

Go Agent は 3秒周期で SYN Delta を計測し、以下を自動実行します。

```
SYN Delta >= 300 を 2回連続検知
    ↓
QOS_MAP[src_ip] = 10KB/s を自動設定（即時・人間確認なし）
ログ: [Defense] 🛡️  Mitigated {IP}: QoS set to 10000 B/s (SYN spike x{count})

2分間 Delta < 300 が続いたら
    ↓
QOS_MAP から自動削除（復旧）
ログ: [Recovery] ✅ Restored {IP}: QoS mitigation lifted after 2m0s
```

**LLMオーケストレータとの役割分担**:

| 処理 | 担当 | 確認 |
|---|---|---|
| QoS自動減速（ミティゲーション） | Go Agent（即時・自律） | なし |
| DROP_LISTブロック | LLMオーケストレータ | 人間確認あり |

**LLM推奨フロー**:
1. `/qos/list` で自動ミティゲーション適用状況を確認
2. 攻撃が継続していれば `/drop/block` で完全遮断（人間確認）
3. `/drop/block` 後も `/qos/list` にエントリが残る場合は Go Agent の復旧を待つ
   または `/qos/set?ip=X&limit=0` は使わない（0は設定不可）

---

## 💡 推奨される LLM 推論フロー

### Python実装例

```python
import requests
import time

class FWOrchestrator:
    def __init__(self, api_url="http://localhost:8080"):
        self.api_url = api_url

    def get_stats(self):
        return requests.get(f"{self.api_url}/stats").json()

    def get_top(self):
        return requests.get(f"{self.api_url}/top").json()

    def get_qos_list(self):
        return requests.get(f"{self.api_url}/qos/list").json()

    def get_qos(self, ip):
        return requests.get(f"{self.api_url}/qos/get?ip={ip}").json()

    def set_qos(self, ip, limit_bytes_per_sec):
        requests.get(f"{self.api_url}/qos/set?ip={ip}&limit={limit_bytes_per_sec}")
        print(f"[FW] QoS set {ip} → {limit_bytes_per_sec} B/s")

    def block(self, ip, proto, port):
        requests.get(f"{self.api_url}/drop/block?ip={ip}&proto={proto}&port={port}")
        print(f"[FW] Blocked {proto}://{ip}:{port}")

    def unblock(self, ip, proto, port):
        requests.get(f"{self.api_url}/drop/unblock?ip={ip}&proto={proto}&port={port}")
        print(f"[FW] Unblocked {proto}://{ip}:{port}")

    def analyze(self, flow):
        s = flow['stats']
        duration = (s['last_ts'] - s['flow_start_ns']) / 1e9
        ack_ratio = s['ack_packets'] / (s['syn_packets'] + 1)
        rst_ratio = s['rst_packets'] / (s['syn_packets'] + 1)
        drop_ratio = s['dropped_packets'] / (s['packets'] + 1)

        score = 0

        # SYN Flood (SYN大量 + ACK=0 + RST>=30%)
        if s['syn_packets'] > 1000 and ack_ratio < 0.1 and rst_ratio >= 0.3:
            score += 0.5

        # SYN Flood (RST=0パターン: ターゲットが応答しない)
        if s['syn_packets'] > 1000 and ack_ratio < 0.1 and s['rst_packets'] == 0:
            score += 0.5

        # ハーフオープン接続
        if ack_ratio < 0.5:
            score += 0.2

        # 長期フロー（データ流出疑い）
        if duration > 7200:
            score += 0.1

        return {
            'ip': flow['ip'],
            'port': flow['port'],
            'protocol': flow['protocol'],
            'anomaly_score': min(score, 1.0),
            'metrics': {
                'duration_sec': duration,
                'ack_ratio': ack_ratio,
                'rst_ratio': rst_ratio,
                'drop_ratio': drop_ratio,
            }
        }

    def run(self):
        while True:
            # 自動ミティゲーション状況確認
            qos_list = self.get_qos_list()
            if qos_list:
                print(f"[FW] Auto-mitigation active: {list(qos_list.keys())}")

            stats = self.get_top()
            for flow in stats:
                result = self.analyze(flow)
                score = result['anomaly_score']
                ip = result['ip']
                port = result['port']
                proto = result['protocol']

                if score >= 0.5:
                    # 高スコア → ブロック（Go Agent のQoSミティゲーションと並行）
                    self.block(ip, proto, port)

                elif score >= 0.2:
                    print(f"[FW] Warning: {ip}:{port}/{proto} score={score:.2f}")

            time.sleep(60)
```

---

## 📋 統計フィールド完全マッピング表

| フィールド | 型 | 用途 | 計算式/推奨閾値 |
|---|---|---|---|
| packets | u64 | トラフィック総量 | N/A |
| bytes | u64 | バイト総量 | N/A |
| dropped_packets | u64 | 破棄パケット数（Block+QoS） | `>= packets/10 → QoS過剰 or 攻撃中` |
| syn_packets | u64 | SYN数 | `> 1000 → SYN Flood疑い` |
| rst_packets | u64 | RST数 | `rst/syn >= 0.3 かつ ack=0 → SYN Flood（ターゲット応答）` |
| ack_packets | u64 | ACK数 | `ack/(syn+1) < 0.5 → ハーフオープン疑い` |
| last_ts | u64 | 最終観測時刻（ns） | `now() - last_ts > 60s → 非アクティブフロー` |
| flow_start_ns | u64 | フロー開始時刻（ns） | `(last_ts - flow_start_ns)/1e9 → 継続秒数` |
| user_id | u32 | FW版では常に 0 | 参照不要 |
| policy_status | u32 | FW版では常に 0 | 参照不要 |
| l7_proto_label | u32 | L7プロトコル推測 | `1=HTTP/S, 2=DNS, 3=SSH, 0=Other` |
| pkt_min | u32 | 最小パケットサイズ | N/A |
| pkt_max | u32 | 最大パケットサイズ | `> 1500 → フラグメント or 異常` |

---

## 🎯 アーキテクチャ概要（v9.1）

```
パケット受信
    │
    ▼
[XDP / eBPF カーネル層 - main.rs]
    │
    ├─ DROP_LIST に一致？ → XDP_DROP
    │
    ├─ QOS_MAP でトークン不足？ → XDP_DROP
    │
    └─ それ以外 → XDP_PASS
              └─ STATS_MAP に統計記録

[Go Agent / ユーザー空間 - main.go]
    │
    ├─ SYNスパイク自動ミティゲーション（3秒周期）
    │   Delta>=300 × 2回 → QOS_MAP[ip]=10KB/s
    │   2分安定後 → QOS_MAP 削除（復旧）
    │
    └─ REST API (:8080)
           /info, /stats, /top
           /qos/set, /qos/list, /qos/get
           /drop/block, /drop/unblock, /drop/list

[LLM オーケストレータ - sase_agent.py]
    │
    ├─ /qos/list で自動ミティゲーション状況確認
    │
    ├─ /stats, /top を定期取得・分析
    │
    ├─ 異常検知 → /drop/block で遮断（人間確認）
    │
    └─ 正常化確認 → /drop/unblock で解除（人間確認）
```
"""
