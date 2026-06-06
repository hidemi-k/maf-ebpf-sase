#!/usr/bin/env python3
# Copyright (c) 2026 hidemi-k
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

"""
XDP Firewall Orchestrator

変更履歴:
  [1.4.0 → 1.7.0 移行時の変更点]
  1. OpenAI クライアントの import を最新 API に更新
     旧: agent_framework.openai.OpenAIChatClient
     新: agent_framework_openai.OpenAIChatCompletionClient

  2. OpenAIChatCompletionClient の初期化引数を変更
     旧: model_id=
     新: model=

  3. Message コンストラクタの変更
     旧: Message(role="user", text="...")
     新: Message(role="user", contents=["..."])

  4. Agent() の引数順変更（1.7.0 破壊的変更）
     旧: Agent(name=..., instructions=..., client=..., tools=...)
     新: Agent(client, name=..., instructions=..., tools=...)
     ← client が第1位置引数になった

  5. FWAnalyst.analyze() の asyncio.run() 廃止（1.7.0 非同期対処）
     旧: response = asyncio.run(self._agent.run(messages))
     新: Groq API を requests.post() で直接呼び出す（完全同期）

     理由:
       run_chat() は同期関数。そこから asyncio.run() を呼ぶと
       1.4.0 では ContextVar エラーが発生した。
       1.7.0 で内部修正された可能性があるが、MAF バージョン間の
       互換性を保つため、Agent.run() に依存しない直接呼び出しに統一する。
       FWAnalyst はツールを「LLM へのスキーマ提示」にのみ使い、
       実行は response.text の [EXEC:] 解析で行う設計なので、
       Agent.run() を使わなくても機能に影響なし。
"""

import os
import sys
import io
import json
import asyncio  # 現在未使用。将来の拡張用に保持。
import configparser
import requests
import re
import time
from datetime import datetime
from typing import Any, List, Tuple
from urllib.parse import urlparse

from agent_framework import Agent, Message
from agent_framework_openai import OpenAIChatCompletionClient

sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')

# ── 設定 ─────────────────────────────────────────────────────────────────────
GROQ_CONFIG_PATH = os.getenv(
    "SASE_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config.ini")
)

groq_api_key = ""
if os.path.exists(GROQ_CONFIG_PATH):
    _cfg = configparser.ConfigParser()
    _cfg.read(GROQ_CONFIG_PATH)
    if 'GROQ' in _cfg and 'GROQ_API_KEY' in _cfg['GROQ']:
        groq_api_key = _cfg['GROQ']['GROQ_API_KEY'].strip()

SASE_API_URL = os.getenv("SASE_API_URL", "http://localhost:8080")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", groq_api_key)
MODEL        = "llama-3.3-70b-versatile"

# Groq API エンドポイント（FWAnalyst が直接呼び出す）
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


# ── FW API ツール関数（tools= に登録・実行は直接呼び出し）────────────────────
def fw_get_top() -> str:
    """Get top 10 flows by packet count from XDP Firewall stats."""
    try:
        r = requests.get(f"{SASE_API_URL}/top", timeout=5)
        r.raise_for_status()
        return json.dumps(r.json(), ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_get_stats() -> str:
    """Get all flow statistics from XDP Firewall."""
    try:
        r = requests.get(f"{SASE_API_URL}/stats", timeout=5)
        r.raise_for_status()
        return json.dumps(r.json(), ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_drop_list() -> str:
    """Get the current block rule list from XDP Firewall drop_list map."""
    try:
        r = requests.get(f"{SASE_API_URL}/drop/list", timeout=5)
        r.raise_for_status()
        return json.dumps(r.json(), ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_drop_block(ip: str, proto: str, port: int) -> str:
    """Block a specific flow in XDP Firewall.

    Args:
        ip: Source IPv4 address to block (e.g. '192.168.1.100')
        proto: Protocol: 'tcp', 'udp', or 'icmp'
        port: Destination port number (e.g. 80)
    """
    try:
        r = requests.get(
            f"{SASE_API_URL}/drop/block",
            params={"ip": ip, "proto": proto, "port": port},
            timeout=5
        )
        r.raise_for_status()
        return r.text.strip()
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_drop_unblock(ip: str, proto: str, port: int) -> str:
    """Remove a block rule for a specific flow in XDP Firewall.

    Args:
        ip: Source IPv4 address to unblock (e.g. '192.168.1.100')
        proto: Protocol: 'tcp', 'udp', or 'icmp'
        port: Destination port number (e.g. 80)
    """
    try:
        r = requests.get(
            f"{SASE_API_URL}/drop/unblock",
            params={"ip": ip, "proto": proto, "port": port},
            timeout=5
        )
        r.raise_for_status()
        return r.text.strip()
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_set_qos(ip: str, limit: int) -> str:
    """Apply token-bucket QoS bandwidth limit to an IP in XDP Firewall.

    Args:
        ip: Target IPv4 address (e.g. '192.168.1.100')
        limit: Bandwidth limit in bytes per second (e.g. 10000 = 10KB/s)
    """
    try:
        r = requests.get(
            f"{SASE_API_URL}/qos/set",
            params={"ip": ip, "limit": limit},
            timeout=5
        )
        r.raise_for_status()
        return r.text.strip()
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_get_info() -> str:
    """Get XDP Firewall agent info (interface, xdp_mode, version)."""
    try:
        r = requests.get(f"{SASE_API_URL}/info", timeout=5)
        r.raise_for_status()
        return json.dumps(r.json(), ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_qos_list() -> str:
    """Get all QoS policies currently applied in XDP Firewall (QOS_MAP).

    Use this to confirm whether auto-mitigation is active.
    Returns a dict of {ip: {limit_bytes_per_sec, tokens, last_updated}}.
    Empty dict means no mitigation is active.
    tokens near 0 means QoS is actively dropping packets.
    """
    try:
        r = requests.get(f"{SASE_API_URL}/qos/list", timeout=5)
        r.raise_for_status()
        return json.dumps(r.json(), ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[API ERROR] {e}"


def fw_qos_get(ip: str) -> str:
    """Get QoS policy for a specific IP in XDP Firewall.

    Args:
        ip: IPv4 address to query (e.g. '10.0.1.30')

    Returns status 'no QoS policy' if not set, otherwise limit/tokens/last_updated.
    """
    try:
        r = requests.get(f"{SASE_API_URL}/qos/get", params={"ip": ip}, timeout=5)
        r.raise_for_status()
        return json.dumps(r.json(), ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[API ERROR] {e}"


FW_TOOLS = [
    fw_get_top, fw_get_stats, fw_drop_list,
    fw_drop_block, fw_drop_unblock, fw_set_qos,
    fw_qos_list, fw_qos_get, fw_get_info,
]

# パス → 関数 のマップ（[EXEC:] 解析後の実行用）
FW_EXEC_MAP = {
    "/drop/block":   fw_drop_block,
    "/drop/unblock": fw_drop_unblock,
    "/qos/set":      fw_set_qos,
}


# ── MAF: FWAnalyst ────────────────────────────────────────────────────────────
class FWAnalyst:
    """
    セキュリティイベント解析・対処提案生成。

    設計方針（1.7.0 対応）:
    - Agent(client, name=..., tools=FW_TOOLS) でスキーマ提示は維持する
    - 実際の LLM 呼び出しは Groq API を requests.post() で直接行う（完全同期）
    - response.text 内の [EXEC: ...] タグで副作用アクションを制御する
    - asyncio.run() を使わないため MAF バージョン間の互換性に依存しない

    なぜ Agent.run() を使わないか:
      run_chat() は同期関数 → asyncio.run() を呼ぶと ContextVar 衝突の
      リスクがある（1.4.0 で実際に発生。1.7.0 で修正の可能性があるが不確実）。
      FWAnalyst はツール実行を response.text 解析で行う設計なので
      Agent.run() のツール自動実行機能が不要。直接呼び出しで完全に代替できる。
    """

    SYSTEM_PROMPT = """あなたは高度なネットワークセキュリティ運用エンジニアです。
XDP Firewall の通信統計を分析し、異常を検知して対処を提案します。

【ブロック済み判定ルール（最優先・必ず最初に確認すること）】
以下のいずれかに該当するフローは【防御済み（対応不要）】です：
  条件A: そのフローが「現在のブロック状況」のキーに含まれている
         例: "10.0.1.30:22 [tcp]" が drop_list に存在する → 防御済み
  条件B: dropped_packets > 0

条件Aに該当する場合、dropped_packets が 0 であっても防御済みです。
条件Aに該当するフローは「防御済み」と判定してください。
ただし、条件Aに該当するフローがあっても、他のフローの分析を省略しないでください。
必ず統計内の全フローを順番に評価してください。

【RST パケットの解釈（重要）】
XDP の統計には「攻撃元が送信したパケット」だけでなく
「ターゲットが返した応答パケット」も含まれる場合があります。

  SYN Flood の典型パターン:
  - 攻撃元が SYN を大量送信
  - ターゲットが SYN に対して RST または RST/ACK を返す
  - 統計上: syn_packets ≒ rst_packets、ack_packets = 0 となる

  「≒」の定義: rst_packets が syn_packets の 30%〜100% の範囲にある場合
  例: syn=34237, rst=12128 → rst/syn = 35% → SYN Flood の兆候あり

  よって「SYN が大量 かつ ACK = 0 かつ RST が SYN の 30% 以上」は SYN Flood です。
  RST がターゲットからの拒否応答であるため、攻撃が継続中と判断してください。

  ポートスキャンとの違い:
    - ポートスキャン: 複数ポートに少量ずつ SYN+RST
    - SYN Flood:     単一ポートに大量の SYN（RST はターゲット応答）

【判定の優先順位】

1. 【防御済み（対応不要）】
   - 条件A または 条件B に該当
   - 対応: [EXEC: ...] タグは絶対に書かない
   - 説明: 「遮断済みで防御効果が確認できています」

2. 【異常あり・未対策（要アクション）】
   - dropped_packets = 0 かつ 条件A に非該当 かつ 以下のいずれかに該当:

   (a) SYN Flood（単一ポートへの大量 SYN）
       - syn_packets が大量（目安: 1000以上）
       - かつ ack_packets = 0
       - かつ rst_packets = 0（ターゲットが応答しない場合）
         または rst_packets が syn_packets の 30% 以上（ターゲット応答）
       → fw_drop_block で即時遮断

   (b) ポートスキャン
       - syn_packets と rst_packets が共に大量
       - かつ複数ポートに分散している場合
       → fw_drop_block で遮断

   (c) その他の Flood
       - パケットサイズが固定でパケット数が異常に多い

   (d) ハーフオープン接続
       - ack_packets / (syn_packets + 1) < 0.5

   - 対応: 説明の文末に必ず以下を記述:
     [EXEC: /drop/block?ip=<実際のIP>&proto=<実際のproto>&port=<実際のport>]
     または帯域制限の場合:
     [EXEC: /qos/set?ip=<実際のIP>&limit=<bytes_per_sec>]

3. 【正常】
   - 上記のいずれにも該当しない

【厳守事項（違反禁止）】
- 条件A または 条件B に該当するフローに絶対に [EXEC: ...] を書かない
- [EXEC: ...] に書く IP・proto・port は通信統計の実際の値のみ使用する
- <IP>, <PROTO>, <PORT> などプレースホルダーをそのまま出力しない
- 同一フロー（同じ IP+proto+port）への二重ブロック提案をしない
- 説明文中のフロー情報（SYN数、RST数等）は通信統計の実際の数値のみ引用する
- rst_packets = 0 のフローに「RST が大量」と書かない
- [EXEC: ...] は必ず半角の角括弧 [ ] で記述する（全角【】は使わない）
- 一つのフローが防御済みでも、残りのフローの評価を省略しない
- 統計内の全フローを必ず最後まで評価してから回答する
- rst_packets = 0 のフローに「RST が大量」と書かない

【QoS自動ミティゲーションとの連携】
Go Agent が以下を自動実行しています（人間確認なし）:
  SYN Delta >= 300 を 2回連続検知 → QOS_MAP[src_ip] = 10KB/s 自動設定
  2分間安定後 → QOS_MAP 自動削除（復旧）

LLMオーケストレータの役割:
- fw_qos_list() で自動ミティゲーション適用状況を確認できる
- ミティゲーション適用中（limit=10000）でも攻撃が継続する場合は
  fw_drop_block で完全遮断を提案する（人間確認あり）
- ミティゲーション適用中のIPへの fw_set_qos 提案は不要
"""

    def __init__(self):
        # Agent インスタンスはスキーマ提示（tools= のシグネチャを LLM に見せる）
        # のために保持する。実際の run() は呼ばない。
        # 1.7.0: client が第1位置引数
        client = OpenAIChatCompletionClient(
            model=MODEL,
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
        self._agent = Agent(
            client,
            name="FWAnalyst",
            instructions=self.SYSTEM_PROMPT,
            tools=FW_TOOLS,
        )

    def _build_user_content(self, user_query: str, stats_json: str,
                            block_list: str, diff_info: str) -> str:
        """LLM へ渡すユーザーメッセージを組み立てる"""
        return (
            f"【現在のブロック状況】\n{block_list}\n\n"
            f"【防御効果（前回比 dropped_packets 増加量）】\n"
            f"{diff_info if diff_info else '（変化なし）'}\n\n"
            f"【通信統計（最新JSON）】\n{stats_json}\n\n"
            f"【ユーザーの指示】\n{user_query}"
        )

    def analyze(self, user_query: str, stats_json: str,
                block_list: str, diff_info: str) -> Any:
        """
        統計・ブロック状況を渡して解析・提案を生成する。

        Groq API を requests.post() で直接呼び出す（完全同期）。
        asyncio.run() を使わないため run_chat()（同期関数）から
        安全に呼び出せる。

        Returns:
            _FWResponse（.text 属性を持つ簡易レスポンスオブジェクト）
            失敗時は None
        """
        user_content = self._build_user_content(
            user_query, stats_json, block_list, diff_info
        )
        payload = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user",   "content": user_content},
            ],
            "max_tokens": 2048,
            "temperature": 0.1,  # 判定の再現性を高めるため低めに設定
        }
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type":  "application/json",
        }
        try:
            r = requests.post(
                GROQ_API_URL,
                json=payload,
                headers=headers,
                timeout=30,
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"].strip()
            return _FWResponse(text)
        except requests.RequestException as e:
            print(f"  ⚠️  [LLM ERROR] Groq API 呼び出し失敗: {e}")
            return None
        except (KeyError, IndexError) as e:
            print(f"  ⚠️  [LLM ERROR] レスポンス解析失敗: {e}")
            return None


class _FWResponse:
    """
    Agent.run() の戻り値と同じ .text インターフェースを提供する
    薄いラッパー。ChatAgent が response.text を参照するコードを
    変更せずに済むようにする。
    """
    def __init__(self, text: str):
        self.text = text


# ── AI SASE エージェント ──────────────────────────────────────────────────────
class AISaseAgent:
    def __init__(self, api_client: "SaseApiClient", analyst: FWAnalyst = None):
        self.api        = api_client
        self.analyst    = analyst
        self.prev_stats: dict = {}

    def ask_ai(self, user_query: str, stats_json: str = "",
               block_list: str = "", diff_info: str = "") -> Any:
        if not self.analyst:
            return None
        return self.analyst.analyze(user_query, stats_json, block_list, diff_info)


# ── SASE API クライアント（UI層でのデータ取得専用）────────────────────────────
class SaseApiClient:
    def __init__(self, base_url: str = SASE_API_URL):
        self.base = base_url.rstrip("/")

    def _get(self, path: str, params: dict = None) -> str:
        try:
            r = requests.get(f"{self.base}{path}", params=params, timeout=5)
            r.raise_for_status()
            try:
                return json.dumps(r.json(), ensure_ascii=False, indent=2)
            except ValueError:
                return r.text
        except requests.RequestException as e:
            return f"[API ERROR] {e}"

    def get_top_json(self) -> list:
        try:
            raw = self._get("/top")
            if not raw or raw.startswith("[API ERROR]"):
                return []
            result = json.loads(raw)
            return result if isinstance(result, list) else []
        except Exception:
            return []

    def drop_list(self) -> str:
        return self._get("/drop/list")


# ── チャット UI ───────────────────────────────────────────────────────────────
class ChatAgent:
    LLM_RETRY_MAX = 2

    def __init__(self, ai_agent: AISaseAgent):
        self.agent           = ai_agent
        self.pending_actions: List[Tuple] = []

    def display_raw_stats(self, stats: list):
        print(f"\n{'='*105}")
        print(f"📊 RAW FLOW STATISTICS ({datetime.now().strftime('%H:%M:%S')})")
        print(f"{'='*105}")
        print(f"{'IP ADDRESS':<15} | {'PROT':<4} | {'PORT':<5} | {'PKTS':<8} | "
              f"{'DROP':<8} | {'SYN':<6} | {'RST':<6} | {'ACK':<8} | {'SIZE(MIN/MAX)':<14}")
        print("-" * 105)
        for s in stats:
            st = s.get('stats', {})
            size_range = f"{st.get('pkt_min', 0)}/{st.get('pkt_max', 0)}"
            print(f"{s.get('ip', 'N/A'):<15} | {s.get('protocol', 'N/A')[:4]:<4} | "
                  f"{s.get('port', 0):<5} | {st.get('packets', 0):<8} | "
                  f"{st.get('dropped_packets', 0):<8} | {st.get('syn_packets', 0):<6} | "
                  f"{st.get('rst_packets', 0):<6} | {st.get('ack_packets', 0):<8} | "
                  f"{size_range:<14}")

    def run_chat(self):
        os.system("clear")
        print("\n=== XDP Firewall Orchestrator (MAF版 v9.4) ===")
        print("コマンド例: 統計を見せて / ブロックリストを見せて / QoSリストを見せて / 状況を分析して / exit")
        while True:
            try:
                user_input = input("\n👤 USER > ").strip()
                if not user_input:
                    continue
                if user_input.lower() in ["exit", "quit"]:
                    break

                is_affirmative = any(
                    x in user_input.lower()
                    for x in ["はい", "yes", "y", "実行", "おねがい"]
                )
                is_negative = any(
                    x in user_input.lower()
                    for x in ["いいえ", "no", "n", "キャンセル", "やめて"]
                )

                if self.pending_actions:
                    if is_affirmative:
                        for func, kwargs, label in self.pending_actions:
                            print(f"✅ 実行中: {label}")
                            result = func(**kwargs)
                            print(f"   結果: {result}")
                        self.pending_actions = []
                    elif is_negative:
                        print("❎ アクションをキャンセルしました。")
                        self.pending_actions = []
                    else:
                        self.pending_actions = []
                        self.handle_message(user_input)
                else:
                    self.handle_message(user_input)

            except KeyboardInterrupt:
                break

    def handle_message(self, user_input: str):
        lower = user_input.lower()

        # ── 情報表示系は LLM を介さず直接表示 ──────────────────────────────
        if any(k in lower for k in ["ブロックリスト", "blocklist", "block list",
                                     "ブロック一覧", "遮断リスト"]):
            print(f"📋 現在のブロックリスト:\n{self.agent.api.drop_list()}")
            return

        if any(k in lower for k in ["qosリスト", "qos list", "qos一覧",
                                     "ミティゲーション", "帯域制限一覧"]):
            print(f"📡 現在のQoSポリシー:\n{fw_qos_list()}")
            return

        if any(k in lower for k in ["/info", "エージェント情報", "バージョン"]):
            print(f"ℹ️  Agent Info:\n{fw_get_info()}")
            return

        # ── 以降は統計取得 + LLM 分析 ───────────────────────────────────────
        stats  = self.agent.api.get_top_json() or []
        blocks = self.agent.api.drop_list() or "{}"

        # dropped_packets の前回比を計算
        diff_reports = []
        for s in stats:
            key       = f"{s['ip']}-{s['protocol']}-{s['port']}"
            curr_drop = s['stats'].get('dropped_packets', 0)
            if key in self.agent.prev_stats:
                diff = curr_drop - self.agent.prev_stats[key]
                if diff > 0:
                    diff_reports.append(f"{key}:+{diff}")
            self.agent.prev_stats[key] = curr_drop

        if any(k in lower for k in ["統計", "stats", "状況"]):
            self.display_raw_stats(stats)

        if not stats:
            print("ℹ️  現在フローがありません。統計データが取得できたら再度お試しください。")
            return

        # LLM に解析・提案させる（リトライ上限: LLM_RETRY_MAX 回）
        response = None
        for attempt in range(1, self.LLM_RETRY_MAX + 2):
            label = f"（リトライ {attempt - 1}/{self.LLM_RETRY_MAX}）" if attempt > 1 else ""
            print(f"🤖 AI分析中...{label}")
            response = self.agent.ask_ai(
                user_query=user_input,
                stats_json=json.dumps(stats, ensure_ascii=False),
                block_list=blocks,
                diff_info=", ".join(diff_reports),
            )
            if response is not None:
                break
            if attempt <= self.LLM_RETRY_MAX:
                print(f"⚠️  LLM応答なし → 1秒後にリトライします...")
                time.sleep(1)

        if response is None:
            print("❌ AI応答を取得できませんでした。")
            return

        text = response.text or ""
        if text:
            print(f"🤖 AI:\n{text}")

        self._extract_pending_actions(text)

    def _extract_pending_actions(self, text: str):
        """
        response.text から [EXEC: /drop/block?...] 等を全件抽出し、
        副作用ありの操作を pending_actions に積んでユーザー確認を求める。
        すでにブロック済みのフローへの /drop/block は除外する。
        """
        try:
            current_blocks = json.loads(self.agent.api.drop_list() or "{}")
        except Exception:
            current_blocks = {}

        pattern  = r"(?:\[|【)EXEC:\s*((?:/drop/block|/drop/unblock|/qos/set)\?[^\]\s<>】]{5,})(?:\]|】)"
        matches  = re.findall(pattern, text)
        pattern2 = r"(?<!\[)(?<!【)EXEC:\s*((?:/drop/block|/drop/unblock|/qos/set)\?[^\s<>】\]]{5,})"
        for m in re.findall(pattern2, text):
            if m not in matches:
                matches.append(m)

        valid_actions = []
        for cmd in matches:
            if cmd.startswith("http"):
                parsed = urlparse(cmd)
                cmd = parsed.path + ("?" + parsed.query if parsed.query else "")

            if not re.search(r"ip=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", cmd):
                continue

            if "/drop/block" in cmd:
                ip_m    = re.search(r"ip=([\d.]+)", cmd)
                proto_m = re.search(r"proto=(\w+)", cmd)
                port_m  = re.search(r"port=(\d+)", cmd)
                if ip_m and proto_m and port_m:
                    block_key = f"{ip_m.group(1)}:{port_m.group(1)} [{proto_m.group(1)}]"
                    if block_key in current_blocks:
                        continue

            action = self._parse_exec_cmd(cmd)
            if action:
                valid_actions.append(action)

        seen    = set()
        deduped = []
        for item in valid_actions:
            _, kwargs, label = item
            if label not in seen:
                seen.add(label)
                deduped.append(item)
        valid_actions = deduped

        if not valid_actions:
            return

        self.pending_actions = valid_actions
        print(f"\n⚠️  AIが {len(valid_actions)} 件のアクションを提案しました:")
        for i, (_, _, label) in enumerate(valid_actions, 1):
            print(f"   {i}. {label}")
        print("💡 すべて実行してよろしいですか？ (はい/いいえ)")

    def _parse_exec_cmd(self, cmd: str):
        """
        '/drop/block?ip=X.X.X.X&proto=tcp&port=22' 形式を
        (func, kwargs, label) に変換する。
        """
        try:
            if "?" in cmd:
                path, qs = cmd.split("?", 1)
            else:
                path, qs = cmd, ""

            func = FW_EXEC_MAP.get(path)
            if func is None:
                return None

            kwargs = {}
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    kwargs[k] = v

            if "port" in kwargs:
                kwargs["port"] = int(kwargs["port"])
            if "limit" in kwargs:
                kwargs["limit"] = int(kwargs["limit"])

            label = f"{func.__name__}({', '.join(f'{k}={v}' for k, v in kwargs.items())})"
            return (func, kwargs, label)

        except Exception:
            return None


# ── メイン ────────────────────────────────────────────────────────────────────
def main():
    if not GROQ_API_KEY:
        print("❌ GROQ_API_KEY が設定されていません")
        print(f"   設定ファイル: {GROQ_CONFIG_PATH}")
        sys.exit(1)

    api     = SaseApiClient()
    analyst = FWAnalyst()
    agent   = AISaseAgent(api, analyst)
    ChatAgent(agent).run_chat()


if __name__ == "__main__":
    main()
