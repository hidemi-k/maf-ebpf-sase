#!/usr/bin/env python3
"""
XDP Firewall Orchestrator - MAF版 (v9.3)

変更点 (vs v9.2):
  [tool_calls 未対応への対処]
    - MAF の当バージョンでは tools= を渡しても response.tool_calls が返らない
      → LLM はテキスト内にツール名を書くだけで構造化レスポンスを返さない
    - tools= の定義は MAF 準拠として維持（LLM へのシグネチャ提示用）
    - 実行トリガーは [EXEC: ...] テキスト解析に戻す（v9.0方式・実績あり）
    - 人間確認（はい/いいえ）は維持

  [LLM誤判定の修正]
    - ブロック済み判定: drop_list にある OR dropped_packets > 0 の両方を明示
    - システムプロンプトでブロックリストの参照方法を明確化
"""

import os
import sys
import io
import json
import asyncio
import configparser
import requests
import re
import time
from datetime import datetime
from typing import Any, List, Tuple
from urllib.parse import urlparse

from agent_framework import Agent, Message
from agent_framework.openai import OpenAIChatClient

sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')

# ── 設定 ─────────────────────────────────────────────────────────────────────
GROQ_CONFIG_PATH = os.getenv("SASE_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config.ini"))

groq_api_key = ""
if os.path.exists(GROQ_CONFIG_PATH):
    _cfg = configparser.ConfigParser()
    _cfg.read(GROQ_CONFIG_PATH)
    if 'GROQ' in _cfg and 'GROQ_API_KEY' in _cfg['GROQ']:
        groq_api_key = _cfg['GROQ']['GROQ_API_KEY'].strip()

SASE_API_URL = os.getenv("SASE_API_URL", "http://localhost:8080")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", groq_api_key)
MODEL        = "llama-3.3-70b-versatile"


# ── FW API ツール関数（tools= に登録・実行は直接呼び出し）────────────────────
# docstring が LLM へのツール説明になるため明確に記述する。
# MAF tools= に渡すことで LLM がシグネチャを認識できる。
# 実際の実行は [EXEC:] 解析後に ChatAgent が直接呼び出す。

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


# ── ツール定義（tools= に渡す・シグネチャ提示用）─────────────────────────────
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


# ── MAF: FWAnalyst（tools= + Message・実行は [EXEC:] 解析）──────────────────
class FWAnalyst:
    """
    MAF Agent による異常解析・対処提案生成。

    - Agent(tools=FW_TOOLS): LLM がツールシグネチャを認識できる
    - 実際の実行トリガーは response.text 内の [EXEC: ...] タグ
      （MAF 当バージョンで response.tool_calls が返らないため）
    - Message(role=..., text=...) で会話コンテキストを管理
    - 人間確認（はい/いいえ）は ChatAgent が担当
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
        client = OpenAIChatClient(
            model_id=MODEL,
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
        # tools= に渡すことで LLM がシグネチャを認識できる（MAF 準拠）
        # 実行は response.text の [EXEC:] 解析で行う
        self._agent = Agent(
            name="FWAnalyst",
            instructions=self.SYSTEM_PROMPT,
            client=client,
            tools=FW_TOOLS,
        )

    def analyze(self, user_query: str, stats_json: str,
                block_list: str, diff_info: str) -> Any:
        """
        統計・ブロック状況を Message で渡して解析・提案を生成する。

        Returns:
            AgentResponse (response.text に [EXEC: ...] タグを含む場合あり)
        """
        messages = [
            Message(
                role="user",
                text=(
                    f"【現在のブロック状況】\n{block_list}\n\n"
                    f"【防御効果（前回比 dropped_packets 増加量）】\n"
                    f"{diff_info if diff_info else '（変化なし）'}\n\n"
                    f"【通信統計（最新JSON）】\n{stats_json}\n\n"
                    f"【ユーザーの指示】\n{user_query}"
                )
            )
        ]
        try:
            response = asyncio.run(self._agent.run(messages))
            return response
        except Exception as e:
            return None


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
        self.pending_actions: List[Tuple] = []  # [(func, kwargs, label), ...]

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
        print("\n=== XDP Firewall Orchestrator (MAF版 v9.3) ===")
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

        # 統計が空の場合は LLM を呼ばない
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

        # [EXEC: ...] タグを解析して pending_actions に積む
        self._extract_pending_actions(text)

    def _extract_pending_actions(self, text: str):
        """
        response.text から [EXEC: /drop/block?...] 等を全件抽出し、
        副作用ありの操作を pending_actions に積んでユーザー確認を求める。
        すでにブロック済みのフローへの /drop/block は除外する。
        """
        # 現在のブロックリストを取得（二重ブロック防止）
        try:
            current_blocks = json.loads(self.agent.api.drop_list() or "{}")
        except Exception:
            current_blocks = {}

        # 半角[EXEC:...]、全角【EXEC:...】、括弧なし EXEC:... の3パターンに対応
        pattern = r"(?:\[|【)EXEC:\s*((?:/drop/block|/drop/unblock|/qos/set)\?[^\]\s<>】]{5,})(?:\]|】)"
        matches = re.findall(pattern, text)
        # 括弧なしパターンも補足（行末または空白で終わるケース）
        pattern2 = r"(?<!\[)(?<!【)EXEC:\s*((?:/drop/block|/drop/unblock|/qos/set)\?[^\s<>】\]]{5,})"
        for m in re.findall(pattern2, text):
            if m not in matches:
                matches.append(m)

        valid_actions = []
        for cmd in matches:
            if cmd.startswith("http"):
                parsed = urlparse(cmd)
                cmd = parsed.path + ("?" + parsed.query if parsed.query else "")

            # ip= パラメータが実際の IP アドレス形式か確認
            if not re.search(r"ip=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", cmd):
                continue

            # /drop/block の場合、すでにブロック済みか確認
            if "/drop/block" in cmd:
                # "ip=X.X.X.X&proto=tcp&port=N" からブロックリストキーを生成して照合
                ip_m    = re.search(r"ip=([\d.]+)", cmd)
                proto_m = re.search(r"proto=(\w+)", cmd)
                port_m  = re.search(r"port=(\d+)", cmd)
                if ip_m and proto_m and port_m:
                    block_key = f"{ip_m.group(1)}:{port_m.group(1)} [{proto_m.group(1)}]"
                    if block_key in current_blocks:
                        continue  # すでにブロック済みのため除外

            # パスとクエリパラメータを分解して関数・引数に変換
            action = self._parse_exec_cmd(cmd)
            if action:
                valid_actions.append(action)

        # 同一コマンドの重複を排除
        seen = set()
        deduped = []
        for item in valid_actions:
            _, kwargs, label = item
            key = label  # label はコマンド文字列と同等
            if key not in seen:
                seen.add(key)
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

            # クエリパラメータを辞書に変換
            kwargs = {}
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    kwargs[k] = v

            # port は int に変換
            if "port" in kwargs:
                kwargs["port"] = int(kwargs["port"])
            # limit は int に変換
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
