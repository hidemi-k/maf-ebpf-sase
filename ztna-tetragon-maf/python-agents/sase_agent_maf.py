# Copyright (c) 2026 hidemi-k
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

"""
SASE Agent

変更履歴:
  [v9.0 対応]
  1. /auth/ticket に X-API-Key ヘッダ認証を追加
     AGENT_API_KEY 環境変数が設定されている場合、書き込み系 API に
     X-API-Key ヘッダを付与する。未設定時は従来どおり（開発環境向け）。

  2. /auth/logs のフィールド変更に対応
     旧: magic フィールドに平文 hex 値
     新: magic_hash フィールドに "sha256:XXXXXXXXXXXXXXXX" 形式のハッシュ値
     revoke_by_magic ツール内のログ照合ロジックを magic_hash ベースに変更。

  3. 認証ポートの動的取得に対応
     旧: UDP 8888 ハードコード
     新: /config エンドポイントの auth_port フィールドから取得し、
         取得失敗時は 8888 にフォールバックする。

  4. /config レスポンス変更に対応
     旧: current_magic_ticket (hex 文字列)
     新: magic_status ("active" / "consumed" / "unset")

  [初期移行時の変更点]
  1. OpenAI クライアントの import を最新 API に更新
     旧: agent_framework.openai.OpenAIChatClient
     新: agent_framework_openai.OpenAIChatCompletionClient

  2. OpenAIChatCompletionClient の初期化引数を最新仕様に合わせて変更
     旧: model_id=
     新: model=
"""

import os
import sys
import asyncio
import configparser
import json
import random
import subprocess
import requests
from agent_framework import Agent, Message, tool
from agent_framework_openai import OpenAIChatCompletionClient

# ── 設定 ────────────────────────────────────────────────────────────────────
GROQ_CONFIG_PATH = os.getenv(
    "SASE_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config.ini")
)

groq_api_key = ""
if os.path.exists(GROQ_CONFIG_PATH):
    config = configparser.ConfigParser()
    config.read(GROQ_CONFIG_PATH)
    if 'GROQ' in config and 'GROQ_API_KEY' in config['GROQ']:
        groq_api_key = config['GROQ']['GROQ_API_KEY'].strip()
        print("✅ Groq API key loaded from config")
else:
    print(f"⚠️  Config file not found: {GROQ_CONFIG_PATH}")

SASE_API_URL   = os.getenv("SASE_API_URL",   "http://localhost:8080")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY",   groq_api_key)
AGENT_API_KEY  = os.getenv("AGENT_API_KEY",  "")  # 書き込み系 API の認証キー
MODEL          = "openai/gpt-oss-120b"
CONTAINER_NAME = "linux1"

# AGENT_API_KEY が未設定の場合は開発モードで動作する
if not AGENT_API_KEY:
    print("⚠️  AGENT_API_KEY が未設定です。書き込み系 API は認証なしで動作します（開発モード）")


# ── SASE API クライアント ─────────────────────────────────────────────────────
class SaseApiClient:
    """SASE / XDP Go Agent の REST API を操作するクライアント"""

    def __init__(self, base_url: str = SASE_API_URL, api_key: str = AGENT_API_KEY):
        self.base    = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self, write: bool = False) -> dict:
        """write=True の場合は X-API-Key ヘッダを付与する"""
        h = {}
        if write and self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def _get(self, path: str, params: dict = None, write: bool = False) -> str:
        try:
            r = requests.get(
                f"{self.base}{path}",
                params=params,
                headers=self._headers(write),
                timeout=5
            )
            r.raise_for_status()
            try:
                return json.dumps(r.json(), ensure_ascii=False, indent=2)
            except ValueError:
                return r.text
        except requests.RequestException as e:
            return f"[API ERROR] {e}"

    def get_info(self) -> str:
        return self._get("/info")

    def get_config(self) -> str:
        """カーネル状態（magic_status, auth_duration_ns, auth_port）を取得"""
        return self._get("/config")

    def get_auth_port(self) -> int:
        """認証受付ポートを /config から取得する。取得失敗時は 8888 を返す"""
        try:
            raw = self.get_config()
            cfg = json.loads(raw)
            return int(cfg.get("auth_port", 8888))
        except Exception:
            return 8888

    def issue_ticket(self, magic: str) -> str:
        """マジックナンバーをカーネルにセットし、チケットを発行する（書き込み系）"""
        return self._get("/auth/ticket", {"magic": magic}, write=True)

    def get_logs(self) -> str:
        """チケット発行履歴を取得する。magic_hash フィールドにハッシュ値が入る"""
        return self._get("/auth/logs")

    def revoke(self, ip: str) -> str:
        """送信元IPの認証セッションを取り消す（書き込み系）"""
        return self._get("/auth/revoke", {"ip": ip}, write=True)

    def get_stats(self) -> str:
        return self._get("/stats")


# ── ユーティリティ ────────────────────────────────────────────────────────────
def magic_to_printf_bytes(magic_hex: str) -> str:
    """
    32bit マジックナンバーを printf のバイト列引数に変換する。
    UDP ペイロードは 8 バイト（u64 big-endian）で送信するため、
    上位 4 バイトを 0x00 でパディングする。
    例: 0x9519d2d1 → \\x00\\x00\\x00\\x00\\x95\\x19\\xd2\\xd1
    """
    magic_int = int(magic_hex, 16) & 0xFFFFFFFF
    b         = magic_int.to_bytes(4, byteorder='big')
    byte_str  = "".join(f"\\x{byte:02x}" for byte in b)
    return f"\\x00\\x00\\x00\\x00{byte_str}"


def validate_magic_32bit(magic_hex: str) -> bool:
    """マジックナンバーが 32bit 以内（1〜0xFFFFFFFF）かチェック"""
    try:
        val = int(magic_hex, 16)
        return 0 < val <= 0xFFFFFFFF
    except ValueError:
        return False


# ── MAF ツール定義 ────────────────────────────────────────────────────────────
def create_tools(api: SaseApiClient) -> list:
    """
    @tool デコレータを使い SaseApiClient をバインドしたツール関数リストを返す。
    MAF では関数の docstring と型アノテーションからスキーマが自動生成される。
    """

    @tool
    def generate_magic_number() -> str:
        """
        ランダムな 32 ビット（0x00000001〜0xFFFFFFFF）のマジックナンバーを生成し、
        SASE Agent の /auth/ticket API でカーネルにセットする。
        必ず 32 ビット以内（8 桁 hex）の値を生成する。64 ビット値（16 桁）は不可。
        ユーザーが新しいマジックナンバーの発行を求めたときに呼ぶ。
        """
        magic_int = random.randint(1, 0xFFFFFFFF)
        magic_hex = f"0x{magic_int:08x}"
        result    = api.issue_ticket(magic_hex)
        return json.dumps({
            "generated_magic": magic_hex,
            "bit_width":       32,
            "api_response":    result.strip()
        }, ensure_ascii=False)

    @tool
    def send_magic_to_container(magic: str, target_ip: str) -> str:
        """
        発行済みの 32bit マジックナンバーを docker exec 経由で linux1 コンテナから
        対象 IP の UDP 認証ポートに送信し、疎通許可を行う。
        認証ポートは /config から動的に取得する（デフォルト 8888）。
        ユーザーが特定 IP へのping疎通や通信許可を指示したときに呼ぶ。
        generate_magic_number で発行したマジックナンバーをそのまま渡すこと。

        Args:
            magic:     発行済みの 32bit マジックナンバー (例: 0x9519d2d1)
            target_ip: 疎通を許可したい宛先 IP アドレス (例: 192.168.5.2)
        """
        if not magic or not target_ip:
            return json.dumps({"error": "magic と target_ip は必須です"}, ensure_ascii=False)

        if not validate_magic_32bit(magic):
            return json.dumps({
                "error": f"マジックナンバーは 32bit 以内で指定してください。受け取った値: {magic}"
            }, ensure_ascii=False)

        # 認証ポートを動的取得（取得失敗時は 8888 にフォールバック）
        auth_port = api.get_auth_port()

        try:
            printf_bytes = magic_to_printf_bytes(magic)
            sh_cmd       = f'printf "{printf_bytes}" | nc -u -w1 {target_ip} {auth_port}'
            cmd          = ["docker", "exec", CONTAINER_NAME, "sh", "-c", sh_cmd]

            print(f"\n  [EXEC] {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            status = "SUCCESS" if result.returncode == 0 else "ERROR"
            detail = result.stdout or result.stderr or "(no output)"

            return json.dumps({
                "status":     status,
                "magic":      magic,
                "target_ip":  target_ip,
                "auth_port":  auth_port,
                "printf_cmd": sh_cmd,
                "detail":     detail
            }, ensure_ascii=False)

        except subprocess.TimeoutExpired:
            return json.dumps({"error": "docker exec がタイムアウトしました"}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @tool
    def revoke_by_magic(magic: str) -> str:
        """
        マジックナンバーのハッシュ（sha256 プレフィックス付き）または
        元の 32bit hex 値を指定して、そのチケットで認証されたIPの通信を遮断する。

        v9.0 対応: /auth/logs の magic フィールドは廃止され、
        magic_hash フィールド（sha256:XXXXXXXXXXXXXXXX 形式）に変更された。
        ユーザーが提示する値は元の magic hex 値でも magic_hash 値でも受け付ける。
        ただしハッシュは不可逆のため、元の magic 値からの照合は
        「全ログエントリの revoke」にフォールバックする。

        ユーザーが「マジックナンバー 0xXXXX を無効化して」「チケットを無効化して」と
        指示したときに呼ぶ。

        Args:
            magic: 無効化したいマジックナンバー (例: 0x5d88366e) または
                   magic_hash 値 (例: sha256:ab12cd34ef56gh78)
        """
        magic = magic.lower().strip()
        if not magic:
            return json.dumps({"error": "magic は必須です"}, ensure_ascii=False)

        # ① /auth/logs 取得
        try:
            logs_raw = api.get_logs()
            logs     = json.loads(logs_raw)
            if not isinstance(logs, list):
                raise ValueError("logs is not a list")
        except Exception:
            return json.dumps({"error": "auth/logs の取得に失敗しました"}, ensure_ascii=False)

        # ② ログ照合
        # v9.0 以降、ログには magic_hash（sha256:...）のみ記録される。
        # ユーザーが sha256: プレフィックス付きで指定した場合は直接照合。
        # 元の hex 値で指定した場合はハッシュを逆算できないため、
        # ログ全件を revoke 対象とし、その旨をユーザーに説明する。
        is_hash_search = magic.startswith("sha256:")
        matched        = []

        if is_hash_search:
            # magic_hash フィールドで直接照合
            matched = [e for e in logs if e.get("magic_hash", "").lower() == magic]
        else:
            # 元の hex 値からは逆算不可。TICKET_ISSUED 全件を対象とする
            matched = [e for e in logs if e.get("action") == "TICKET_ISSUED"]

        if not matched:
            return json.dumps({
                "error":             f"マジックナンバー {magic} に対応するログが存在しません",
                "available_hashes":  [e.get("magic_hash") for e in logs
                                      if e.get("action") == "TICKET_ISSUED"]
            }, ensure_ascii=False)

        # ③ /stats から現在通信中の IP を取得
        try:
            stats_raw  = api.get_stats()
            stats      = json.loads(stats_raw)
            active_ips = list({e["ip"] for e in stats if isinstance(e, dict) and "ip" in e})
        except Exception:
            return json.dumps({"error": "stats の取得に失敗しました"}, ensure_ascii=False)

        # ④ 通信中の全 IP を revoke
        revoked = []
        errors  = []
        for ip in active_ips:
            result = api.revoke(ip)
            if "ERROR" in result.upper() or "error" in result.lower():
                errors.append({"ip": ip, "result": result})
            else:
                revoked.append({"ip": ip, "result": result})

        note = ""
        if not is_hash_search:
            note = ("元の hex 値からハッシュへの逆算はできないため、"
                    "現在認証中の全IPを revoke しました。")

        return json.dumps({
            "magic":        magic,
            "search_mode":  "hash" if is_hash_search else "hex_fallback_all",
            "log_entries":  matched,
            "revoked_ips":  revoked,
            "errors":       errors,
            "status":       "SUCCESS" if revoked else "NO_ACTIVE_SESSION",
            "note":         note,
        }, ensure_ascii=False)

    @tool
    def get_stats() -> str:
        """
        全フローの通信統計を取得する。
        ユーザーが統計や通信量の確認を明示的に求めたときだけ呼ぶ。
        send_magic_to_container の前後に自動で呼んではいけない。
        """
        return api.get_stats()

    @tool
    def get_logs() -> str:
        """
        チケット発行履歴（認証ログ）を取得する。
        v9.0 以降、magic フィールドは magic_hash（sha256:... 形式）に変更されている。
        """
        return api.get_logs()

    @tool
    def get_info() -> str:
        """XDP Agent の動作情報（インターフェース、モード、バージョン）を取得する。"""
        return api.get_info()

    return [
        generate_magic_number,
        send_magic_to_container,
        revoke_by_magic,
        get_stats,
        get_logs,
        get_info,
    ]


# ── MAF エージェント構築 ──────────────────────────────────────────────────────
SYSTEM_PROMPT = """あなたはSASE/XDPネットワークセキュリティシステムのAIオーケストレータです。
ユーザーからの自然言語の指示を理解し、適切なAPIツールを呼び出してネットワークを制御します。

【最重要ルール - 必ず守ること】
- 1回の指示に対して呼び出すツールは必ず1つだけにすること
- ユーザーが明示的に指示していない操作は絶対に実行しないこと
- 「発行してください」→ generate_magic_number のみ呼ぶ。send_magic_to_containerは呼ばない
- 「疎通を許可してください」→ send_magic_to_container のみ呼ぶ
- get_logs・get_stats・get_info はユーザーが明示的に要求したときだけ呼ぶ
- ツールを呼んだ後は結果を日本語で報告してユーザーの次の指示を待つこと

【マジックナンバーのルール】
- 必ず32bit（0x00000001〜0xFFFFFFFF、8桁hex）で扱うこと
- 64bitの値（16桁hex）は絶対に使用しないこと
- ログに記録される magic_hash は sha256: プレフィックス付きのハッシュ値であり、
  元の magic 値とは異なる。ユーザーに混同させないよう注意すること

【認証フロー - 必ずこの順序でユーザーの指示を待つ】
1. ユーザーが「発行」を指示 → generate_magic_number を呼ぶ → 結果を報告して待機
2. ユーザーが「疎通を許可」を指示 → send_magic_to_container を呼ぶ → 結果を報告して待機
3. ユーザーが「無効化」を指示 → revoke_by_magic を呼ぶ → 結果を報告して待機

必ずツールを使って実際にAPIを操作し、結果をユーザーに日本語で簡潔に報告してください。"""


def build_agent() -> Agent:
    """MAF Agent を構築して返す"""
    api   = SaseApiClient()
    tools = create_tools(api)

    client = OpenAIChatCompletionClient(
        model=MODEL,
        api_key=GROQ_API_KEY,
        base_url="https://api.groq.com/openai/v1",
    )

    agent = Agent(
        name="SaseAgent",
        instructions=SYSTEM_PROMPT,
        client=client,
        tools=tools,
    )
    return agent


# ── チャットUI ──────────────────────────────────────────────────────────────
async def chat_loop(agent: Agent):
    """非同期チャットループ"""
    if hasattr(sys.stdin, 'reconfigure'):
        sys.stdin.reconfigure(encoding='utf-8', errors='replace')

    os.system("clear")
    print("=" * 60)
    print("  SASE Agent")
    print("  終了: 'exit' または 'quit'")
    print("=" * 60)
    print()
    print("【シナリオ例】")
    print("  > マジックナンバーを発行してください")
    print("  > マジックナンバー 0x5d88366e で 10.0.5.1 への疎通を許可してください")
    print("  > マジックナンバー 0x5d88366e を無効化してください")
    print()

    # MAF のセッションを会話全体で保持（会話履歴管理）
    session = agent.create_session()

    while True:
        try:
            user_input = input("あなた: ")
            user_input = (
                user_input
                .encode('utf-8', errors='replace')
                .decode('utf-8', errors='replace')
                .strip()
                .strip('\u3000\t\r\n\u200b\xa0')
            )
        except (EOFError, KeyboardInterrupt):
            print("\n終了します。")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "終了"):
            print("終了します。")
            break

        print()
        # llm はツール呼び出しの JSON 生成に失敗することがある（400 エラー）。
        # 同じ入力でリトライすることで大半は回復するため、最大2回まで再試行する。
        MAX_RETRY = 2
        for attempt in range(MAX_RETRY + 1):
            try:
                response = await agent.run(
                    messages=user_input,
                    session=session,
                )
                print(f"\nエージェント: {response.text}")
                break
            except Exception as e:
                err_str = str(e)
                if "tool_use_failed" in err_str and attempt < MAX_RETRY:
                    print(f"  ⚠️  ツール呼び出し生成に失敗しました。リトライします... "
                          f"({attempt + 1}/{MAX_RETRY})")
                    await asyncio.sleep(1)
                    continue
                print(f"  ⚠️  [ERROR] {e}")
                print(f"  もう一度入力してください。")
                break
        print()


def main():
    if not GROQ_API_KEY:
        print("❌ GROQ_API_KEY が設定されていません")
        sys.exit(1)

    agent = build_agent()
    asyncio.run(chat_loop(agent))


if __name__ == "__main__":
    main()
