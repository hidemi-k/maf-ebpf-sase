"""
SASE Agent - MAF (Microsoft Agent Framework) rc5 移植版
Groq / llama-3.3-70b-versatile

移植方針:
  - 手動ツールループ → Agent.run() に委譲
  - TOOLS JSON スキーマ → @tool デコレータで自動生成
  - execute_tool() ディスパッチャ → 不要（MAFが自動呼び出し）
  - history 管理・トークン制限 → MAFセッション管理に委譲
  - BadRequestError / RateLimitError → MAFのエラーハンドリングに委譲
  - SaseApiClient, ユーティリティ関数はそのまま流用

必要ライブラリ:
  pip install "agent-framework==1.0.0rc5" --pre requests
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
from agent_framework.openai import OpenAIChatClient

# ── 設定 ────────────────────────────────────────────────────────────────────
GROQ_CONFIG_PATH = os.getenv("SASE_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config.ini"))

groq_api_key = ""
if os.path.exists(GROQ_CONFIG_PATH):
    config = configparser.ConfigParser()
    config.read(GROQ_CONFIG_PATH)
    if 'GROQ' in config and 'GROQ_API_KEY' in config['GROQ']:
        groq_api_key = config['GROQ']['GROQ_API_KEY'].strip()
        print("✅ Groq API key loaded from config")
else:
    print(f"⚠️  Config file not found: {GROQ_CONFIG_PATH}")

SASE_API_URL   = os.getenv("SASE_API_URL", "http://localhost:8080")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY", groq_api_key)
MODEL          = "llama-3.3-70b-versatile"
CONTAINER_NAME = "linux1"


# ── SASE API クライアント ─────────────────────────────────────────────────────
class SaseApiClient:
    """SASE / XDP Go Agent の REST APIを操作するクライアント（変更なし）"""

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

    def get_info(self) -> str:
        return self._get("/info")

    def issue_ticket(self, magic: str) -> str:
        """32bitマジックナンバーをカーネルにセットし、チケットを発行"""
        return self._get("/auth/ticket", {"magic": magic})

    def get_logs(self) -> str:
        return self._get("/auth/logs")

    def revoke(self, ip: str) -> str:
        """送信元IPの認証セッションを取り消す"""
        return self._get("/auth/revoke", {"ip": ip})

    def get_stats(self) -> str:
        return self._get("/stats")


# ── ユーティリティ ────────────────────────────────────────────────────────────
def magic_to_printf_bytes(magic_hex: str) -> str:
    """
    32bitマジックナンバーをprintfのバイト列引数に変換する。
    例: 0x9519d2d1 → \\x00\\x00\\x00\\x00\\x95\\x19\\xd2\\xd1
    """
    magic_int = int(magic_hex, 16) & 0xFFFFFFFF
    b = magic_int.to_bytes(4, byteorder='big')
    byte_str = "".join(f"\\x{byte:02x}" for byte in b)
    return f"\\x00\\x00\\x00\\x00{byte_str}"


def validate_magic_32bit(magic_hex: str) -> bool:
    """マジックナンバーが32bit以内（1〜0xFFFFFFFF）かチェック"""
    try:
        val = int(magic_hex, 16)
        return 0 < val <= 0xFFFFFFFF
    except ValueError:
        return False


# ── MAF ツール定義 ────────────────────────────────────────────────────────────
# SaseApiClientのインスタンスをツール関数にクロージャで渡すため
# ツール群をファクトリ関数でまとめて生成する

def create_tools(api: SaseApiClient) -> list:
    """
    @tool デコレータを使いSaseApiClientをバインドしたツール関数リストを返す。
    MAF rc5 では関数の docstring と型アノテーションからスキーマが自動生成される。
    """
    @tool
    def generate_magic_number() -> str:
        """
        ランダムな32ビット（0x00000001〜0xFFFFFFFF）のマジックナンバーを生成し、
        SASE Agent の /auth/ticket API でカーネルにセットする。
        必ず32ビット以内（8桁hex）の値を生成する。64ビット値（16桁）は絶対に不可。
        ユーザーが新しいマジックナンバーの発行を求めたときに呼ぶ。
        """
        magic_int = random.randint(1, 0xFFFFFFFF)
        magic_hex = f"0x{magic_int:08x}"
        result = api.issue_ticket(magic_hex)
        return json.dumps({
            "generated_magic": magic_hex,
            "bit_width": 32,
            "api_response": result.strip()
        }, ensure_ascii=False)

    @tool
    def send_magic_to_container(magic: str, target_ip: str) -> str:
        """
        発行済みの32bitマジックナンバーを docker exec 経由で linux1 コンテナから
        対象IPのUDP:8888に送信し、疎通許可を行う。
        ユーザーが特定IPへのping疎通や通信許可を指示したときに呼ぶ。
        generate_magic_number で発行したマジックナンバーをそのまま渡すこと。

        Args:
            magic: 発行済みの32bitマジックナンバー (例: 0x9519d2d1)
            target_ip: 疎通を許可したい宛先IPアドレス (例: 192.168.5.2)
        """
        if not magic or not target_ip:
            return json.dumps({"error": "magic と target_ip は必須です"}, ensure_ascii=False)

        if not validate_magic_32bit(magic):
            return json.dumps({
                "error": f"マジックナンバーは32bit以内で指定してください。受け取った値: {magic}"
            }, ensure_ascii=False)

        try:
            printf_bytes = magic_to_printf_bytes(magic)
            sh_cmd = f'printf "{printf_bytes}" | nc -u -w1 {target_ip} 8888'
            cmd = ["docker", "exec", CONTAINER_NAME, "sh", "-c", sh_cmd]

            print(f"\n  [EXEC] {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            status = "SUCCESS" if result.returncode == 0 else "ERROR"
            detail = result.stdout or result.stderr or "(no output)"

            return json.dumps({
                "status":     status,
                "magic":      magic,
                "target_ip":  target_ip,
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
        マジックナンバーを指定して、そのチケットで認証されたIPの通信を遮断する。
        ユーザーが「マジックナンバー 0xXXXX を無効化して」「0xXXXX の疎通を禁止して」と
        指示したときに呼ぶ。送信元IPを知らなくてもマジックナンバーだけで遮断できる。

        Args:
            magic: 無効化したいマジックナンバー (例: 0x5d88366e)
        """
        magic = magic.lower().strip()
        if not magic:
            return json.dumps({"error": "magic は必須です"}, ensure_ascii=False)

        # ① /auth/logs からマジックナンバーに紐づくエントリを検索
        try:
            logs_raw = api.get_logs()
            logs = json.loads(logs_raw)
        except Exception:
            return json.dumps({"error": "auth/logs の取得に失敗しました"}, ensure_ascii=False)

        def normalize_magic(m: str) -> str:
            return m.lower().lstrip("0x").lstrip("0") or "0"

        target_norm = normalize_magic(magic)
        matched = [e for e in logs if normalize_magic(e.get("magic", "")) == target_norm]

        if not matched:
            return json.dumps({
                "error": f"マジックナンバー {magic} はログに存在しません",
                "available_magics": [e.get("magic") for e in logs]
            }, ensure_ascii=False)

        # ② /stats から現在通信中のIPを取得
        try:
            stats_raw = api.get_stats()
            stats = json.loads(stats_raw)
        except Exception:
            return json.dumps({"error": "stats の取得に失敗しました"}, ensure_ascii=False)

        active_ips = list({e["ip"] for e in stats if isinstance(e, dict) and "ip" in e})

        # ③ 通信中の全IPを revoke
        revoked = []
        errors  = []
        for ip in active_ips:
            result = api.revoke(ip)
            if "ERROR" in result.upper() or "error" in result.lower():
                errors.append({"ip": ip, "result": result})
            else:
                revoked.append({"ip": ip, "result": result})

        return json.dumps({
            "magic":       magic,
            "log_entries": matched,
            "revoked_ips": revoked,
            "errors":      errors,
            "status":      "SUCCESS" if revoked else "NO_ACTIVE_SESSION"
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
        """チケット発行履歴（認証ログ）を取得する。"""
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
SYSTEM_PROMPT = f"""あなたはSASE/XDPネットワークセキュリティシステムのAIオーケストレータです。
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

【認証フロー - 必ずこの順序でユーザーの指示を待つ】
1. ユーザーが「発行」を指示 → generate_magic_number を呼ぶ → 結果を報告して待機
2. ユーザーが「疎通を許可」を指示 → send_magic_to_container を呼ぶ → 結果を報告して待機
3. ユーザーが「無効化」を指示 → revoke_by_magic を呼ぶ → 結果を報告して待機

必ずツールを使って実際にAPIを操作し、結果をユーザーに日本語で簡潔に報告してください。"""


def build_agent() -> Agent:
    """MAF Agent を構築して返す"""
    api = SaseApiClient()
    tools = create_tools(api)

    client = OpenAIChatClient(
        model_id=MODEL,
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
    print("  SASE Agent - MAF rc5 移植版 (Groq / llama-3.3-70b-versatile)")
    print("  終了: 'exit' または 'quit'")
    print("=" * 60)
    print()
    print("【シナリオ例】")
    print("  > マジックナンバーを発行してください")
    print("  > マジックナンバー 0x5d88366e で 10.0.5.1 への疎通を許可してください")
    print("  > マジックナンバー 0x5d88366e を無効化してください")
    print()

    # MAFのセッションを会話全体で保持（会話履歴管理）
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
        # llama はツール呼び出しの JSON 生成に失敗することがある（400エラー）。
        # 同じ入力でリトライすることで大半は回復するため、最大2回まで再試行する。
        MAX_RETRY = 2
        for attempt in range(MAX_RETRY + 1):
            try:
                response = await agent.run(
                    messages=user_input,
                    session=session,
                )
                print(f"\nエージェント: {response.text}")
                break  # 成功したらリトライループを抜ける
            except Exception as e:
                err_str = str(e)
                # tool_use_failed: llama のツール呼び出し JSON 生成失敗
                if "tool_use_failed" in err_str and attempt < MAX_RETRY:
                    print(f"  ⚠️  ツール呼び出し生成に失敗しました。リトライします... "
                          f"({attempt + 1}/{MAX_RETRY})")
                    await asyncio.sleep(1)
                    continue
                # それ以外のエラー、またはリトライ上限に達した場合
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
