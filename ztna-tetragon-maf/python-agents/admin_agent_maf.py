"""
SASE Admin Agent - MAF rc5 移植版 (Groq / llama-3.1-8b-instant)

変更点 (vs v4):
  [MAF移植]
    - AdminNarrator: Groq SDK 直接呼び出し → Agent + OpenAIChatClient に置き換え

  [バグ修正]
    - _is_reauthed() フォールバック判定の修正
        旧: src_ip が空 かつ identities が空でなければ → 再認証あり（緩すぎ）
        新: src_ip が空の場合は「再認証不明」として再遮断しない
        理由: linux2 の IP キャッシュ取得が失敗した場合、
              sase_agent 側の正規ユーザーが認証しているだけで
              「再認証あり」と誤判定し、遮断ループが永続してしまう

  [セキュリティ修正 - Go API修正に対応]
    - SaseApiClient.invalidate_ticket() を廃止し lock_ticket() に置き換え
        旧: /auth/ticket?magic=0x0 → 「0チケット発行」になるだけで無効化にならない
        新: /auth/lock → チケット発行を再起動まで恒久的にロックするAPIを呼び出す
    - SaseApiClient.get_blacklist() を追加（/auth/blacklist の参照用）
    - TicketRateMonitor: 大量発行検知時に invalidate_ticket() → lock_ticket() に変更
    - TetragonMonitor: 再遮断閾値到達時のチケット封鎖を /auth/lock に変更
    - format_config_state(): 番兵値 (0xffffffffffffffff) を「認証後リセット済み」と表示
    - AdminNarrator のプロンプトに /auth/lock・ブラックリスト情報を追加

  [変更なし]
    - SaseApiClient の revoke / stats / priority などの監視ロジック
    - threading による並列実行構造
"""

import os
import sys
import json
import time
import asyncio
import threading
import subprocess
import configparser
import requests
from datetime import datetime, timezone
from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient

# ── 設定 ────────────────────────────────────────────────────────────────────
GROQ_CONFIG_PATH = os.getenv("SASE_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config.ini"))

groq_api_key = ""
if os.path.exists(GROQ_CONFIG_PATH):
    config = configparser.ConfigParser()
    config.read(GROQ_CONFIG_PATH)
    if 'GROQ' in config and 'GROQ_API_KEY' in config['GROQ']:
        groq_api_key = config['GROQ']['GROQ_API_KEY'].strip()

SASE_API_URL       = os.getenv("SASE_API_URL", "http://localhost:8080")
GROQ_API_KEY       = os.getenv("GROQ_API_KEY", groq_api_key)
MODEL              = "llama-3.1-8b-instant"
TETRAGON_CONTAINER = "tetragon1"
DATAPLANE_SUBNET   = "10.0.5."
SIGKILL_THRESHOLD  = 2

# ── チケット発行レート監視設定 ────────────────────────────────────────────────
RATE_WINDOW_SEC    = 30
RATE_LIMIT         = 3
RATE_POLL_INTERVAL = 10


# ── SASE API クライアント ─────────────────────────────────────────────────────
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

    def get_identities(self) -> str:
        return self._get("/auth/identities")

    def revoke(self, ip: str) -> str:
        return self._get("/auth/revoke", {"ip": ip})

    def get_stats(self) -> str:
        return self._get("/stats")

    def get_logs(self) -> str:
        return self._get("/auth/logs")

    def get_config(self) -> str:
        return self._get("/config")

    def set_priority(self, ip: str, level: int) -> str:
        return self._get("/auth/priority", {"ip": ip, "level": level})

    def lock_ticket(self) -> str:
        """
        チケット発行を恒久ロックする（再起動まで解除不可）。
        旧実装の invalidate_ticket() は /auth/ticket?magic=0x0 を呼び出していたが、
        これは「0x0 チケットを発行するだけ」であり無効化にならなかった。
        Go API の /auth/lock エンドポイント追加に伴い置き換え。
        """
        return self._get("/auth/lock")

    def get_blacklist(self) -> str:
        """revoke 済みIPのブラックリスト一覧を取得（/auth/blacklist）"""
        return self._get("/auth/blacklist")

    def drop_block(self, ip: str, proto: str, port: int) -> str:
        return self._get("/drop/block", {"ip": ip, "proto": proto, "port": port})

    def drop_unblock(self, ip: str, proto: str, port: int) -> str:
        return self._get("/drop/unblock", {"ip": ip, "proto": proto, "port": port})

    def revoke_by_stats(self) -> list:
        try:
            stats = json.loads(self.get_stats())
            active_ips = list({e["ip"] for e in stats if isinstance(e, dict) and "ip" in e})
        except Exception as e:
            return [{"error": f"stats取得失敗: {e}"}]

        results = []
        for ip in active_ips:
            prio   = self.set_priority(ip, 1)
            result = self.revoke(ip)
            results.append({"ip": ip, "priority": prio.strip(), "result": result.strip()})
        return results


# ── ユーティリティ ────────────────────────────────────────────────────────────
def get_container_name_by_docker_id(docker_id_partial: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                container_id, name = parts
                if container_id.startswith(docker_id_partial[:12]):
                    return name
    except Exception as e:
        print(f"  [ERROR] docker ps failed: {e}")
    return ""


def build_ip_cache(subnet_prefix: str = DATAPLANE_SUBNET) -> dict:
    import re
    cache = {}
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        container_names = result.stdout.strip().splitlines()
    except Exception as e:
        print(f"  [WARN] docker ps failed: {e}")
        return cache

    for name in container_names:
        try:
            result = subprocess.run(
                ["docker", "exec", name, "ip", "addr", "show"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    if ip.startswith(subnet_prefix):
                        cache[name] = ip
                        break
        except Exception:
            pass

    return cache


def get_dataplane_ip(container_name: str, subnet_prefix: str = DATAPLANE_SUBNET,
                     cache: dict = None) -> str:
    import re

    if cache and container_name in cache:
        return cache[container_name]

    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "ip", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                if ip.startswith(subnet_prefix):
                    return ip
    except Exception as e:
        print(f"  [ERROR] ip addr failed: {e}")

    return ""


def now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")


def extract_auth_history(logs_raw: str, src_ip: str) -> list:
    try:
        logs = json.loads(logs_raw)
        if not isinstance(logs, list):
            return []
        return logs[-5:]
    except Exception:
        return []


def format_config_state(config_raw: str) -> str:
    try:
        cfg     = json.loads(config_raw)
        ticket  = cfg.get("current_magic_ticket", "不明")
        dur_ns  = cfg.get("auth_duration_ns", 0)
        dur_sec = int(dur_ns) // 1_000_000_000
        # 0x0        : 未発行
        # 0xffffffff...（u64::MAX）: 認証成功後のリセット済み番兵値（再利用不可）
        # それ以外   : 有効なチケットが待機中
        SENTINEL = "0xffffffffffffffff"
        if ticket in ("0x0", "0", "", "不明"):
            status = "未発行（0x0）"
        elif ticket.lower() == SENTINEL:
            status = "リセット済み（認証後番兵値・再発行待ち）"
        else:
            status = f"有効（{ticket}）"
        return f"チケット状態: {status} / 認証有効期限: {dur_sec}秒"
    except Exception:
        return f"config取得結果: {config_raw}"


# ── MAF: AdminNarrator ────────────────────────────────────────────────────────
class AdminNarrator:
    """
    MAF rc5 Agent によるセキュリティイベント解説生成。
    旧実装: Groq SDK 直接呼び出し
    新実装: Agent + OpenAIChatClient（ツールなし、解説生成専用）
    """

    SYSTEM_PROMPT = """あなたはSASEネットワークセキュリティシステムの監視AIです。
セキュリティイベントをリアルタイムで検知し、管理者向けに状況を日本語で簡潔に解説します。

【解説のスタイル】
- 何が起きたか（検知内容）
- なぜ危険か（脅威の説明）
- 何をしたか（自動対応の内容）
- 現在の状態（遮断後の状況・チケット状態・ブラックリスト状態）

【チケット制御に関する注意】
- /auth/lock が呼ばれるとエージェント再起動まで新規チケット発行が不可能になります
- revoke されたIPはブラックリストに登録され、一定期間は /auth/ticket 経由の再認証も拒否されます
- チケット状態が「リセット済み（番兵値）」の場合は正常な認証後の状態です

簡潔に、かつ非技術者にも伝わるように解説してください。"""

    def __init__(self):
        client = OpenAIChatClient(
            model_id=MODEL,
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
        self._agent = Agent(
            name="AdminNarrator",
            instructions=self.SYSTEM_PROMPT,
            client=client,
        )

    def narrate(self, event_summary: dict) -> str:
        """イベントサマリーを受け取り、管理者向け解説を生成する（同期ラッパー）"""

        auth_log_lines = ""
        for entry in event_summary.get("auth_logs", []):
            ts     = entry.get("timestamp", "")
            magic  = entry.get("magic", "")
            action = entry.get("action", "")
            auth_log_lines += f"  [{ts}] {action} magic={magic}\n"
        if not auth_log_lines:
            auth_log_lines = "  （ログなし）"

        prompt = f"""以下のセキュリティイベントが発生しました。管理者向けに状況を解説してください。

【検知情報】
- 攻撃元コンテナ: {event_summary.get('container_name', '不明')}
- 攻撃元IP: {event_summary.get('src_ip', '不明')}
- 不正操作内容: {event_summary.get('binary', '')} {event_summary.get('args', '')}
- tetragonポリシー: {event_summary.get('policy_name', '')}
- 検知回数: {event_summary.get('count', 0)}回

【自動対応】
- 優先度降格: {event_summary.get('priority_result', '未実施')}
- 遮断実行: {event_summary.get('action_taken', '')}
- 遮断結果: {event_summary.get('revoke_result', '')}
- チケット発行ロック: {event_summary.get('lock_result', '未実施')}
- ブラックリスト状態: {event_summary.get('blacklist_state', '未取得')}

【直近の認証ログ（チケット発行履歴）】
{auth_log_lines}
【遮断後のカーネルチケット状態】
{event_summary.get('config_state', '取得失敗')}
"""
        try:
            # Agent.run() は async のため asyncio.run() でラップ
            response = asyncio.run(self._agent.run(prompt))
            return response.text or ""
        except Exception as e:
            return f"[LLM ERROR] {e}"


# ── チケット発行レート監視 ────────────────────────────────────────────────────
class TicketRateMonitor:
    def __init__(self, api: SaseApiClient):
        self.api               = api
        self._stop_event       = threading.Event()
        # クールダウン: アラート後 RATE_WINDOW_SEC 秒間は再発火しない
        # 旧実装の _last_alerted_count 比較は件数減少時に再発火する問題があった
        self._last_alerted_at: float = 0.0

    def _parse_log_timestamp(self, ts_str: str):
        if not ts_str:
            return None
        try:
            if "." in ts_str:
                base, frac = ts_str.rstrip("Z").split(".", 1)
                frac = frac[:6].ljust(6, "0")
                return datetime.fromisoformat(f"{base}.{frac}+00:00")
            return datetime.strptime(
                ts_str.rstrip("Z"), "%Y-%m-%dT%H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def _check(self):
        try:
            logs_raw = self.api.get_logs()
            logs = json.loads(logs_raw)
            if not isinstance(logs, list) or len(logs) == 0:
                return
        except Exception:
            return

        now    = datetime.now(timezone.utc)
        recent = []
        for entry in logs:
            # 除外対象:
            #   0x0              : 旧実装の invalidate_ticket() 呼び出し残骸（互換性のため残す）
            #   REVOKED_AND_BLACKLISTED: revoke API のログエントリ（チケット発行ではない）
            magic  = entry.get("magic", "").lower().strip()
            action = entry.get("action", "")
            if magic in ("0x0", "0x00000000", "0", "-"):
                continue
            if action.startswith("REVOKED_AND_BLACKLISTED"):
                continue
            ts = self._parse_log_timestamp(entry.get("timestamp", ""))
            if ts and (now - ts).total_seconds() <= RATE_WINDOW_SEC:
                recent.append(entry)

        count = len(recent)

        if count < RATE_LIMIT:
            return

        # クールダウン中はスキップ（RATE_WINDOW_SEC 秒間は再発火しない）
        now_ts = time.monotonic()
        if now_ts - self._last_alerted_at < RATE_WINDOW_SEC:
            return

        self._last_alerted_at = now_ts

        print(f"\n{'!'*60}")
        print(f"[{now_str()}] 🚨 チケット大量発行を検知: "
              f"{RATE_WINDOW_SEC}秒以内に {count}件（閾値: {RATE_LIMIT}件）")
        for e in recent:
            print(f"           [{e.get('timestamp','')}] "
                  f"{e.get('magic','')} from {e.get('remote_ip','')}")
        print(f"{'!'*60}")

        # /auth/lock でチケット発行を恒久ロック
        # 旧実装: /auth/ticket?magic=0x0 → 「0チケット発行」にしかならず sase_agent に上書きされる
        # 新実装: /auth/lock → 再起動まで一切のチケット発行を拒否する
        print(f"[{now_str()}] 🔒 チケット発行を恒久ロック: /auth/lock")
        lock_result = self.api.lock_ticket()
        print(f"[{now_str()}] 📡 ロック結果: {lock_result.strip()}")

        print(f"[{now_str()}] 🔒 認証中IP 一斉revoke開始...")
        revoke_results = self.api.revoke_by_stats()
        if revoke_results and "error" not in revoke_results[0]:
            for r in revoke_results:
                print(f"[{now_str()}] 🔒 revoke: {r['ip']} → {r['result']}")
            print(f"[{now_str()}] ✅ 大量発行攻撃への対応完了（ロック済み）")
        else:
            print(f"[{now_str()}] ℹ️  認証中IPなし（または取得失敗）")

    def run(self):
        print(f"[{now_str()}] 🔍 チケットレート監視開始"
              f"（{RATE_WINDOW_SEC}秒/{RATE_LIMIT}件 閾値、{RATE_POLL_INTERVAL}秒間隔）")
        while not self._stop_event.is_set():
            self._check()
            self._stop_event.wait(RATE_POLL_INTERVAL)

    def stop(self):
        self._stop_event.set()


# ── Tetragon 監視エンジン ────────────────────────────────────────────────────
class TetragonMonitor:
    # 再遮断がこの回数を超えたらチケット発行を封鎖する
    REREVOKE_LOCKOUT_THRESHOLD = 2

    def __init__(self, api: SaseApiClient, narrator: AdminNarrator, ip_cache: dict):
        self.api      = api
        self.narrator = narrator
        self.ip_cache = ip_cache
        self.sigkill_counts: dict[str, int]    = {}
        self.revoked_ids: set[str]             = set()
        # docker_id → 遮断時に特定した src_ip（None = IP不明）
        self.revoked_ip: dict[str, str | None] = {}
        # docker_id → 再遮断回数（チケット封鎖判定に使用）
        self.rerevoke_counts: dict[str, int]   = {}
        # チケット発行封鎖済みフラグ
        self.ticket_locked: bool               = False

    def _is_reauthed(self, docker_id: str) -> bool:
        """
        遮断済みコンテナが再認証されているか判定する。

        【修正点】
        フォールバック時（IP が特定できなかった場合）は revoked_ip[docker_id] = None。
        この場合「再認証かどうか不明」として False を返し、再遮断ループを防ぐ。

        旧実装の問題:
          revoked_ip = "" のとき identities が空でなければ「再認証あり」と判定していた。
          sase_agent 側の正規ユーザーが認証しているだけで誤検知し、
          遮断 → 再認証検出 → 再遮断 のループが無限に続いていた。
        """
        src_ip = self.revoked_ip.get(docker_id)  # None = フォールバック時

        # IP が不明な場合は再認証判定を行わない（誤検知防止）
        if src_ip is None:
            return False

        try:
            identities_raw = self.api.get_identities()
            identities     = json.loads(identities_raw)
            if not isinstance(identities, dict):
                return False
            return src_ip in identities
        except Exception:
            return False

    def _handle_sigkill_event(self, event: dict):
        kprobe    = event.get("process_kprobe", {})
        process   = kprobe.get("process", {})
        docker_id = process.get("docker", "")
        binary    = process.get("binary", "")
        args_list = kprobe.get("args", [])
        args_str  = " ".join(a.get("string_arg", "") for a in args_list)
        policy    = kprobe.get("policy_name", "")
        action    = kprobe.get("action", "")

        if action != "KPROBE_ACTION_SIGKILL":
            return
        if not docker_id:
            return

        self.sigkill_counts[docker_id] = self.sigkill_counts.get(docker_id, 0) + 1
        count = self.sigkill_counts[docker_id]

        ts = now_str()
        print(f"\n{'='*60}")
        print(f"[{ts}] 🚨 SIGKILL検知 #{count}")
        print(f"  コンテナID : {docker_id[:12]}")
        print(f"  操作内容   : {binary} {args_str}")
        print(f"  ポリシー   : {policy}")
        print(f"{'='*60}")

        if count < SIGKILL_THRESHOLD:
            print(f"  ⚠️  警告: あと{SIGKILL_THRESHOLD - count}回で自動遮断します")
            return

        if docker_id in self.revoked_ids:
            if not self._is_reauthed(docker_id):
                # 遮断済み かつ 再認証なし（またはIP不明）→ スキップ
                src_ip_display = self.revoked_ip.get(docker_id) or "不明"
                print(f"  ℹ️  {docker_id[:12]} は遮断済みかつ再認証なし"
                      f"（IP: {src_ip_display}）→ スキップ")
                return
            # 再遮断回数をカウント
            self.rerevoke_counts[docker_id] = self.rerevoke_counts.get(docker_id, 0) + 1
            rerevoke_count = self.rerevoke_counts[docker_id]
            print(f"  🔄 {docker_id[:12]} の再認証を検出 → 再遮断シーケンスを実行します"
                  f"（再遮断 {rerevoke_count}回目）")

            # 再遮断が閾値を超えた場合の対応
            if rerevoke_count >= self.REREVOKE_LOCKOUT_THRESHOLD:
                if not self.ticket_locked:
                    # /auth/lock を呼び出してチケット発行を恒久ロック
                    # 旧実装: /auth/ticket?magic=0x0 は「0チケット発行」でしかなく
                    #         sase_agent が直後に上書きできてしまう問題があった
                    # 新実装: /auth/lock → Go API が再起動まで発行を完全拒否する
                    self.ticket_locked = True
                    lock_result = self.api.lock_ticket()
                    print(f"\n[{now_str()}] 🔐 再遮断が{rerevoke_count}回に達しました。")
                    print(f"[{now_str()}] 🔒 /auth/lock を実行しました: {lock_result.strip()}")
                    print(f"[{now_str()}] ℹ️  チケット発行はエージェント再起動まで禁止されます。")
                    print(f"[{now_str()}] 👤 管理者による手動対応を推奨します：")
                    print(f"[{now_str()}]    → sase_agent を停止するか、"
                          f"linux2 への SSH 経路を物理的に遮断してください。")
                else:
                    print(f"[{now_str()}] 🔐 封鎖継続中（再遮断 {rerevoke_count}回目）"
                          f"→ 即時 revoke で対応します（チケット発行ロック済み）。")

        # ── 自動遮断シーケンス ──────────────────────────────────────────
        print(f"\n[{now_str()}] 🔍 閾値({SIGKILL_THRESHOLD}回)到達 → 自動遮断シーケンス開始")

        # ① コンテナ名特定
        container_name = get_container_name_by_docker_id(docker_id)
        print(f"[{now_str()}] 📦 コンテナ名特定: {docker_id[:12]} → {container_name or '不明'}")

        # ② データプレーンIP取得
        src_ip = ""
        if container_name:
            src_ip = get_dataplane_ip(container_name, cache=self.ip_cache)
            print(f"[{now_str()}] 🌐 IPアドレス特定: {container_name} → {src_ip or '取得失敗'}")

        # ③ 認証ログ取得
        print(f"[{now_str()}] 📋 認証ログ取得中... (/auth/logs)")
        logs_raw  = self.api.get_logs()
        auth_logs = extract_auth_history(logs_raw, src_ip)
        print(f"[{now_str()}] 📋 直近ログ {len(auth_logs)}件 取得完了")

        # ④ 優先度降格
        priority_result = "未実施（IP取得失敗）"
        if src_ip:
            print(f"[{now_str()}] ⬇️  優先度降格: /auth/priority?ip={src_ip}&level=1")
            prio_raw        = self.api.set_priority(src_ip, 1)
            priority_result = prio_raw.strip()
            print(f"[{now_str()}] 📡 降格結果: {priority_result}")

        # ⑤ revoke
        revoke_result = ""
        if src_ip:
            revoke_result = self.api.revoke(src_ip)
            self.revoked_ids.add(docker_id)
            self.revoked_ip[docker_id] = src_ip
            print(f"[{now_str()}] 🔒 自動遮断実行: /auth/revoke?ip={src_ip}")
            print(f"[{now_str()}] 📡 遮断結果: {revoke_result.strip()}")
        else:
            # ── IPキャッシュ取得失敗時のフォールバック ──────────────────────
            # linux2 のような「データプレーンIPを持たないコンテナ」のケース:
            #   linux2 は 10.0.5. サブネットを持たず SASE 認証対象外。
            #   linux2 への侵入経路は「linux1(10.0.5.x) で認証 → SSH で linux2 へ」。
            #   よって linux1 の認証を revoke することが正しい遮断手段。
            #
            # 対処方針:
            #   ① /stats から「現在認証中の踏み台IP」を特定して revoke
            #      ※ 全IP を対象にするが、これは意図的な踏み台遮断
            #   ② revoked_ip[docker_id] = None のままにして再遮断ループは防ぐ
            #      ただし /auth/identities で踏み台IPが再認証されたら再遮断する

            print(f"[{now_str()}] ⚠️  {container_name} はデータプレーンIP({DATAPLANE_SUBNET}x)を"
                  f"持ちません")
            print(f"[{now_str()}] 🔍 踏み台経由の侵入と判断 → /stats から認証中IPを遮断します")

            results = self.api.revoke_by_stats()
            self.revoked_ids.add(docker_id)

            if results and "error" not in results[0]:
                revoked_ips = [r["ip"] for r in results]
                for r in results:
                    print(f"[{now_str()}] ⬇️  降格: {r['ip']} → {r.get('priority', '?')}")
                    print(f"[{now_str()}] 🔒 踏み台遮断: {r['ip']} → {r['result']}")
                revoke_result   = json.dumps(results, ensure_ascii=False)
                src_ip          = ", ".join(revoked_ips)
                priority_result = " / ".join(
                    f"{r['ip']}: {r.get('priority', '?')}" for r in results
                )
                # 踏み台IPが1つに絞れた場合は再認証チェックを有効にする
                if len(revoked_ips) == 1:
                    self.revoked_ip[docker_id] = revoked_ips[0]
                    print(f"[{now_str()}] ✅ 踏み台遮断完了。"
                          f"再認証検出時は {revoked_ips[0]} を再遮断します。")
                else:
                    self.revoked_ip[docker_id] = None
                    print(f"[{now_str()}] ✅ 踏み台遮断完了（複数IP）。"
                          f"以降この コンテナの再認証チェックはスキップします。")
            else:
                revoke_result   = json.dumps(results, ensure_ascii=False)
                priority_result = "未実施"
                self.revoked_ip[docker_id] = None
                print(f"[{now_str()}] ❌ 踏み台遮断失敗（認証中IPなし）: {revoke_result}")

        # ⑥ チケット状態確認
        print(f"[{now_str()}] 🔑 チケット状態確認中... (/config)")
        config_raw   = self.api.get_config()
        config_state = format_config_state(config_raw)
        print(f"[{now_str()}] 🔑 {config_state}")

        # ⑦ ブラックリスト確認
        print(f"[{now_str()}] 📋 ブラックリスト確認中... (/auth/blacklist)")
        blacklist_raw   = self.api.get_blacklist()
        blacklist_state = blacklist_raw.strip() if blacklist_raw.startswith("[") else "取得失敗"
        try:
            bl_entries = json.loads(blacklist_raw)
            if isinstance(bl_entries, list) and bl_entries:
                blacklist_state = (
                    "ブラックリスト中: "
                    + ", ".join(f"{e.get('ip')} (残{e.get('expires_in')})" for e in bl_entries)
                )
            else:
                blacklist_state = "ブラックリスト：なし"
        except Exception:
            pass
        print(f"[{now_str()}] 📋 {blacklist_state}")

        # ⑧ MAF Agent による管理者向け解説
        print(f"\n[{now_str()}] 🤖 管理者向け解説を生成中...")
        event_summary = {
            "container_name":  container_name or docker_id[:12],
            "src_ip":          src_ip,
            "binary":          binary,
            "args":            args_str,
            "policy_name":     policy,
            "count":           count,
            "auth_logs":       auth_logs,
            "priority_result": priority_result,
            "action_taken":    f"/auth/revoke?ip={src_ip}",
            "revoke_result":   revoke_result.strip(),
            "config_state":    config_state,
            "lock_result":     "ロック済み（/auth/lock 実行）" if self.ticket_locked else "未実施",
            "blacklist_state": blacklist_state,
        }
        narration = self.narrator.narrate(event_summary)

        print(f"\n{'─'*60}")
        print(f"📋 【セキュリティレポート】")
        print(f"{'─'*60}")
        print(narration)
        print(f"{'─'*60}\n")

    def run(self):
        print(f"[{now_str()}] 🚀 Tetragon監視開始")
        print(f"[{now_str()}] 📡 コンテナ: {TETRAGON_CONTAINER}")
        print(f"[{now_str()}] 🎯 自動遮断閾値: SIGKILL {SIGKILL_THRESHOLD}回")
        print(f"[{now_str()}] 待機中... (Ctrl+C で終了)\n")

        cmd = ["docker", "exec", TETRAGON_CONTAINER, "tetra", "getevents"]

        while True:
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                print(f"[{now_str()}] ✅ tetragetevents ストリーム接続成功")

                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if "process_kprobe" in event:
                            action = event["process_kprobe"].get("action", "")
                            if action == "KPROBE_ACTION_SIGKILL":
                                self._handle_sigkill_event(event)
                    except json.JSONDecodeError:
                        pass

                proc.wait()
                print(f"[{now_str()}] ⚠️  ストリーム切断、5秒後に再接続...")
                time.sleep(5)

            except KeyboardInterrupt:
                print(f"\n[{now_str()}] 終了します。")
                break
            except Exception as e:
                print(f"[{now_str()}] ❌ エラー: {e} → 5秒後に再試行")
                time.sleep(5)


# ── メイン ────────────────────────────────────────────────────────────────────
def main():
    os.system("clear")
    print("=" * 60)
    print("  SASE Admin Agent - MAF rc5 移植版")
    print("  Tetragon監視 ＋ チケットレート監視 → 段階的対応 → 自動遮断 → 管理者向け解説")
    print("=" * 60)
    print()

    if not GROQ_API_KEY:
        print("❌ GROQ_API_KEY が設定されていません")
        sys.exit(1)

    api      = SaseApiClient()
    narrator = AdminNarrator()

    print(f"[{now_str()}] 🗺️  コンテナIPキャッシュ構築中...")
    ip_cache = build_ip_cache()
    if ip_cache:
        for name, ip in ip_cache.items():
            print(f"           {name} → {ip}")
    else:
        print(f"           ⚠️  データプレーンIP ({DATAPLANE_SUBNET}x) を持つコンテナが見つかりません")
    print()

    rate_monitor = TicketRateMonitor(api)
    rate_thread  = threading.Thread(target=rate_monitor.run, daemon=True)
    rate_thread.start()

    monitor = TetragonMonitor(api, narrator, ip_cache)
    try:
        monitor.run()
    finally:
        rate_monitor.stop()


if __name__ == "__main__":
    main()
