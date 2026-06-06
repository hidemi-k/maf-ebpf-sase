// Copyright (c) 2026 hidemi-k
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_ktime_get_ns, bpf_redirect},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ---------------------------------------------------------------------------
// 構造体定義
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Stats {
    pub packets:         u64,
    pub bytes:           u64,
    pub dropped_packets: u64,
    pub syn_packets:     u64,
    pub rst_packets:     u64,
    pub ack_packets:     u64,
    pub last_ts:         u64,
    pub flow_start_ns:   u64,
    pub user_id:         u32,
    pub policy_status:   u32,
    pub l7_proto_label:  u32,
    pub pkt_min:         u32,
    pub pkt_max:         u32,
    pub _pad:            u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub ip:       u32,
    pub port:     u16,
    pub protocol: u8,
    pub pad:      u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QosConfig {
    pub limit_bytes_per_sec: u64,
    pub tokens:              u64,
    pub last_updated:        u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthInfo {
    pub expiry:   u64,
    pub priority: u32,
    pub user_id:  u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RedirectConfig {
    pub ifindex: u32,
}

// ---------------------------------------------------------------------------
// eBPF MAP 定義
// ---------------------------------------------------------------------------

#[map]
static mut STATS_MAP:      HashMap<FlowKey, Stats>         = HashMap::with_max_entries(16384, 0);

#[map]
static mut DROP_LIST:      HashMap<FlowKey, u32>           = HashMap::with_max_entries(16384, 0);

#[map]
static mut QOS_MAP:        HashMap<u32, QosConfig>         = HashMap::with_max_entries(16384, 0);

#[map]
static mut AUTH_IPS:       HashMap<u32, AuthInfo>          = HashMap::with_max_entries(4096, 0);

/// CONFIG_MAP のキー割り当て
///   key=0 : magic チケット値（u64）。0=未設定, u64::MAX=使用済み番兵
///   key=1 : 認証有効期限（ナノ秒）。デフォルト 300s
///   key=2 : 認証受付ポート（u16 として下位16bitを使用）。デフォルト 8888
#[map]
static mut CONFIG_MAP:     HashMap<u32, u64>               = HashMap::with_max_entries(16, 0);

#[map]
static mut REDIRECT_CONFIG: HashMap<u32, RedirectConfig>   = HashMap::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// 定数
// ---------------------------------------------------------------------------

const DEFAULT_AUTH_DURATION: u64 = 300 * 1_000_000_000;  // 300秒（ns）
const DEFAULT_AUTH_PORT:     u16 = 8888;
const MAX_TOKENS:            u64 = 10_000_000;

// CONFIG_MAP のキー
const CFG_MAGIC:    u32 = 0;
const CFG_DURATION: u32 = 1;
const CFG_PORT:     u32 = 2;

// ---------------------------------------------------------------------------
// ヘルパー関数
// ---------------------------------------------------------------------------

/// パケット境界チェック付きポインタ取得
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end   = ctx.data_end();
    let len   = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// 認証受付ポートを CONFIG_MAP[2] から取得する。
/// 未設定の場合は DEFAULT_AUTH_PORT を返す。
/// Go 側の /config エンドポイントから動的変更可能にするための設計。
#[inline(always)]
fn get_auth_port() -> u16 {
    unsafe {
        CONFIG_MAP
            .get(&CFG_PORT)
            .map(|v| (*v & 0xFFFF) as u16)
            .unwrap_or(DEFAULT_AUTH_PORT)
    }
}

/// トークンバケット QoS。
/// priority >= 2 の認証済みユーザーは補充レートを10倍にする（スライシング）。
/// QOS_MAP に設定のない IP は無条件 PASS（QoS 未適用）。
#[inline(always)]
fn apply_qos(src_ip: u32, pkt_sz: u32, priority: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        if let Some(config) = QOS_MAP.get_ptr_mut(&src_ip) {
            let elapsed    = now.saturating_sub((*config).last_updated);
            let multiplier = if priority >= 2 { 10 } else { 1 };
            let refill     = (elapsed * (*config).limit_bytes_per_sec * multiplier)
                             / 1_000_000_000;

            (*config).tokens      = core::cmp::min(MAX_TOKENS, (*config).tokens + refill);
            (*config).last_updated = now;

            if (*config).tokens >= pkt_sz as u64 {
                (*config).tokens -= pkt_sz as u64;
                return true;
            }
            return false;
        }
    }
    true // QoS 未設定 IP は通過
}

/// VPP（xdp0）へのリダイレクト。
/// REDIRECT_CONFIG が未設定の場合は XDP_PASS にフォールバックする。
#[inline(always)]
fn redirect_to_vpp() -> Result<u32, ()> {
    unsafe {
        if let Some(cfg) = REDIRECT_CONFIG.get(&0u32) {
            let rc = bpf_redirect(cfg.ifindex, 0);
            return Ok(rc as u32);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

// ---------------------------------------------------------------------------
// XDP エントリポイント
// ---------------------------------------------------------------------------

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_)  => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let data     = ctx.data();
    let data_end = ctx.data_end();
    let pkt_sz   = (data_end - data) as u32;

    // --- Ethernet ヘッダ ---
    let eth = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
    if u16::from_be(unsafe { (*eth).ether_type as u16 }) != 0x0800 {
        // IPv4 以外は通過（ARP 等）
        return Ok(xdp_action::XDP_PASS);
    }

    // --- IP ヘッダ ---
    let iph      = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
    let src_addr = u32::from_be(unsafe { (*iph).src_addr });
    let protocol = unsafe { (*iph).proto as u8 };
    let l4_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let mut fk = FlowKey { ip: src_addr, port: 0, protocol, pad: 0 };
    let (mut is_syn, mut is_rst, mut is_ack) = (0u64, 0u64, 0u64);

    // --- L4 ヘッダ解析 + magic 認証 ---
    match protocol {
        6 => {
            // TCP
            let tcp   = unsafe { ptr_at::<TcpHdr>(&ctx, l4_offset)? };
            fk.port   = u16::from_be(unsafe { (*tcp).dest });
            let flags = unsafe { *tcp };
            if flags.syn() != 0 && flags.ack() == 0 { is_syn = 1; }
            if flags.rst() != 0 { is_rst = 1; }
            if flags.ack() != 0 { is_ack = 1; }
        }
        17 => {
            // UDP
            let udp = unsafe { ptr_at::<UdpHdr>(&ctx, l4_offset)? };
            fk.port = u16::from_be(unsafe { (*udp).dest });

            // --- magic チケット認証 ---
            // 認証受付ポートは CONFIG_MAP[2] から動的取得（デフォルト 8888）。
            // UDP ペイロードの先頭8バイトをビッグエンディアンで読み、
            // CONFIG_MAP[0] に登録済みの magic 値と比較する。
            // 一致した場合のみ src_addr（IP）を AUTH_IPS に登録し、
            // CONFIG_MAP[0] を u64::MAX（使用済み番兵）で上書きする。
            // これにより同一チケットの再利用を eBPF 層で防止する。
            //
            // 注意: user_id には src_addr を使用する。
            // magic の下位ビットを user_id に流用すると、攻撃者が
            // magic を細工することで任意の user_id を偽装できるため。
            let auth_port = get_auth_port();
            if fk.port == auth_port {
                if let Ok(tag_ptr) = unsafe {
                    ptr_at::<u64>(&ctx, l4_offset + UdpHdr::LEN)
                } {
                    let tag            = u64::from_be(unsafe { *tag_ptr });
                    let expected_magic = unsafe {
                        CONFIG_MAP.get(&CFG_MAGIC).unwrap_or(&0)
                    };

                    // 0（未設定）と u64::MAX（使用済み）は認証不可
                    let valid = *expected_magic != 0
                        && *expected_magic != u64::MAX
                        && tag == *expected_magic;

                    if valid {
                        let now      = unsafe { bpf_ktime_get_ns() };
                        let duration = unsafe {
                            CONFIG_MAP
                                .get(&CFG_DURATION)
                                .unwrap_or(&DEFAULT_AUTH_DURATION)
                        };

                        let info = AuthInfo {
                            expiry:   now + *duration,
                            priority: 2,
                            user_id:  src_addr,
                        };
                        unsafe {
                            let _ = AUTH_IPS.insert(&src_addr, &info, 0);
                            // チケットを使用済みに設定（再利用防止）
                            let sentinel = u64::MAX;
                            let _ = CONFIG_MAP.insert(&CFG_MAGIC, &sentinel, 0);
                        }
                        return Ok(xdp_action::XDP_PASS);
                    }
                }
                // magic 不一致でも認証ポート宛パケットは PASS
                // （認証試行パケット自体を DROP すると正規クライアントが
                //   ループするため。失敗ログは Go 側で記録する）
                return Ok(xdp_action::XDP_PASS);
            }
        }
        _ => {}
    }

    // --- 認証状態チェック ---
    let now = unsafe { bpf_ktime_get_ns() };
    let mut current_prio = 0u32;
    let mut user_id      = 0u32;

    let is_authed = unsafe {
        if let Some(info) = AUTH_IPS.get(&src_addr) {
            if info.expiry > now {
                current_prio = info.priority;
                user_id      = info.user_id;
                true
            } else {
                // 有効期限切れ → DROP（エントリは Go 側の定期 GC で削除）
                false
            }
        } else {
            false
        }
    };

    // --- 未認証 → 全トラフィック DROP ---
    if !is_authed {
        update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, user_id, current_prio, true);
        return Ok(xdp_action::XDP_DROP);
    }

    // --- 認証済み: ICMP は VPP へリダイレクト ---
    if protocol == 1 {
        update_stats(&fk, pkt_sz, 0, 0, 0, user_id, current_prio, false);
        return redirect_to_vpp();
    }

    // --- DROP_LIST チェック（個別ブロック） ---
    unsafe {
        if let Some(drop) = DROP_LIST.get(&fk) {
            if *drop == 1 {
                update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack,
                             user_id, current_prio, true);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    // --- Priority 3（VIP）は QoS をバイパスして VPP へ ---
    if current_prio == 3 {
        update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack,
                     user_id, current_prio, false);
        return redirect_to_vpp();
    }

    // --- QoS トークンバケット ---
    if !apply_qos(src_addr, pkt_sz, current_prio) {
        update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack,
                     user_id, current_prio, true);
        return Ok(xdp_action::XDP_DROP);
    }

    update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, user_id, current_prio, false);
    redirect_to_vpp()
}

// ---------------------------------------------------------------------------
// 統計更新
// ---------------------------------------------------------------------------

#[inline(always)]
fn update_stats(
    fk:      &FlowKey,
    pkt_sz:  u32,
    is_syn:  u64,
    is_rst:  u64,
    is_ack:  u64,
    user_id: u32,
    prio:    u32,
    dropped: bool,
) {
    unsafe {
        let now = bpf_ktime_get_ns();
        if let Some(s) = STATS_MAP.get_ptr_mut(fk) {
            (*s).packets += 1;
            if dropped {
                (*s).dropped_packets += 1;
            } else {
                (*s).bytes += pkt_sz as u64;
            }
            (*s).syn_packets  += is_syn;
            (*s).rst_packets  += is_rst;
            (*s).ack_packets  += is_ack;
            (*s).last_ts       = now;
            (*s).policy_status = prio;

            if pkt_sz < (*s).pkt_min { (*s).pkt_min = pkt_sz; }
            if pkt_sz > (*s).pkt_max { (*s).pkt_max = pkt_sz; }
        } else {
            let stats = Stats {
                packets:        1,
                bytes:          if dropped { 0 } else { pkt_sz as u64 },
                dropped_packets: if dropped { 1 } else { 0 },
                syn_packets:    is_syn,
                rst_packets:    is_rst,
                ack_packets:    is_ack,
                last_ts:        now,
                flow_start_ns:  now,
                user_id,
                policy_status:  prio,
                l7_proto_label: match fk.port {
                    80 | 443 => 1,  // HTTP/HTTPS
                    53       => 2,  // DNS
                    22       => 3,  // SSH
                    _        => 0,
                },
                pkt_min: pkt_sz,
                pkt_max: pkt_sz,
                _pad:    0,
            };
            let _ = STATS_MAP.insert(fk, &stats, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// panic ハンドラ（no_std 必須）
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
