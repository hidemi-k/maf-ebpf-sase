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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub syn_packets: u64,
    pub rst_packets: u64,
    pub ack_packets: u64,
    pub last_ts: u64,
    pub flow_start_ns: u64,
    pub user_id: u32,
    pub policy_status: u32,
    pub l7_proto_label: u32,
    pub pkt_min: u32,
    pub pkt_max: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QosConfig {
    pub limit_bytes_per_sec: u64,
    pub tokens: u64,
    pub last_updated: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthInfo {
    pub expiry: u64,
    pub priority: u32,
    pub user_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RedirectConfig {
    pub ifindex: u32,
}

#[map]
static mut STATS_MAP: HashMap<FlowKey, Stats> = HashMap::with_max_entries(16384, 0);

#[map]
static mut DROP_LIST: HashMap<FlowKey, u32> = HashMap::with_max_entries(16384, 0);

#[map]
static mut QOS_MAP: HashMap<u32, QosConfig> = HashMap::with_max_entries(16384, 0);

#[map]
static mut AUTH_IPS: HashMap<u32, AuthInfo> = HashMap::with_max_entries(4096, 0);

#[map]
static mut CONFIG_MAP: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

#[map]
static mut REDIRECT_CONFIG: HashMap<u32, RedirectConfig> = HashMap::with_max_entries(1, 0);

const DEFAULT_AUTH_DURATION: u64 = 300 * 1_000_000_000;
const MAX_TOKENS: u64 = 10_000_000;

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end { return Err(()); }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn apply_qos(src_ip: u32, pkt_sz: u32, priority: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        if let Some(config) = QOS_MAP.get_ptr_mut(&src_ip) {
            let elapsed = now.saturating_sub((*config).last_updated);
            let multiplier = if priority >= 2 { 10 } else { 1 };
            let refill = (elapsed * (*config).limit_bytes_per_sec * multiplier) / 1_000_000_000;

            (*config).tokens = core::cmp::min(MAX_TOKENS, (*config).tokens + refill);
            (*config).last_updated = now;

            if (*config).tokens >= pkt_sz as u64 {
                (*config).tokens -= pkt_sz as u64;
                return true;
            }
            return false;
        }
    }
    true
}

#[inline(always)]
fn redirect_to_vpp() -> Result<u32, ()> {
    unsafe {
        if let Some(cfg) = REDIRECT_CONFIG.get(&0u32) {
            let rc = bpf_redirect(cfg.ifindex, 0);
            return Ok(rc as u32);
        }
    }
    // フォールバック：設定されてなければ PASS
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_sz = (data_end - data) as u32;

    let eth = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
    if u16::from_be(unsafe { (*eth).ether_type as u16 }) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let iph = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
    let src_addr = u32::from_be(unsafe { (*iph).src_addr });
    let protocol = unsafe { (*iph).proto as u8 };
    let l4_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let mut fk = FlowKey { ip: src_addr, port: 0, protocol, pad: 0 };
    let (mut is_syn, mut is_rst, mut is_ack) = (0, 0, 0);

    match protocol {
        6 => {
            let tcp = unsafe { ptr_at::<TcpHdr>(&ctx, l4_offset)? };
            fk.port = u16::from_be(unsafe { (*tcp).dest });
            let flags = unsafe { *tcp };
            if flags.syn() != 0 && flags.ack() == 0 { is_syn = 1; }
            if flags.rst() != 0 { is_rst = 1; }
            if flags.ack() != 0 { is_ack = 1; }
        }
        17 => {
            let udp = unsafe { ptr_at::<UdpHdr>(&ctx, l4_offset)? };
            fk.port = u16::from_be(unsafe { (*udp).dest });

            // ===== マジックナンバー認証 =====
            if fk.port == 8888 {
                if let Ok(tag_ptr) = unsafe { ptr_at::<u64>(&ctx, l4_offset + UdpHdr::LEN) } {
                    let tag = u64::from_be(unsafe { *tag_ptr });
                    let magic_key = 0u32;
                    let expected_magic = unsafe { CONFIG_MAP.get(&magic_key).unwrap_or(&0) };

                    // CONFIG_MAP の値をビッグエンディアンに変換して比較
                    // 0 は未設定、u64::MAX は認証後の番兵値（いずれも認証不可）
                    if *expected_magic != 0 && *expected_magic != u64::MAX && tag == *expected_magic {
                        let now = unsafe { bpf_ktime_get_ns() };
                        let duration_key = 1u32;
                        let duration = unsafe { CONFIG_MAP.get(&duration_key).unwrap_or(&DEFAULT_AUTH_DURATION) };

                        // user_id はパケット送信元IPから取得する（magic値を流用しない）
                        // magic値の下位32bitをuser_idに使うと攻撃者が任意のIDを偽装できる
                        let info = AuthInfo {
                            expiry: now + *duration,
                            priority: 2,
                            user_id: src_addr,
                        };
                        unsafe {
                            let _ = AUTH_IPS.insert(&src_addr, &info, 0);
                            // 認証後は CONFIG_MAP[0] を u64::MAX（番兵値）で上書きし
                            // 「0チケット」での再利用・偽無効化を防ぐ
                            // Go側の /auth/lock または次の正規チケット発行まで無効状態を維持
                            let _ = CONFIG_MAP.insert(&magic_key, &u64::MAX, 0);
                        }
                        return Ok(xdp_action::XDP_PASS);
                    }
                }
            }
        }
        _ => {}
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let mut current_prio = 0;
    let mut user_id = 0;

    let is_authed = unsafe {
        if let Some(info) = AUTH_IPS.get(&src_addr) {
            if info.expiry > now {
                current_prio = info.priority;
                user_id = info.user_id;
                true
            } else { false }
        } else { false }
    };

    // ===== UDP 8888 (マジックナンバー認証) は未認証でも許可 =====
    if protocol == 17 && fk.port == 8888 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ===== 未認証の場合、すべてのトラフィックをDROP（ICMP 含む） =====
    if !is_authed {
        update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, user_id, current_prio, true);
        return Ok(xdp_action::XDP_DROP);
    }

    // ===== 認証済みの場合は ICMP を許可（VPPにリダイレクト） =====
    if protocol == 1 {
        update_stats(&fk, pkt_sz, 0, 0, 0, user_id, current_prio, false);
        return redirect_to_vpp();
    }

    unsafe {
        if let Some(drop) = DROP_LIST.get(&fk) {
            if *drop == 1 {
                update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, user_id, current_prio, true);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    if current_prio == 3 {
        update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, user_id, current_prio, false);
        return redirect_to_vpp();
    }

    if !apply_qos(src_addr, pkt_sz, current_prio) {
        update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, user_id, current_prio, true);
        return Ok(xdp_action::XDP_DROP);
    }

    update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, user_id, current_prio, false);
    redirect_to_vpp()
}

#[inline(always)]
fn update_stats(fk: &FlowKey, pkt_sz: u32, is_syn: u64, is_rst: u64, is_ack: u64, user_id: u32, prio: u32, dropped: bool) {
    unsafe {
        let now = bpf_ktime_get_ns();
        if let Some(s_ptr) = STATS_MAP.get_ptr_mut(fk) {
            (*s_ptr).packets += 1;
            if dropped {
                (*s_ptr).dropped_packets += 1;
            } else {
                (*s_ptr).bytes += pkt_sz as u64;
            }
            (*s_ptr).syn_packets += is_syn;
            (*s_ptr).rst_packets += is_rst;
            (*s_ptr).ack_packets += is_ack;
            (*s_ptr).last_ts = now;
            (*s_ptr).policy_status = prio;

            if pkt_sz < (*s_ptr).pkt_min { (*s_ptr).pkt_min = pkt_sz; }
            if pkt_sz > (*s_ptr).pkt_max { (*s_ptr).pkt_max = pkt_sz; }
        } else {
            let stats = Stats {
                packets: 1,
                bytes: if dropped { 0 } else { pkt_sz as u64 },
                dropped_packets: if dropped { 1 } else { 0 },
                syn_packets: is_syn,
                rst_packets: is_rst,
                ack_packets: is_ack,
                last_ts: now,
                flow_start_ns: now,
                user_id,
                policy_status: prio,
                l7_proto_label: match fk.port {
                    80 | 443 => 1,
                    53 => 2,
                    22 => 3,
                    _ => 0
                },
                pkt_min: pkt_sz,
                pkt_max: pkt_sz,
                _pad: 0,
            };
            let _ = STATS_MAP.insert(fk, &stats, 0);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

