// Copyright (c) 2026 hidemi-k
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
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

#[map]
static mut STATS_MAP: HashMap<FlowKey, Stats> = HashMap::with_max_entries(16384, 0);

#[map]
static mut DROP_LIST: HashMap<FlowKey, u32> = HashMap::with_max_entries(16384, 0);

#[map]
static mut QOS_MAP: HashMap<u32, QosConfig> = HashMap::with_max_entries(16384, 0);

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
fn apply_qos(src_ip: u32, pkt_sz: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        if let Some(config) = QOS_MAP.get_ptr_mut(&src_ip) {
            let elapsed = now.saturating_sub((*config).last_updated);
            let refill = (elapsed * (*config).limit_bytes_per_sec) / 1_000_000_000;
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
        }
        _ => {}
    }

    unsafe {
        // --- 1. ブロックリスト判定 ---
        if let Some(drop) = DROP_LIST.get(&fk) {
            if *drop == 1 {
                update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, true);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        // --- 2. QoS判定 (IP単位) ---
        if !apply_qos(src_addr, pkt_sz) {
            update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, true);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // --- 3. 正常パケットの統計更新と通過 ---
    update_stats(&fk, pkt_sz, is_syn, is_rst, is_ack, false);
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn update_stats(fk: &FlowKey, pkt_sz: u32, is_syn: u64, is_rst: u64, is_ack: u64, dropped: bool) {
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
                user_id: 0,
                policy_status: 0,
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

