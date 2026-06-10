#![no_std]
#![no_main]



use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuHashMap},
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use core::mem;
use aincrad_common::ReputationRecord;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitBucket {
    pub tokens: u32,
    pub _padding: u32,
    pub last_updated: u64,
}

#[map]
static RATE_LIMIT_MAP: PerCpuHashMap<u32, RateLimitBucket> =
    PerCpuHashMap::with_max_entries(10240, 0);

#[map]
static REPUTATION_MAP: HashMap<u32, ReputationRecord> = 
    HashMap::with_max_entries(1024, 0);

#[repr(C)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: u16,
}

#[repr(C)]
pub struct Ipv4Hdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub res1_doff: u8,
}

#[xdp]
pub fn aincrad_xdp(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            aya_log_ebpf::error!(&ctx, "!!! AINCRAD FALHOU NO TRY: código {} !!!", e);
            xdp_action::XDP_PASS
        }
    }
}

fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth = data as *const EthHdr;
    if data + mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS); 
    }

    let eth_type = u16::from_be(unsafe { (*eth).ether_type });
    aya_log_ebpf::info!(ctx, "!!! VIVO !!! EtherType detectado: {}", eth_type);

    if eth_type != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }


    let ip_start = data + 14;

    if ip_start + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = unsafe { &*(ip_start as *const Ipv4Hdr) };
    let src_addr = ip_hdr.src_addr;
    let now = unsafe { bpf_ktime_get_ns() };

    let ihl = unsafe { (*(ip_start as *const u8)) & 0x0F };
    let ip_hdr_len = (ihl as usize) * 4;

    if ip_hdr_len < 20 || ip_start + ip_hdr_len > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp_start = ip_start + ip_hdr_len;

    if tcp_start + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let dest_port = u16::from_be(unsafe { *((tcp_start + 2) as *const u16) });
    if dest_port != 8080 {
        return Ok(xdp_action::XDP_DROP);
    }

    let doff_byte = unsafe { *((tcp_start + 12) as *const u8) };
    let tcp_hlen = ((doff_byte >> 4) as usize) * 4; 

    if tcp_start + tcp_hlen > data_end {
        return Ok(xdp_action::XDP_PASS);
    }


    let mut current_offset = 14 + ip_hdr_len + tcp_hlen;

    if data + current_offset >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }




    let mut found = false;
    
    if data + current_offset + 4 <= data_end {
        let p = unsafe { *((data + current_offset) as *const [u8; 4]) };
        aya_log_ebpf::info!(ctx, "PAYLOAD REAL DETECTADO -> {} {} {} {}", p[0], p[1], p[2], p[3]);
    }

    for _ in 0..128 {
        if data + current_offset + 4 > data_end {
            break;
        }

        let chunk = unsafe { *((data + current_offset) as *const u32) };
        
        let chunk_lower = chunk | 0x20202020;

        let value = u32::from_be(chunk_lower);

        if value == 0x73656C65 || value == 0x70696E67 {
            found = true;
            break;
        }

        current_offset += 1;
    }


    if let Some(global_record) = unsafe { REPUTATION_MAP.get(&src_addr) } {
        if now < global_record.ban_until {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    const TOKENS_REGEN_PER_NS: u64 = 10_000_000; // 1 token a cada 10ms
    const MAX_TOKENS: u32 = 100;

    let mut bucket = match unsafe { RATE_LIMIT_MAP.get(&src_addr) } {
        Some(bucket_ptr) => *bucket_ptr, 
        None => RateLimitBucket {
            tokens: MAX_TOKENS,
            _padding: 0,
            last_updated: now,
        },
    };

    let elapsed = now.saturating_sub(bucket.last_updated);
    let tokens_to_add = (elapsed / TOKENS_REGEN_PER_NS) as u32;

    if tokens_to_add > 0 {
        bucket.tokens = core::cmp::min(MAX_TOKENS, bucket.tokens + tokens_to_add);
        bucket.last_updated = now;
    }

    if bucket.tokens > 0 {
        bucket.tokens -= 1;
        let _ = RATE_LIMIT_MAP.insert(&src_addr, &bucket, 0);
    } else {
        let _ = RATE_LIMIT_MAP.insert(&src_addr, &bucket, 0);
        return Ok(xdp_action::XDP_DROP);
    }

    if found {
        let global_ban = ReputationRecord {
            balance: 0,
            _padding: 0,
            ban_until: now + 60_000_000_000,
            last_updated: now,
        };

        let _ = REPUTATION_MAP.insert(&src_addr, &global_ban, 0);
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
