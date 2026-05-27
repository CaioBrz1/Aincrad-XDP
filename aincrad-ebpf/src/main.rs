#![no_std]
#![no_main]

use network_types::eth::{EthHdr, EtherType};
use network_types::tcp::TcpHdr;
use aincrad_common::ReputationRecord;
use network_types::ip::Ipv4Hdr;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_ebpf::helpers::bpf_ktime_get_ns;


fn is_banned(record: &ReputationRecord) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    now < record.ban_until
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static REPUTATION_MAP: HashMap<u32, ReputationRecord> = HashMap::<u32, ReputationRecord>::with_max_entries(10000, 0);

#[map]
pub static BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn aincrad_xdp(ctx: XdpContext) -> u32 {
    let data = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;

    if data + 64 > data_end {
        return xdp_action::XDP_PASS;
    }

    let ip_hdr: Ipv4Hdr = unsafe { ((data + 14) as *const Ipv4Hdr).read_unaligned() };
    let tcp_hdr: TcpHdr = unsafe { ((data + 34) as *const TcpHdr).read_unaligned() };
    if tcp_hdr.dest != u16::to_be(8080) {
    return xdp_action::XDP_PASS; 
}

    let src_addr = ip_hdr.src_addr;
    let tcp_hdr_len = (tcp_hdr.doff() as usize) * 4;
    let payload_offset = 14 + 20 + tcp_hdr_len;

    let mut found = false;
    for i in 0..128 {
        let current_offset = payload_offset + i;
        if data + current_offset + 6 > data_end {
            break;
        }

        let chunk_ptr = (data + current_offset) as *const [u8; 6];
        let mut chunk = unsafe { chunk_ptr.read_unaligned() };

        for j in 0..6 {
            chunk[j] |= 0x20; // Case insensitive
        }

        if &chunk == b"select" || &chunk == b"union " {
            found = true;
            break;
        }
    }

    let record = if let Some(ptr) = REPUTATION_MAP.get_ptr_mut(&src_addr) {
        unsafe { &mut *ptr }
    } else {
        let new_r = ReputationRecord { balance: 100, ban_until: 0 };
        let _ = REPUTATION_MAP.insert(&src_addr, &new_r, 0);
        if let Some(ptr) = REPUTATION_MAP.get_ptr_mut(&src_addr) {
            unsafe { &mut *ptr }
        } else {
            return xdp_action::XDP_PASS;
        }
    };

    let now = unsafe { bpf_ktime_get_ns() };

    if now < record.ban_until {
        return xdp_action::XDP_DROP;
    }

    if found || record.balance == 0 {
        record.ban_until = now + 60_000_000_000;
        return xdp_action::XDP_DROP;
    }

    record.balance -= 1;

    xdp_action::XDP_PASS
}
