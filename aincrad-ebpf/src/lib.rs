#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, xdp}, // Mudamos para 'xdp'
    programs::XdpContext,
    maps::PerCpuHashMap,
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReputationRecord {
    pub balance: u32,
    pub _padding: u32,
    pub ban_until: u64,
    pub last_updated: u64,
}

#[map]
pub static REPUTATION_MAP: PerCpuHashMap<u32, ReputationRecord> = 
    PerCpuHashMap::with_max_entries(1024, 0);

// A macro mais recente da Aya usa apenas #[xdp]
#[xdp] 
pub fn aincrad_xdp(ctx: XdpContext) -> u32 {
    match try_aincrad_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_aincrad_xdp(ctx: XdpContext) -> Result<u32, u32> {
    let now = unsafe { bpf_ktime_get_ns() };
    let mut found = false;
    
    let src_addr: u32 = 0; 
    let payload_offset: usize = 54; 
    let data = ctx.data();
    let data_end = ctx.data_end();

    for i in 0..128 {
        let current_offset = payload_offset + i;
        if data + current_offset + 6 > data_end {
            break;
        }
        let chunk_ptr = (data + current_offset) as *const [u8; 6];
        let mut chunk = unsafe { chunk_ptr.read_unaligned() };

        for j in 0..6 {
            chunk[j] |= 0x20;
        }

        if &chunk == b"select" || &chunk == b"union " {
            found = true;
            break;
        }
    }

    let mut record = unsafe {
        match REPUTATION_MAP.get(&src_addr) {
            Some(existing_record) => *existing_record,
            None => ReputationRecord {
                balance: 100,
                _padding: 0,
                ban_until: 0,
                last_updated: now,
            },
        }
    };

    if now < record.ban_until {
        return Ok(xdp_action::XDP_DROP);
    }

    if found || record.balance == 0 {
        record.ban_until = now + 60_000_000_000;
        let _ = REPUTATION_MAP.insert(&src_addr, &record, 0);
        return Ok(xdp_action::XDP_DROP);
    }

    record.balance -= 1;
    let _ = REPUTATION_MAP.insert(&src_addr, &record, 0);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
