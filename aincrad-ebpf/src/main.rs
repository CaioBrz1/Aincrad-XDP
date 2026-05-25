#![no_std]
#![no_main]

use network_types::eth::EthHdr;
use network_types::ip::Ipv4Hdr;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
pub static PACKET_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
pub static BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn aincrad_xdp(ctx: XdpContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    let eth_size = core::mem::size_of::<EthHdr>();

    if unsafe { data.add(eth_size) } > data_end {
        return xdp_action::XDP_PASS;
    }

    let eth = unsafe { &*(data as *const EthHdr) };
    let eth_type = eth.ether_type as u16;

    if eth_type == 0x0800 {
        let ip_size = core::mem::size_of::<Ipv4Hdr>();
        if unsafe { data.add(eth_size + ip_size) } <= data_end {
            let ip = unsafe { &*((data as *const u8).add(eth_size) as *const Ipv4Hdr) };
            let src_addr = u32::from_be(ip.src_addr);
            
            if unsafe { BLOCKLIST.get(&src_addr) }.is_some() {
                return xdp_action::XDP_DROP; // Ponto de saída válido
            }
        }
    }

    let key = 0u32;
    unsafe {
        if let Some(count) = PACKET_COUNT.get(&key) {
            let new_count = *count + 1;
            let _ = PACKET_COUNT.insert(&key, &new_count, 0);
        } else {
            let _ = PACKET_COUNT.insert(&key, &1u64, 0);
        }
    }

    xdp_action::XDP_PASS
}
