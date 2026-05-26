#![no_std]
#![no_main]

use network_types::tcp::TcpHdr;
use network_types::ip::IpProto;
use aincrad_common::ReputationRecord;
use network_types::eth::EthHdr;
use network_types::ip::Ipv4Hdr;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use network_types::eth::EtherType;

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
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    let eth_size = core::mem::size_of::<EthHdr>();

    if unsafe { data.add(eth_size) } > data_end {
        return xdp_action::XDP_PASS;
    }

    let eth = unsafe { &*(data as *const EthHdr) };
    let ether_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(eth.ether_type)) };

    if ether_type == EtherType::Ipv4 {
        let ip_size = core::mem::size_of::<Ipv4Hdr>();
        if unsafe { data.add(eth_size + ip_size) } <= data_end {
            let ip = unsafe { &*((data as *const u8).add(eth_size) as *const Ipv4Hdr) };
            
            // Leitura segura do IP
            let src_addr = u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(ip.src_addr)) });
           
            let my_safe_ip: u32 = 0xC0A80164; 

            if src_addr == my_safe_ip {
            return xdp_action::XDP_PASS;
}

    let packet_len = (data_end as usize - data as usize) as u32;
    if packet_len < 64 {
    if let Some(ptr) = REPUTATION_MAP.get_ptr_mut(&src_addr) {
        let record = unsafe { &mut *ptr };
        record.balance = 0;
        record.ban_until = unsafe { bpf_ktime_get_ns() } + 3_600_000_000_000;
    }
    return xdp_action::XDP_DROP;
}

    if ip.proto != IpProto::Tcp {
    return xdp_action::XDP_DROP;
}

    let tcp_size = 20; 
    if (data as usize + eth_size + ip_size + tcp_size) > data_end as usize {
    return xdp_action::XDP_DROP; // Pacote malformado (TCP header truncado)
}

    let tcp = unsafe { &*((data as *const u8).add(eth_size + ip_size) as *const TcpHdr) };

    if u16::from_be(tcp.dest) != 8080 {
        return xdp_action::XDP_DROP;
}

    let payload_offset = eth_size + ip_size + tcp_size;
    let payload = unsafe { (data as *const u8).add(payload_offset) };

    if (payload as usize + 6) <= data_end as usize {
    let chunk = unsafe { *(payload as *const [u8; 6]) };
    
    if &chunk == b"SELECT" || &chunk == b"UNION " {
        return xdp_action::XDP_DROP;
    }
}

    let payload_offset = eth_size + ip_size + tcp_size;
    let payload = unsafe { (data as *const u8).add(payload_offset) };

    const SCAN_LIMIT: usize = 128; // Limite fixo para o Verifier eBPF
    let mut found = false;
    let mut i: usize = 0;

    while i < (SCAN_LIMIT - 6) {
    if (payload as usize + i + 6) > data_end as usize {
        break;
    }

    let p = unsafe { payload.add(i) as *const [u8; 6] };
    let mut chunk = unsafe { *p };

    for j in 0..6 {
        chunk[j] |= 0x20;
    }

    if chunk == *b"select" || chunk == *b"union " {
        found = true;
        break;
    }

    i += 1;
}

            let now = unsafe { bpf_ktime_get_ns() };

    let record_ptr = REPUTATION_MAP.get_ptr_mut(&src_addr);
    let record = match record_ptr {
    Some(ptr) => unsafe { &mut *ptr }, 
    None => {
        let new_r = ReputationRecord { balance: 100, ban_until: 0 };
        let _ = REPUTATION_MAP.insert(&src_addr, &new_r, 0);
        match REPUTATION_MAP.get_ptr_mut(&src_addr) {
            Some(ptr) => unsafe { &mut *ptr },
            None => return xdp_action::XDP_PASS, 
        }
    }
};

            if now < record.ban_until {
                return xdp_action::XDP_DROP;
            }

            if record.balance > 0 {
                record.balance -= 1;
            } else {
                record.ban_until = now + 60_000_000_000;
                return xdp_action::XDP_DROP;
            }
        }
    }

    xdp_action::XDP_PASS
}
