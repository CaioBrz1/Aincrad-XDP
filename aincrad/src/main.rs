use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::HashMap;
use std::convert::TryFrom;
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let bpf_bytes = aya::include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aincrad-ebpf");
    let mut bpf = Bpf::load(bpf_bytes)?;

    let packet_count = HashMap::try_from(bpf.map("PACKET_COUNT")?)?;
    
    let program: &mut Xdp = bpf.program_mut("aincrad_xdp")?.try_into()?;
    program.load()?;
    program.attach("enp3s0", XdpFlags::default())?;

    println!("FIREWALL AINCRAD LIGADO! Monitorando...");

    // Loop de monitoramento
    let mut interval = time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        
        let key = 0u32;
        if let Ok(count) = packet_count.get(&key, 0) {
            println!("Pacotes processados: {}", count);
        }
    }
}
