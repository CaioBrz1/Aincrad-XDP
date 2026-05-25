use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::HashMap;
use std::convert::TryFrom;
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
<<<<<<< HEAD
    let bpf_bytes = aya::include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aincrad-ebpf");
=======
    // 1. Load bytes
    let bpf_bytes = aya::include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aincrad-ebpf");
    
    // 2. BPF
>>>>>>> 1052fd456e4db443fbbf2dedf5bb1ea93bea65b8
    let mut bpf = Bpf::load(bpf_bytes)?;

    let packet_count = HashMap::try_from(bpf.map("PACKET_COUNT")?)?;
    
<<<<<<< HEAD
    let program: &mut Xdp = bpf.program_mut("aincrad_xdp")?.try_into()?;
=======
    let program: &mut Xdp = bpf.program_mut("aincrad_xdp")
        .ok_or_else(|| anyhow::anyhow!("Programa XDP não encontrado"))?
        .try_into()?;
        
>>>>>>> 1052fd456e4db443fbbf2dedf5bb1ea93bea65b8
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
