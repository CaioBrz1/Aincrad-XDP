use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::HashMap;
use std::time::Duration;
use tokio::{time, signal};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    
    let bpf_bytes = aya::include_bytes_aligned!("../../target/bpfel-unknown-none/release/aincrad-ebpf");
    let mut bpf = Bpf::load(bpf_bytes)?;

    let program: &mut Xdp = bpf.program_mut("aincrad_xdp")
        .ok_or_else(|| anyhow::anyhow!("Programa XDP não encontrado"))?
        .try_into()?;
    
    program.load()?;
    program.attach("enp3s0", XdpFlags::default())?;

    let map_data = bpf.map("PACKET_COUNT")
        .ok_or_else(|| anyhow::anyhow!("Mapa PACKET_COUNT não encontrado"))?;
    
    let packet_count: HashMap<_, u32, u64> = HashMap::try_from(map_data)?;

    println!("FIREWALL AINCRAD LIGADO! Monitorando...");

    let mut interval = time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let key = 0u32;
                if let Ok(count) = packet_count.get(&key, 0) {
                    println!("Pacotes processados: {}", count);
                }
            }
            _ = signal::ctrl_c() => {
                println!("\nDesligando Aincrad...");
                break;
            }
        }
    }
    Ok(())
}

