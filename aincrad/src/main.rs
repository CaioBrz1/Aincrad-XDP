use aincrad_common::ReputationRecord;
use aya::Bpf;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use std::time::Duration;
use tokio::{signal, time};

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodReputation(ReputationRecord);

unsafe impl aya::Pod for PodReputation {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let bpf_bytes =
        aya::include_bytes_aligned!("../../target/bpfel-unknown-none/release/aincrad-ebpf");

    let mut bpf = Bpf::load(bpf_bytes)?;

    for (name, _) in bpf.programs() {
        println!("Programa encontrado no binário: {}", name);
    }

    let program: &mut Xdp = bpf
        .program_mut("aincrad_xdp")
        .ok_or_else(|| anyhow::anyhow!("Programa XDP não encontrado"))?
        .try_into()?;

    program.load()?;
    program.attach("enp3s0", XdpFlags::default())?;

    let map_data = bpf
        .map("REPUTATION_MAP")
        .ok_or_else(|| anyhow::anyhow!("Mapa REPUTATION_MAP não encontrado"))?;

    let reputation_map: HashMap<_, u32, PodReputation> = HashMap::try_from(map_data)?;

    println!("FIREWALL AINCRAD LIGADO! Monitorando...");

    let mut interval = time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
        _ = interval.tick() => {
            let mut banned_count = 0;
            let mut total_records = 0;
            for entry in reputation_map.iter() {
                if let Ok((_, pod_wrapper)) = entry {
                    total_records += 1;
                    if pod_wrapper.0.ban_until > 0 {
                        banned_count += 1;
                    }
                }
            }

            println!("--- Status Aincrad | IPs Monitorados: {} | Bloqueados Agora: {} ---", total_records, banned_count);
        }

                    _ = signal::ctrl_c() => {
                        println!("\nDesligando Aincrad...");
                        break;
                    }
                }
    }

    Ok(())
}
