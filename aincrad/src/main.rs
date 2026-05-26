use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::HashMap;
use std::time::Duration;
use tokio::{time, signal};
use aincrad_common::ReputationRecord; 

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodReputation(ReputationRecord);

unsafe impl aya::Pod for PodReputation {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let bpf_bytes = aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/aincrad-ebpf"
    );

    let mut bpf = Bpf::load(bpf_bytes)?;

    for (name, _) in bpf.programs() {
        println!("Programa encontrado no binário: {}", name);
    }

    let program: &mut Xdp = bpf.program_mut("aincrad_xdp")
        .ok_or_else(|| anyhow::anyhow!("Programa XDP não encontrado"))?
        .try_into()?;

    program.load()?;
    program.attach("enp3s0", XdpFlags::default())?;

    let map_data = bpf.map("REPUTATION_MAP")
        .ok_or_else(|| anyhow::anyhow!("Mapa REPUTATION_MAP não encontrado"))?;

    let reputation_map: HashMap<_, u32, PodReputation> = HashMap::try_from(map_data)?;

    println!("FIREWALL AINCRAD LIGADO! Monitorando...");

let mut interval = time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                println!("--- Status da Tabela de Reputação ---");
                for entry in reputation_map.iter() {
                    match entry {
                        Ok((key, pod_wrapper)) => {
                            let record = pod_wrapper.0;
                            println!("IP/Key: {:?}, Balance: {}, Ban: {}", 
                                     key, record.balance, record.ban_until);
                        }
                        Err(e) => eprintln!("Erro ao ler entrada do mapa: {}", e),
                    }
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
