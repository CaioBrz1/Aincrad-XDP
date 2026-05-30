use aya::maps::{PerCpuHashMap, MapData};
use aya::programs::{Xdp, XdpMode};
use aya::programs::xdp::XdpLinkId;
use aya::Ebpf;
use std::convert::TryInto;
use tokio::{signal, time, time::Duration};

#[derive(Debug, Clone, Copy)]
pub struct ReputationRecord {
    pub ban_until: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let (reputation_map, _link) = init_ebpf()?;

    println!("FIREWALL AINCRAD LIGADO! Monitorando...");

    let mut interval = time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut banned_count = 0;
                let mut total_records = 0;

                for entry in reputation_map.iter() {
                    if let Ok((_key, records)) = entry {
                        total_records += 1;
                        
                        let ban_until = records
                            .iter()
                            .map(|raw_bytes| {

                                let record = bytes_to_record(raw_bytes);
                                record.ban_until
                            })
                            .max()
                            .unwrap_or(0);

                        if ban_until > 0 {
                            banned_count += 1;
                        }
                    }
                }

                println!("--- Status Aincrad | IPs: {} | Bloqueados: {} ---", total_records, banned_count);
            }
            _ = signal::ctrl_c() => { break; }
        }
    }
    Ok(())
}

fn bytes_to_record(bytes: &[u8; 24]) -> ReputationRecord {
    let ban_until = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
    
    ReputationRecord { ban_until }
}

fn init_ebpf() -> Result<(PerCpuHashMap<MapData, u32, [u8; 24]>, XdpLinkId), anyhow::Error> {

let mut bpf = Ebpf::load(aya::include_bytes_aligned!(
    "../../target/bpfel-unknown-none/release/libaincrad_ebpf.so"
))?;

    let program: &mut Xdp = bpf
        .program_mut("aincrad_xdp")
        .ok_or_else(|| anyhow::anyhow!("Programa não encontrado"))?
        .try_into()?;
    
    program.load()?;

let link = program.attach("enp3s0", XdpMode::default())?;

    let map = bpf.take_map("REPUTATION_MAP")
        .ok_or_else(|| anyhow::anyhow!("Mapa não encontrado"))?;

    let reputation_map = PerCpuHashMap::try_from(map)?;

    Ok((reputation_map,link))
}
