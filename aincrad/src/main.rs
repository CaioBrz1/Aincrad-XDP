use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // 1. Carrega os bytes
    let bpf_bytes = aya::include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aincrad-ebpf");
    
    // 2. Carrega o BPF
    let mut bpf = Bpf::load(bpf_bytes)?;
    
    // 3. Pega o programa e anexa
    let program: &mut Xdp = bpf.program_mut("aincrad_xdp")
        .ok_or_else(|| anyhow::anyhow!("Programa XDP não encontrado"))?
        .try_into()?;
        
    program.load()?;
    program.attach("enp3s0", XdpFlags::default())?;

    println!("FIREWALL AINCRAD LIGADO! Filtrando pacotes na enp3s0...");
    println!("Pressione Ctrl+C para encerrar...");

    tokio::signal::ctrl_c().await?;

    Ok(())
} 
