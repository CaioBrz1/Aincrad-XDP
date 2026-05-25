use aya::Bpf;

fn main() -> Result<(), anyhow::Error> {
    // Binário eBPF compilado
    let mut bpf = Bpf::load(aya::include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aincrad-ebpf"))?;
    
    Ok(())
}
