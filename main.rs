use aya::Bpf;

fn main() -> Result<(), anyhow::Error> {
    // Carrega o binário eBPF compilado
    let mut bpf = Bpf::load(aya::include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aincrad-ebpf"))?;
    
    // Aqui entra o seu ModLoader que discutimos
    // ... loop de mods ...
    Ok(())
}
