# Aincrad-XDP

### High-performance firewall based on XDP (eBPF), completely rewritten in Rust using the Aya framework.
 # About the Project

### Aincrad-XDP is a kernel-level firewall designed to process packets at the fastest networking layer (XDP - Express Data Path). We migrated from an initial prototype (Python/C) to a robust and secure architecture in Rust, ensuring native performance and memory safety.
# Technologies

####    Language: Rust (Edition 2024)

 ####    eBPF Framework: Aya

  ####    Infrastructure: XDP (eBPF)

   ####    Dependency Manager: Cargo

📂 Repository Structure

    /aincrad: eBPF Loader in Rust (User Space).

    /aincrad-ebpf: Firewall code that runs inside the Kernel (Kernel Space).

    /legacy: Original prototypes in Python and C (for historical reference).

 # Prerequisites

### Ensure you have the following installed:

    Rust (Nightly, as Aya uses experimental features): rustup toolchain install nightly

    bpfel-unknown-none target: rustup target add bpfel-unknown-none

    cargo-generate and the necessary Aya dependencies.

### How to Build and Run

   ### Build the Kernel (eBPF):
    Bash
```
    cargo +nightly build -p aincrad-ebpf --target bpfel-unknown-none -Z build-std=core
```

2. **Build the Loader (User Space):**
   ```bash
   cargo build -p aincrad
```
```
   # Execution:
```
sudo ./target/debug/aincrad
```

## 📜 License
Distributed under the MIT License. See `LICENSE` for more details.
