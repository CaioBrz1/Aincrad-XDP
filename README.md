![Rust](https://img.shields.io/badge/rust-nightly-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-active-green)

> <small>This project is built on the shoulders of giants. Special thanks to the aya-rs community for the revolutionary framework that makes it possible to write high-performance eBPF in Rust.</small>

#### Status:  Under Active Development

##  Dev Log: Architectural Vanguard

<small>

> *"Sometimes, you have to take one step back in development to take two steps forward in architecture."*

Aincrad-XDP is currently at a critical transition point. To ensure this project remains the firewall reference it is, I am working intensely on the migration to **Aya 0.13.2**.

This is not merely a dependency update; it is a fine-tuning of the system's core structure. I am resolving technical debt and refining abstractions to ensure that our security remains impenetrable.

**Status:** Actively in development. Commits will resume once the new foundation is 100% calibrated.

</small>


   ## Benchmarking: Currently establishing the baseline environment (using pktgen). Metrics and optimization reports coming soon.

We are currently establishing performance baselines using pktgen and iperf3. Preliminary results will be published here soon. Our goal is to demonstrate Aincrad-XDP's capacity to filter 10Gbps+ traffic with minimal CPU utilization.

# Aincrad-XDP

### High-performance firewall based on XDP (eBPF), completely rewritten in Rust using the Aya framework.
 # About the Project

### Aincrad-XDP is a kernel-level firewall designed to process packets at the fastest networking layer (XDP - Express Data Path). We migrated from an initial prototype (Python/C) to a robust and secure architecture in Rust, ensuring native performance and memory safety.

## Defensive Pipeline: The Aincrad Shield

 Aincrad-XDP employs a "Fail-Fast" layered processing pipeline. Before a packet is allowed to touch your application or service, it must survive four stages of high-speed inspection within the kernel. By dropping malicious traffic at the XDP layer, we prevent CPU exhaustion and resource abuse before it enters the networking stack.

### 1. Tiny Packet Filter (Anti-Scraping/Empty Traffic)

 We immediately discard packets smaller than 64 bytes, filtering out malformed traffic and common "low-effort" network scans that attempt to probe for open ports without legitimate payloads.

### 2. Protocol & Port Enforcement

We enforce strict traffic rules at the L4 level.

   TCP Protocol Enforcement: Only TCP traffic is permitted.

   Port Binding: We enforce strict destination port checks (e.g., port 8080). Any traffic targeting unauthorized ports is dropped immediately, preventing lateral movement and reconnaissance.

### 3. Deep Packet Inspection (DPI) - SQLi Protection

To defend against injection attacks, we implement a high-performance Sliding Window Scanner.

 Case-Insensitive Signature Matching: We scan the first 128 bytes of the payload for signatures like SELECT or UNION using bitwise normalization ($|= 0x20$), catching obfuscated attempts without the performance overhead of Regex.Kernel-Safe: This is implemented as a bounded loop that ensures predictable CPU cycles, satisfying the eBPF verifier while maintaining speed.

### 4. Rate Limiting (Token Bucket)

After the packet is verified as "clean" and "authorized", we apply a Token Bucket algorithm.

Each IP is tracked for its consumption rate.

 If a source exceeds its allocated "balance", it is temporarily banned, protecting the backend from volumetric DDoS and brute-force attempts.


## Why Rust and Aya?

 We chose Rust and the Aya framework for Aincrad-XDP because modern network infrastructure demands a balance between absolute performance and extreme memory safety.

### 1. Safety at the Kernel Level
 Unlike C, which is prone to memory leaks and buffer overflows, **Rust's borrow checker** guarantees memory safety at compile-time. By using Rust for our eBPF programs, we eliminate entire classes of bugs that could otherwise crash the kernel or create security vulnerabilities in the packet processing pipeline.

### 2. Zero-Cost Abstractions
 Aya provides a idiomatic Rust interface to eBPF without the overhead of traditional C-based toolchains like `bcc` or `libbpf`. This allows us to write high-level, maintainable code that compiles down to highly optimized BPF bytecode, ensuring we stay within the strict instruction limits of the eBPF verifier.

### 3. The "Orphan Rule" and Performance
 Working with Aya requires deep understanding of memory layout and trait implementation (such as `Pod`). By utilizing the **Newtype Pattern** and explicit memory management (`#[repr(C)]`), we explicitly control how data is passed between the kernel and user space. This ensures that our firewall operates with the minimum possible latency, effectively bypassing the overhead found in user-space packet filtering solutions.

### 4. Modern Tooling
 By leveraging `cargo`, `build-std=core`, and the `nightly` toolchain, we gain access to a modern development experience—including robust dependency management and unit testing—that is historically absent from traditional kernel-level development.

### Notes from the Trenches: The Price of Safety

 Aincrad-XDP was built with Rust and Aya to achieve the pinnacle of memory safety and performance. However, this comes with a cost: the eBPF Verifier is a relentless gatekeeper. Unlike user-space development, kernel-level programming in Rust requires a paradigm shift. Navigating ownership, scope, and strict memory bounds while satisfying the Verifier’s constraints was the most challenging part of this project. It is a rigorous process, but the resulting "Fortress" of code is exactly what makes Aincrad-XDP both unbreakable and efficient.

### Debugging & Observability

As we operate within the Kernel, we do not have access to standard println! macros.

   Logging: We utilize the aya-log crate to stream logs from the kernel to user-space.

   Map Inspection: Aincrad exports its internal state (packet counters, ban tables) via eBPF Maps. You can inspect the firewall status in real-time using tools such as bpftool:
    

    sudo bpftool map show

### Known Limitations

Like any advanced eBPF project, we are subject to the constraints of the eBPF Verifier:

   Bounded Loops: All loops must have fixed bounds to prevent deadlocks within the Kernel.

   Memory Access Verification: Any pointer access outside defined memory limits will result in program load failure.

### Contributing

Contributions are welcome! If you wish to optimize the packet parser or add new security protocols:

Fork the repository.

 Create a feature branch (git checkout -b feature/name-of-feature).

  Run the tests (cargo test).

   Submit a Pull Request.

### Security Disclaimer

This is an experimental firewall. Although Aincrad-XDP leverages Rust's memory safety, use in production environments without independent code auditing is not recommended. Use at your own risk.


# Technologies

####    Language: Rust (Edition 2024)

 ####    eBPF Framework: Aya

  ####    Infrastructure: XDP (eBPF)

   ####    Dependency Manager: Cargo

## The Aincrad Architecture: A "Modding" Approach

To ensure extreme performance, we structured Aincrad-XDP like a custom game engine:

* **`aincrad-common` (The Registry/Vanilla):** Contains the shared data structures and protocols. This is the "Vanilla" base that both the Kernel and User-Space must agree upon to communicate without corruption.
* **`aincrad-ebpf` (The Mod):** This is the high-performance logic running directly in the Kernel. It’s where the "hot" network packet processing happens, applying rules to keep the server clean.
* **`aincrad` (The ModLoader):** Our user-space controller. It loads the eBPF programs, manages the maps, and orchestrates the state. Just like a modloader, it bridges the raw "game" (Kernel) with the user interface and configuration management.

This modularity allows us to keep the "Vanilla" (common) stable while we "mod" (optimize and extend) our network processing capabilities in real-time.

📂 Repository Structure

    /aincrad: eBPF Loader in Rust (User Space).

    /aincrad-ebpf: Firewall code that runs inside the Kernel (Kernel Space).

    /legacy: Original prototypes in Python and C (for historical reference).

 # Prerequisites

### Ensure you have the following installed:

- Rust Nightly: `rustup toolchain install nightly`
- Add bpf target: `rustup target add bpfel-unknown-none`
- Rust Source: `rustup component add rust-src`

### How to Build and Run

   ### Build the Kernel (eBPF):
    Bash
```
    cargo +nightly build -p aincrad-ebpf --target bpfel-unknown-none -Z build-std=core --release
```

2. **Build the Loader (User Space):**
   ```bash
   cargo build -p aincrad --release
```
```
   # Execution:
```
sudo ./target/release/aincrad
```

## 📜 License
Distributed under the MIT License. See `LICENSE` for more details.
