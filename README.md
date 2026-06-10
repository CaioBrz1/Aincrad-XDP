![Rust](https://img.shields.io/badge/rust-nightly-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-active-green)
[![Built with Aya](https://img.shields.io/badge/Built%20with-Aya-blue?logo=rust)](https://aya-rs.dev/)

> <small>This project is built on the shoulders of giants. Special thanks to the aya-rs community for the revolutionary framework that makes it possible to write high-performance eBPF in Rust.</small>

## Dev Log: Architectural Vanguard

<small>

> *"Sometimes, you have to take one step back in development to take two steps forward in architecture."*

Aincrad-XDP is currently at a critical transition point. To ensure this project remains the firewall reference it is, I have spent the last cycle performing a deep-system migration to **Aya 0.13.2**.

This is not merely a dependency update; it was a deliberate **reforging of the system's core**. I have been actively dismantling the technical debt accumulated from the rapid evolution of the eBPF ecosystem, refining abstractions to ensure that our security remains truly impenetrable.

### The Current State of the Forge

*   **Refactoring & Macros:** Stripped away legacy boilerplate. The new Aya 0.13.2 structures demand higher type-safety, which I’ve implemented across the board.
*   **Memory Layout (Pod & Zerocopy):** Standardized data exchange using explicit byte-arrays. Every byte is now accounted for.
*   **Kernel Residency:** The bytecode is now successfully compiled and verified by the kernel. The foundation is set.
*   **The "Attach" Phase (In Progress):** We are currently bridging the gap between loading the program and hooking it to the network interface. In the eBPF lifecycle, residency (Load) is only half the battle; activation (Attach) is where the firewall actually begins to breathe.

**Status:** Actively in development. 

The code is being calibrated. My current focus is implementing the lifecycle management of our XDP hook, ensuring that the transition from user-space to kernel-space is not just functional, but atomic and resilient.

Commits will resume at full velocity once the new foundation is 100% calibrated.

</small>


   ###### Benchmarking: Currently establishing the baseline environment (using pktgen). Metrics and optimization reports coming soon.

###### We are currently establishing performance baselines using pktgen and iperf3. Preliminary results will be published here soon. Our goal is to demonstrate Aincrad-XDP's capacity to filter 10Gbps+ traffic with minimal CPU utilization.

# Aincrad-XDP

### High-performance firewall based on XDP (eBPF), completely rewritten in Rust using the Aya framework.
 # About the Project

### Aincrad-XDP is a kernel-level firewall designed to process packets at the fastest networking layer (XDP - Express Data Path). We migrated from an initial prototype (Python/C) to a robust and secure architecture in Rust, ensuring native performance and memory safety.

## Defensive Pipeline: The Aincrad Shield

 Aincrad-XDP employs a "Fail-Fast" layered processing pipeline. Before a packet is allowed to touch your application or service, it must survive four stages of high-speed inspection within the kernel. By dropping malicious traffic at the XDP layer, we prevent CPU exhaustion and resource abuse before it enters the networking stack.

## Pipeline Details

 ###  1. Tiny Packet Filter (Anti-Scraping):

   *Status: Operational.*

  #### Logic: Discards packets < 64 bytes at the XDP hook. Effectively filters basic network scans and malformed traffic before stack allocation.

 ###   2. Protocol & Port Enforcement:

   *Status: Operational.*

 ####  Logic: Strictly enforces TCP at L4. Non-compliant traffic is dropped immediately. Port enforcement logic is currently static (hardcoded for the baseline).

### 3. Deep Packet Inspection (DPI) - SQLi Protection:
   Status: Operational.

####  Design: High-performance static window scanner with dynamic protocol parsing.
####  Technical Constraints & Optimizations:
   * Implemented via strict bounded loop (`for _ in 0..128`) to achieve full compliance with the eBPF Verifier without compromising throughput.
   * Employs bitwise normalization (`|= 0x20202020` / byte-level masking) for efficient, zero-overhead, case-insensitive signature matching (`sele`, `ping`).
   * Features Dynamic Header Parsing (extracting IPv4 IHL and TCP Data Offset) to isolate and inspect the application payload with surgical precision, ignoring variable transport-layer options.
   * Integrated with a stateful REPUTATION_MAP for immediate, low-overhead driver-level mitigation (`XDP_DROP`) of malicious actors.

  ###  4. Rate Limiting (Token Bucket):

   *Status: Operational.*

#### Design: Stateless Token Bucket algorithm utilizing Per-CPU Hash Maps to achieve lockless execution at 10Gbps+ line rates.
#### Technical Constraints & Optimizations:
* Eliminates lock contention by allocating independent bucket structures per CPU core, ensuring zero-overhead tracking under massive multi-core workloads.
* Implements fractional token regeneration using low-overhead integer mathematics via `bpf_ktime_get_ns()`, avoiding non-supported floating-point operations in eBPF.
* Short-circuits malicious/flood traffic early in the pipeline (`XDP_DROP`), preserving CPU cycles and system stability.

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


### Known Limitations

Like any advanced eBPF project, we are subject to the constraints of the eBPF Verifier:

   Bounded Loops: All loops must have fixed bounds to prevent deadlocks within the Kernel.

   Memory Access Verification: Any pointer access outside defined memory limits will result in program load failure.

### Security Disclaimer

This is an experimental firewall. Although Aincrad-XDP leverages Rust's memory safety, use in production environments without independent code auditing is not recommended. Use at your own risk.


# Technologies

####    Language: Rust (Edition 2024)

 ####    eBPF Framework: Aya 0.13.2

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
```
    cargo +nightly build -p aincrad-ebpf --target bpfel-unknown-none -Z build-std=core --release
```

2. **Build the Loader (User Space):**
   
   ```cargo build -p aincrad --release```


   # Execution:

```
sudo ./target/release/aincrad
```

##  How to Test and Verify the Firewall

Aincrad operates directly at the edge of the Linux kernel network stack using XDP (eBPF). To verify that the interception mechanism and the reputation map are working properly, follow the steps below.

### 1. Opening a Port for Testing (Target)
To simulate an active service on the machine and test incoming packets from external agents (such as a mobile device on the same network), use `netcat` to listen on port `8080`:

```
nc -lk 8080
```
 <small>
 > Note: If the firewall is active and the source IP is listed for blocking in the reputation map, packets will be dropped before they even reach this user-space process.<small> 

## 2. Verifying the Kernel Attachment (Attach)

The XDP program must be properly attached to the primary network interface (enp3s0). Run the following command while the firewall is running:

```
ip link show dev enp3s0
```

### Expected Output (XDP Active at the Edge):


`2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 00:e0:4c:ab:57:de brd ff:ff:ff:ff:ff:ff
    prog/xdp id 75 
    altname enx00e04cab57de`

   #### The xdpgeneric (or xdp) tag confirms that the network driver is under our gatekeeper's protection.

   #### The prog/xdp id [ID] identifier indicates the registered Rust bytecode compiled and running inside the Kernel.

## Runtime Logs and Demonstration

The user-space control panel monitors the reputation map (REPUTATION_MAP) in real-time, displaying the count of tracked IPs versus the number of requests actively blocked by XDP_DROP.

Below is the log from an actual test session intercepting connections on port 8080:
Plaintext:


```
--- Status Aincrad | IPs: 0 | Blocked: 0 ---
--- Status Aincrad | IPs: 2 | Blocked: 2 ---
--- Status Aincrad | IPs: 2 | Blocked: 0 ---
--- Status Aincrad | IPs: 4 | Blocked: 2 ---
--- Status Aincrad | IPs: 4 | Blocked: 2 ---
```

####    IPs: Number of unique addresses identified passing through the interface.

####    Blocked: Number of packets dropped at lightning speed directly at the network interface card (NIC) driver level.

## 📜 License
Distributed under the MIT License. See `LICENSE` for more details.
