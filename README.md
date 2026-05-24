<<<<<<< HEAD
# Systems Engineer | Performance Architect
=======
#  Aincrad-XDP
>>>>>>> 3503a216bbc59346eaa5153c90c49ee4e455835e

"Perfection first; your name second; your reputation third."

I am a systems engineer focused on low-level development, with a deep obsession for optimization, the Linux Kernel, and high-performance architectures. My work philosophy is rooted in precision and longevity—code must be robust, clean, and, above all, fast.

###  Current Focus
- **Low-Level Systems:** Rust & C.
- **Networking:** eBPF & XDP (Kernel-space packet processing).
- **Tooling:** Arch Linux, Hyprland & infrastructure automation.
- **Creative Tech:** FL Studio (Professional Audio Engineering).

### 🏆 Featured Projects
- **[Aincrad-XDP](https://github.com/CaioBrz1/Aincrad-XDP)**: Experimental firewall in XDP/eBPF for the Linux Kernel. Focused on Zero-Copy packet processing and driver-layer attack mitigation.

###  Technical Arsenal
*   **Languages:** C, Rust, Python (System Automation).
*   **Tools:** eBPF (BCC/libbpf), GDB, Git, Systemd.
*   **OS:** Arch Linux (Custom Hyprland environment).
*   **Hardware/Embedded:** Exploration of Single-Board Computers & ARM architecture.

###  Work Philosophy
I do not seek the fastest solution for the client; I seek the most correct solution for the system. I believe that technical excellence is the only form of marketing that truly sustains an engineer's reputation in the long run.

---
<<<<<<< HEAD
*Looking for someone to solve a bottleneck that no one else can understand? Let’s talk.*
=======

##  Architecture

The system is divided into two main layers:

* **Kernel-Space (`aincrad_xdp.bpf.c`):** Injected directly into the network driver. It performs ultra-fast lookups in a high-speed `BPF_PERCPU_HASH` map. If a source IP is blacklisted, the packet is pulverized instantly (`XDP_DROP`) without consuming CPU cycles for payload processing.
* **User-Space (`aincrad_monitor.py`):** A Python agent using the BCC library that listens to the kernel, captures drop events, and logs real-time alerts.

## ⚠️⚠️ Prerequisites

To build and run the BPF programs, you need the following development tools installed. 

**For Arch Linux:**

sudo pacman -S bcc clang llvm linux-headers python-bcc

## Ensure you have the required development tools installed (Arch Linux):
```
sudo pacman -S bcc clang llvm linux-headers python-bcc
```
## ⚙️ Systemd Integration

To ensure Aincrad-XDP starts automatically on boot:

  ###  Create the service file:
```
sudo nano /etc/systemd/system/aincrad-xdp.service
```
  #  Paste the following configuration (Replace YOUR_USERNAME with your actual Linux username):
  ```
Ini, TOML

[Unit]
Description=Aincrad eBPF/XDP Firewall Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/YOUR_USERNAME/Aincrad-XDP
ExecStart=/usr/bin/python3 /home/YOUR_USERNAME/Aincrad-XDP/aincrad_monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

   # Manage the service:

```
   # Reload: sudo systemctl daemon-reload

   # Enable: sudo systemctl enable --now aincrad-xdp.service

   # Status: sudo systemctl status aincrad-xdp.service

   # Logs: sudo journalctl -u aincrad-xdp.service -f
```
  ###  ⚠️⚠️⚠️ Disclaimer
   # This tool runs in Kernel-Space. Improper configuration or bugs in BPF programs can lead to kernel instability or system crashes (Kernel Panic). Use with caution and test in non-critical environments first.

📄 License

MIT License
>>>>>>> 3503a216bbc59346eaa5153c90c49ee4e455835e
