#  Aincrad-XDP

Aincrad-XDP is a high-performance experimental firewall developed using **eBPF** (Extended Berkeley Packet Filter) and **XDP** (eXpress Data Path) for the Linux Kernel. 

The project implements **Deep Packet Inspection (DPI)** at the network driver layer to mitigate malicious UDP attacks based on signatures, integrating a real-time monitoring layer via Python (BCC).

---

##  Architecture

The system is divided into two main layers:

* **Kernel-Space (`aincrad_xdp.bpf.c`):** Injected directly into the network driver. It performs ultra-fast lookups in a high-speed `BPF_PERCPU_HASH` map. If a source IP is blacklisted, the packet is pulverized instantly (`XDP_DROP`) without consuming CPU cycles for payload processing.
* **User-Space (`aincrad_monitor.py`):** A Python agent using the BCC library that listens to the kernel, captures drop events, and logs real-time alerts.

##  Prerequisites

Ensure you have the required development tools installed (Arch Linux):

```bash
sudo pacman -S bcc clang llvm linux-headers python-bcc

⚙️ Systemd Integration

To ensure Aincrad-XDP starts automatically on boot:

    Create the service file:

Bash

sudo nano /etc/systemd/system/aincrad-xdp.service

    Paste the following configuration (Replace YOUR_USERNAME with your actual Linux username):

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

    Manage the service:

    Reload: sudo systemctl daemon-reload

    Enable: sudo systemctl enable --now aincrad-xdp.service

    Status: sudo systemctl status aincrad-xdp.service

    Logs: sudo journalctl -u aincrad-xdp.service -f

    ⚠️ Disclaimer
    This tool runs in Kernel-Space. Improper configuration or bugs in BPF programs can lead to kernel instability or system crashes (Kernel Panic). Use with caution and test in non-critical environments first.

📄 License

MIT License
