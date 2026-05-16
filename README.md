#  Aincrad-XDP

Aincrad-XDP é um firewall experimental de alto desempenho desenvolvido em **eBPF (Extended Berkeley Packet Filter)** e **XDP (eXpress Data Path)** para o Kernel do Linux. O projeto implementa um sistema de **DPI (Deep Packet Inspection)** na camada de driver de rede para mitigar ataques UDP maliciosos baseados em assinatura, integrando uma camada de monitoramento em tempo real via Python (BCC).



##  Arquitetura do Sistema

O projeto é dividido em duas camadas principais:

1. **Kernel-Space (`aincrad_xdp.bpf.c`):** Injetado diretamente no driver de rede (ou camada SKB). Inspeciona o payload de pacotes UDP na porta `9999`. Se a assinatura mágica `AINC` for detectada, o pacote é imediatamente pulverizado com `XDP_DROP` e os metadados do ataque são enviados para um anel de memória circular (`BPF_PERF_OUTPUT`).
2. **User-Space (`aincrad_monitor.py`):** Agente em Python utilizando a biblioteca BCC que escuta a memória RAM do Kernel, captura os eventos de drop e exibe alertas formatados em tempo real.

##  Como Executar (Arch Linux)

### Pré-requisitos
Certifique-se de ter os cabeçalhos do kernel e o ecossistema BCC instalados:
```bash
sudo pacman -S bcc bcc-tools python-bcc linux-headers openbsd-netcat
