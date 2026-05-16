kkkk# Aincrad-XDP

Aincrad-XDP é um firewall experimental de alto desempenho desenvolvido em eBPF (Extended Berkeley Packet Filter) e XDP (eXpress Data Path) para o Kernel do Linux. O projeto implementa um sistema de DPI (Deep Packet Inspection) na camada de driver de rede para mitigar ataques UDP maliciosos baseados em assinatura, integrando uma camada de monitoramento em tempo real via Python (BCC).

## Arquitetura do Sistema

O projeto é dividido em duas camadas principais:

* **Kernel-Space (aincrad_xdp.bpf.c):** Injetado diretamente no driver de rede (ou camada SKB). Faz uma checagem ultra-rápida em um mapa de estado de alta velocidade (`BPF_MAP_TYPE_HASH`). Se o IP de origem já estiver na **Blacklist**, o pacote é pulverizado instantaneamente (`XDP_DROP`) sem consumir CPU processando o payload. Caso contrário, o motor inspeciona o payload através de um scanner dinâmico com laço seguro (*Bounded Loop*) contra evasão por espaços. Se a assinatura mágica `AINC` for detectada, o IP é banido por 60 segundos e o evento é enviado para o espaço de usuário (`BPF_PERF_OUTPUT`).
* **User-Space (aincrad_monitor.py):** Agente em Python utilizando a biblioteca BCC que escuta a memória RAM do Kernel, captura os eventos de drop e exibe alertas formatados da Blacklist em tempo real no terminal.
