# Aincrad-XDP

Aincrad-XDP é um firewall experimental de alto desempenho desenvolvido em eBPF (Extended Berkeley Packet Filter) e XDP (eXpress Data Path) para o Kernel do Linux. O projeto implementa um sistema de DPI (Deep Packet Inspection) na camada de driver de rede para mitigar ataques UDP maliciosos baseados em assinatura, integrando uma camada de monitoramento em tempo real via Python (BCC).

## Arquitetura do Sistema

O projeto é dividido em duas camadas principais:

* **Kernel-Space (aincrad_xdp.bpf.c):** Injetado diretamente no driver de rede (ou camada SKB). Faz uma checagem ultra-rápida em um mapa de estado de alta velocidade (`BPF_MAP_TYPE_HASH`). Se o IP de origem já estiver na **Blacklist**, o pacote é pulverizado instantaneamente (`XDP_DROP`) sem consumir CPU processando o payload. Caso contrário, o motor inspeciona o payload através de um scanner dinâmico com laço seguro (*Bounded Loop*) contra evasão por espaços. Se a assinatura mágica `AINC` for detectada, o IP é banido por 60 segundos e o evento é enviado para o espaço de usuário (`BPF_PERF_OUTPUT`).
* **User-Space (aincrad_monitor.py):** Agente em Python utilizando a biblioteca BCC que escuta a memória RAM do Kernel, captura os eventos de drop e exibe alertas formatados da Blacklist em tempo real no terminal.


## Como Rodar em Segundo Plano (Systemd)

Para que o escudo de Aincrad seja iniciado automaticamente junto com o Arch Linux e rode em segundo plano, você pode transformá-lo em um serviço do sistema.

### 1. Criar o arquivo de serviço
Crie o arquivo de configuração com o comando:
```bash
sudo nano /etc/systemd/system/aincrad-xdp.service

[Unit]
Description=Aincrad eBPF/XDP Firewall Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/SEU_USUARIO/Aincrad-XDP
ExecStart=/usr/bin/python3 /home/SEU_USUARIO/Aincrad-XDP/aincrad_monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target

Comandos de Gerenciamento

Sempre que precisar mexer no escudo, utilize os comandos abaixo de qualquer lugar do terminal:

    Atualizar o sistema após criar/editar o arquivo:
sudo systemctl daemon-reload

    Ativar para ligar junto com o PC:
sudo systemctl enable aincrad-xdp.service

    Ligar o escudo agora:
sudo systemctl start aincrad-xdp.service

    Ver se ele está rodando (Status):
sudo systemctl status aincrad-xdp.service

    Desligar o escudo:
 sudo systemctl stop aincrad-xdp.service


Como ver em tempo real os alertas?
sudo journalctl -u aincrad-xdp.service -f


