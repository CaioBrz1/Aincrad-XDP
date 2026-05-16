#!/usr/bin/env python3
from bcc import BPF
import ctypes
import socket

# 1. O MOTOR EM C (Injetado direto no Kernel)
# Repare que agora usamos o formato do BCC, que facilita nossa vida com ponteiros!
ebpf_code = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// Estrutura que vai carregar os dados do Kernel para o Python
struct event_t {
    __u32 src_ip;
    __u32 pkt_len;
};

// Cria o duto de telemetria chamado "events"
BPF_PERF_OUTPUT(events);

int aincrad_monitor(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Como estamos testando local, vamos alinhar direto para o IP (Modo Genérico/SKB)
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == 17) { // UDP
        __u32 ip_hlen = iph->ihl * 4;
        struct udphdr *udph = (void *)iph + ip_hlen;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;

        char *payload = (char *)(udph + 1);
        if ((void *)(payload + 4) > data_end)
            return XDP_PASS;

        // Caça a nossa assinatura "AINC"
        if (payload[0] == 'A' && payload[1] == 'I' && payload[2] == 'N' && payload[3] == 'C') {
            
            // Prepara o evento para enviar pro Python
            struct event_t event = {};
            event.src_ip = iph->saddr;
            event.pkt_len = ctx->data_end - ctx->data;

            // Envia os dados pelo duto de alta velocidade
            events.perf_submit(ctx, &event, sizeof(event));

            return XDP_DROP; // Pulveriza o ataque
        }
    }
    return XDP_PASS;
}
"""

# 2. O COMPILADOR E INJETOR ATÔMICO (Espaço de Usuário)
interface = "enp3s0" # COLOQUE A SUA INTERFACE AQUI (ex: enp3s0, wlan0)

print(f"⚔️ [Aincrad] Compilando código eBPF e injetando na interface {interface}...")
b = BPF(text=ebpf_code)
fn = b.load_func("aincrad_monitor", BPF.XDP)

# Injeta no modo genérico (flags=BPF.XDP_FLAGS_SKB_MODE) para funcionar em qualquer placa
b.attach_xdp(interface, fn, flags=BPF.XDP_FLAGS_SKB_MODE)

# 3. O INTERPRETADOR DE DADOS (Python puro)
# Define a estrutura idêntica em Python para ler os bytes do C
class EventData(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("pkt_len", ctypes.c_uint32)
    ]

# Função de callback executada toda vez que um pacote for dropado
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    # Converte o IP em formato numérico do Kernel para string legível (ex: 192.168.1.1)
    ip_str = socket.inet_ntoa(ctypes.c_uint32(event.src_ip).value.to_bytes(4, 'little'))
    
    print(f"🚨 [DETECÇÃO] Ataque Mitigado! | Origem: {ip_str} | Tamanho do Pacote: {event.pkt_len} bytes")

# Conecta a função de callback ao duto "events"
b["events"].open_perf_buffer(print_event)

print("🏰 [Aincrad] Escudo ativo e monitorando a rede! Pressione Ctrl+C para desligar.")

# Loop infinito escutando a memória RAM do Kernel
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\\n🔓 [Aincrad] Desativando escudo e limpando a interface. Até a próxima!")
    b.remove_xdp(interface, flags=BPF.XDP_FLAGS_SKB_MODE)
