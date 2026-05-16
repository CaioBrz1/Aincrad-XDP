#!/usr/bin/env python3
from bcc import BPF
import ctypes
import socket
import time

# O MOTOR EM C - NÍVEL DE PRODUÇÃO
ebpf_code = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_PAYLOAD_SCAN 16  // Varre os primeiros 16 bytes do payload para evitar evasão
#define BLACKLIST_TIMEOUT_NS 60000000000ULL // 60 segundos de bloqueio (em nanosegundos)

// Estrutura para os eventos enviados ao Python
struct event_t {
    __u32 src_ip;
    __u32 pkt_len;
    __u32 reason; // 1 = Flag flagrada no Scanner, 2 = Já estava na Blacklist
};

// TABELA 1: Mapa Hash da Blacklist (Chave: IP do atacante, Valor: Timestamp do último ataque)
BPF_HASH(blacklist, __u32, __u64, 1024);

// TABELA 2: Duto de Telemetria para o Python
BPF_PERF_OUTPUT(events);

int aincrad_production(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Alinhamento direto para o IP (Modo Genérico/SKB)
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 now = bpf_ktime_get_ns();

    // 🛡️ FILTRO 1: Verificação Ultra-Rápida da Blacklist
    __u64 *last_attack = blacklist.lookup(&src_ip);
    if (last_attack) {
        // Verifica se o castigo de 60 segundos já expirou
        if (now - *last_attack < BLACKLIST_TIMEOUT_NS) {
            // IP criminoso detectado! Drop imediato sem processar nada
            struct event_t event = {};
            event.src_ip = src_ip;
            event.pkt_len = ctx->data_end - ctx->data;
            event.reason = 2;
            events.perf_submit(ctx, &event, sizeof(event));
            return XDP_DROP;
        } else {
            // Tempo expirou, remove da lista negra para dar uma segunda chance
            blacklist.delete(&src_ip);
        }
    }

    // Filtra apenas tráfego UDP
    if (iph->protocol != 17)
        return XDP_PASS;

    __u32 ip_hlen = iph->ihl * 4;
    struct udphdr *udph = (void *)iph + ip_hlen;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    char *payload = (char *)(udph + 1);
    
    // 🔍 FILTRO 2: Scanner Robusto com Bounded Loop (Evita Evasão por Espaços)
    // Procura a assinatura "AINC" de forma contígua dentro da janela inicial
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_SCAN; i++) {
        // Garante a segurança de acesso à memória exigida pelo Verificador do Kernel
        if ((void *)(payload + i + 4) > data_end)
            break;

        if (payload[i] == 'A' && payload[i+1] == 'I' && payload[i+2] == 'N' && payload[i+3] == 'C') {
            // Ataque detectado pelo Scanner! 
            // 1. Registra/Atualiza o IP na Blacklist do Kernel com o timestamp atual
            blacklist.update(&src_ip, &now);

            // 2. Reporta o evento para o espaço de usuário
            struct event_t event = {};
            event.src_ip = src_ip;
            event.pkt_len = ctx->data_end - ctx->data;
            event.reason = 1;
            events.perf_submit(ctx, &event, sizeof(event));

            return XDP_DROP; // Pulveriza o frame
        }
    }

    return XDP_PASS;
}
"""

interface = "enp3s0" # Sua placa de rede

print(f"🛡️ [Aincrad Enterprise] Compilando motor de alta resiliência na interface {interface}...")
b = BPF(text=ebpf_code)
fn = b.load_func("aincrad_production", BPF.XDP)
b.attach_xdp(interface, fn, flags=BPF.XDP_FLAGS_SKB_MODE)

class EventData(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("pkt_len", ctypes.c_uint32),
        ("reason", ctypes.c_uint32)
    ]

# Dicionário simples para monitorar logs repetidos no Python e não travar o terminal
ultimo_print = {}

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    ip_str = socket.inet_ntoa(ctypes.c_uint32(event.src_ip).value.to_bytes(4, 'little'))
    
    agora = time.time()
    # Se o IP já está na blacklist, evita inundar o terminal do usuário (Apenas atualiza internamente)
    if event.reason == 2:
        if agora - ultimo_print.get(ip_str, 0) < 2: # Só printa lembrete a cada 2 segundos por IP
            return
    
    ultimo_print[ip_str] = agora

    if event.reason == 1:
        print(f"🚨 [SCANNER] Assinatura detectada! Origem: {ip_str} | Tamanho: {event.pkt_len} B | Ação: IP BANIDO POR 1 MINUTO")
    elif event.reason == 2:
        print(f"🚫 [BLACKLIST] Bloqueio Ativo! Pacote de {ip_str} mitigado instantaneamente no hardware.")

b["events"].open_perf_buffer(print_event)

print("🏰 [Aincrad Enterprise] Sistema operacional blindado com tabelas de estado em Kernel-Space.")
print("Press Ctrl+C para encerrar o escudo.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\\n🔓 Desativando infraestrutura e limpando ganchos XDP...")
    b.remove_xdp(interface, flags=BPF.XDP_FLAGS_SKB_MODE)
