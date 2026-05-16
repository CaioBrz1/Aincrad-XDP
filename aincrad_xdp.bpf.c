#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_PAYLOAD_SCAN 16  // Janela de varredura contra evasão por espaços
#define BLACKLIST_TIMEOUT_NS 60000000000ULL // 60 segundos de banimento

// Estrutura de telemetria enviada para o espaço de usuário
struct event_t {
    __u32 src_ip;
    __u32 pkt_len;
    __u32 reason; // 1 = Flag pega no Scanner, 2 = Já estava na Blacklist
};

// Definição manual dos mapas no padrão eBPF puro (Production-ready)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Chave: IP de Origem
    __type(value, __u64); // Valor: Timestamp do ataque
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, __u32);
} events SEC(".maps");

SEC("xdp")
int aincrad_production(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Alinhamento para o início do IP (Ajustado para o modo Genérico/SKB)
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 now = bpf_ktime_get_ns();

    // 🛡️ PASSO 1: Checagem Relâmpago na Blacklist
    __u64 *last_attack = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (last_attack) {
        if (now - *last_attack < BLACKLIST_TIMEOUT_NS) {
            // IP segue de castigo. Reporta e dropa instantaneamente
            struct event_t event = { .src_ip = src_ip, .pkt_len = ctx->data_end - ctx->data, .reason = 2 };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            return XDP_DROP;
        } else {
            // Perdoado! O tempo de punição acabou
            bpf_map_delete_elem(&blacklist, &src_ip);
        }
    }

    // Filtra para analisar apenas pacotes UDP
    if (iph->protocol != 17)
        return XDP_PASS;

    __u32 ip_hlen = iph->ihl * 4;
    struct udphdr *udph = (void *)iph + ip_hlen;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    char *payload = (char *)(udph + 1);
    
    // 🔍 PASSO 2: Scanner Anti-Evasão (Bounded Loop)
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_SCAN; i++) {
        // Verificação estrita de limite de memória exigida pelo Verificador do Kernel
        if ((void *)(payload + i + 4) > data_end)
            break;

        // Caça a assinatura contígua "AINC" mesmo se houver camuflagem de espaços antes
        if (payload[i] == 'A' && payload[i+1] == 'I' && payload[i+2] == 'N' && payload[i+3] == 'C') {
            
            // Aplica o banimento no mapa do Kernel
            bpf_map_update_elem(&blacklist, &src_ip, &now, BPF_ANY);

            // Dispara alerta de nova detecção para o Python
            struct event_t event = { .src_ip = src_ip, .pkt_len = ctx->data_end - ctx->data, .reason = 1 };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
