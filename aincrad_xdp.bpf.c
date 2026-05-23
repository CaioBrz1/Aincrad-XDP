#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

// Mapa PERCPU para performance comercial (Sem locks)
BPF_PERCPU_HASH(stats_map, u32, u64);
BPF_PERCPU_HASH(blacklist, u32, u64);

int aincrad_fw_filter(struct xdp_md *ctx) {
    // Endereços de memória do pacote
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parsing Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    // 2. Parsing IP
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

u32 key = 0; // Chave simples para o contador global
u64 *val = stats_map.lookup(&key);
if (val) {
    __sync_fetch_and_add(val, 1);
} else {
    u64 initial_val = 1;
    stats_map.update(&key, &initial_val);
}

    // DEFINIÇÃO DA VARIÁVEL (Agora o compilador vai enxergar!)
    u32 src_ip = iph->saddr;

    // 3. PAREDE DE SILÍCIO (Blacklist)
    u64 *blocked = blacklist.lookup(&src_ip);
    if (blocked) {
        return XDP_DROP;
    }

    // 4. Lógica de Protocolo (AINC)
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        char *payload = (char *)(udp + 1);
        if (payload + 4 <= (char *)data_end) {
            if (payload[0] == 'A' && payload[1] == 'I' && payload[2] == 'N' && payload[3] == 'C') {
                return XDP_DROP;
            }
        }
    }

    // Regra de ouro: Se passou por tudo, deixa passar
    return XDP_PASS;
}
