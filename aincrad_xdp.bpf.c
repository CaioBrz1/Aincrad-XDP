#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

// --- ESTRUTURAS ---
struct stats_t {
    u64 drop;
    u64 passed;
    u64 ainc_blocked;
};

struct event_t {
    u32 ip;
    u32 action;
};

// --- MAPAS ---
BPF_HASH(stats, u32, struct stats_t);
BPF_PERF_OUTPUT(events);
BPF_HASH(whitelist, u32, u64);
BPF_HASH(blacklist, u32, u64);
BPF_HASH(syn_counters, u32, u64);

// --- FUNÇÃO AUXILIAR ---
static __always_inline void update_stats(u32 action) {
    u32 key = 0;
    struct stats_t *val = stats.lookup(&key);
    
    if (val) {
        if (action == 0) val->drop += 1;
        else if (action == 1) val->passed += 1;
        else if (action == 2) val->ainc_blocked += 1;
    } else {
        struct stats_t new_val = {};
        if (action == 0) new_val.drop = 1;
        else if (action == 1) new_val.passed = 1;
        else if (action == 2) new_val.ainc_blocked = 1;
        stats.update(&key, &new_val);
    }
}

static inline void push_event(u32 ip, u32 action, struct xdp_md *ctx) {
    struct event_t e = {};
    e.ip = ip;
    e.action = action;
    events.perf_submit(ctx, &e, sizeof(e));
}

// --- PROGRAMA PRINCIPAL ---

int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parsing Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // 2. Liberar ARP imediatamente
    if (eth->h_proto == htons(ETH_P_ARP)) {
        return XDP_PASS;
    }

    // 3. Checar apenas se é IP
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 4. Parsing IP (Apenas uma vez!)
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    u32 src_ip = iph->saddr;

    // DEBUG: printar o IP
    bpf_trace_printk("IP tentando passar: %x\n", src_ip);

    // 5. WHITELIST (MODO OBSERVAÇÃO)
    if (whitelist.lookup(&src_ip) == NULL) {
        // Loga o IP que não está na whitelist, mas deixa passar!
        bpf_trace_printk("DEBUG: IP nao autorizado: %x\n", src_ip);
        update_stats(1);
        return XDP_PASS; // <--- Mudamos de DROP para PASS para testar
    }

    // 6. BLACKLIST
    if (blacklist.lookup(&src_ip)) {
        push_event(src_ip, 1, ctx);
        update_stats(0);
        return XDP_DROP;
    }

    // 7. INSPEÇÃO (AINC ou ICMP)
    if (iph->protocol == IPPROTO_ICMP) {
        // Ping liberado/contabilizado
    }
    
    if (iph->protocol == IPPROTO_UDP) {
        // Lógica de ataque AINC aqui
    }

    // 8. Tudo certo, deixa passar
    update_stats(1);
    return XDP_PASS;
}
