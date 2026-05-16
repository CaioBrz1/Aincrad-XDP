#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int aincrad_dpi(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Camada 2: Cabeçalho Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Filtra pacotes IPv4
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        
        // 2. Camada 3: Cabeçalho IP (Casting explícito para evitar desvios)
        struct iphdr *iph = (struct iphdr *)((char *)data + sizeof(struct ethhdr));
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        // Filtra apenas o protocolo UDP (17)
        if (iph->protocol == 17) {
            __u32 ip_hlen = iph->ihl * 4;
            if (ip_hlen < sizeof(struct iphdr))
                return XDP_PASS;

            // 3. Camada 4: Cabeçalho UDP
            struct udphdr *udph = (struct udphdr *)((char *)iph + ip_hlen);
            if ((void *)(udph + 1) > data_end)
                return XDP_PASS;

            // Encontra o início exato dos dados úteis (Payload)
            char *payload = (char *)(udph + 1);

            // BARREIRA DO VERIFICADOR
            if ((void *)(payload + 4) > data_end)
                return XDP_PASS;

            // 4. INSPEÇÃO PROFUNDA ANINHADA (Gatilho Antiotimização)
            if (payload[0] == 'A') {
                if (payload[1] == 'I') {
                    if (payload[2] == 'N') {
                        if (payload[3] == 'C') {
                            
                            // Telemetria síncrona
                            unsigned char *ip = (unsigned char *)&iph->saddr;
                            bpf_printk("🚨 [AINCRAD DPI] ASSINATURA DETECTADA DE %d.%d.%d.%d!\n",
                                       ip[0], ip[1], ip[2], ip[3]);

                            return XDP_DROP; // Pulverizado!
                        }
                    }
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
