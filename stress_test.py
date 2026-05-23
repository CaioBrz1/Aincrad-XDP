from scapy.all import IP, UDP, send, Ether
import time

# IP que você adicionou na sua blacklist (ajuste se necessário)
IP_BLOQUEADO = "192.168.1.50"

def enviar_ataque(nome_teste, ip_src, payload, qtd):
    print(f"🚀 Iniciando {nome_teste} ({qtd} pacotes)...")
    for i in range(qtd):
        # O PULO DO GATO: O cabeçalho Ethernet resolve o problema do aviso MAC
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=ip_src, dst="192.168.1.100") / UDP(dport=80) / payload
        send(pkt, iface="enp3s0", verbose=False)
    print(f"✅ {nome_teste} finalizado.")

if __name__ == "__main__":
    # Teste 1: O IP bloqueado tentando enviar tráfego normal
    enviar_ataque("Teste Blacklist", IP_BLOQUEADO, "Tráfego normal", 500)
    
    # Teste 2: Um IP qualquer enviando o padrão proibido
    enviar_ataque("Teste Padrão AINC", "1.1.1.1", "AINC_EVASION_TEST", 500)
    
    print("\n🏁 Stress Test concluído! Verifique seu monitor.")
