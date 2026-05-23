#!/usr/bin/env python3
import os
import sys
import argparse
import socket
import struct
import time
import ctypes
from bcc import BPF
import bcc.libbcc as libbcc

# Caminhos persistentes no Kernel
BLACKLIST_PATH = "/sys/fs/bpf/aincrad_blacklist"
STATS_PATH = "/sys/fs/bpf/aincrad_stats"

def uint32_be_to_ip(val):
    return socket.inet_ntoa(struct.pack("I", val))

def carregar_mapas_compartilhados():
    """Carrega os mapas já fixados no Kernel."""
    if not os.path.exists(BLACKLIST_PATH) or not os.path.exists(STATS_PATH):
        raise Exception("Escudo não está rodando (Mapas não encontrados).")
    
    # Obter FDs dos mapas fixados
    fd_black = libbcc.lib.bpf_obj_get(BLACKLIST_PATH.encode())
    fd_stats = libbcc.lib.bpf_obj_get(STATS_PATH.encode())
    
    # Criar contexto temporário para interagir com os mapas
    bpf_ctx = BPF(text=b'BPF_HASH(blacklist, u32, u64); BPF_HASH(stats_map, u32, u64);') 
    
    blacklist = bpf_ctx.get_table("blacklist")
    blacklist.map_fd = fd_black
    
    stats = bpf_ctx.get_table("stats_map")
    stats.map_fd = fd_stats
    
    return blacklist, stats

def imprimir_stats():
    try:
        _, stats = carregar_mapas_compartilhados()
        print("\n🏰 [Aincrad Enterprise] — Estatísticas de Bloqueio")
        print("-" * 50)
        print(f"{'IP':<15} | {'Drops'}")
        for k, v in stats.items():
            print(f"{uint32_be_to_ip(k.value):<15} | {v.value}")
        print("-" * 50)
    except Exception as e:
        print(f"Erro ao ler estatísticas: {e}")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("Erro: Precisa ser ROOT.")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    # Fluxo CLI
    if args.list:
        imprimir_stats()
        sys.exit(0)

    # Fluxo Monitor (Serviço)
    print("🚀 Aincrad-XDP Iniciado...")
    b = BPF(src_file="aincrad_xdp.bpf.c")
    fn = b.load_func("aincrad_fw_filter", BPF.XDP)
    b.attach_xdp("enp3s0", fn, 0)
    
    # Pinagem dos mapas
    blacklist = b.get_table("blacklist")
    stats_map = b.get_table("stats_map")
    
    libbcc.lib.bpf_obj_pin(blacklist.get_fd(), BLACKLIST_PATH.encode())
    libbcc.lib.bpf_obj_pin(stats_map.get_fd(), STATS_PATH.encode())

    print("🛡️ Mapas fixados no Kernel. Monitorando...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Parando Aincrad...")
        if os.path.exists(BLACKLIST_PATH): os.remove(BLACKLIST_PATH)
        if os.path.exists(STATS_PATH): os.remove(STATS_PATH)
        sys.exit(0)

try:
    b.attach_xdp("enp3s0", fn, flags=2) 
    print("✅ Sucesso! Modo NATIVO ativado. Você está no Modo Turbo.")
except Exception as e:
    print(f"⚠️ O driver recusou o modo nativo: {e}")
    print("🔄 Tentando modo GENERIC (Fallback)...")
    b.attach_xdp("enp3s0", fn, flags=0)
    print("🛡️ Aincrad rodando em modo GENERIC (Ainda muito rápido!).")
