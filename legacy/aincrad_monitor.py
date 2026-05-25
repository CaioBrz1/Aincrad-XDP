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
import json
import sys

# Caminhos persistentes no Kernel
BLACKLIST_PATH = "/sys/fs/bpf/aincrad_blacklist"
STATS_PATH = "/sys/fs/bpf/aincrad_stats"
BAN_DURATION_NS = 60000000000 

# 2. Carrega o BPF
b = BPF(src_file="aincrad_xdp.bpf.c")
blacklist = b.get_table("blacklist")
fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp("enp3s0", fn, 0)
print("✅ XDP acoplado com sucesso na interface enp3s0!")

# 3.
last_cleanup = time.time()

def uint32_be_to_ip(val):
    return socket.inet_ntoa(struct.pack("I", val))

def carregar_mapas_compartilhados():
    """Carrega os mapas já fixados no Kernel."""
    if not os.path.exists(BLACKLIST_PATH) or not os.path.exists(STATS_PATH):
        raise Exception("Escudo não está rodando (Mapas não encontrados).")
    
    # Obter FDs dos mapas fixados
    fd_black = libbcc.lib.bpf_obj_get(BLACKLIST_PATH.encode())
    fd_stats = libbcc.lib.bpf_obj_get(STATS_PATH.encode())
    
    # Contexto temporário para interagir com os mapas
    bpf_ctx = BPF(text=b'BPF_HASH(blacklist, u32, u64); BPF_HASH(stats_map, u32, u64);') 
    
    blacklist = bpf_ctx.get_table("blacklist")
    blacklist.map_fd = fd_black
    
    stats = bpf_ctx.get_table("stats_map")
    stats.map_fd = fd_stats
    
    return blacklist, stats

def imprimir_as_json(b):
    stats_map = b.get_table("stats")
    
    # Prepara os acumuladores
    total_passed = 0
    total_drop = 0
    total_ainc = 0
    
    # Soma de todos os núcleos (Per-CPU array)
    for cpu_val in stats_map[0]:
        total_passed += cpu_val.passed
        total_drop += cpu_val.drop
        total_ainc += cpu_val.ainc_blocked
        
    # Cria o dicionário
    data = {
        "status": "active",
        "metrics": {
            "passed": total_passed,
            "dropped": total_drop,
            "ainc_blocked": total_ainc
        }
    }

def load_whitelist(b):
    whitelist = b.get_table("whitelist")
    
    # Lista de IPs autorizados 
    ips_autorizados = ["192.168.1.1"] 
    
    for ip in ips_autorizados:
        ip_int = struct.unpack("I", socket.inet_aton(ip))[0]
        whitelist[ctypes.c_uint32(ip_int)] = ctypes.c_ulonglong(1)
        print(f"✅ IP {ip} adicionado com sucesso na Whitelist!")

load_whitelist(b)

# --- LOOP PRINCIPAL (LIMPEZA) ---
syn_map = b.get_table("syn_counters")

wl = b.get_table("whitelist")
stats_map = b.get_table("stats")

import time

last_report = time.time()
last_cleanup = time.time()

# --- LOOP PRINCIPAL ---

last_report = time.time()
last_cleanup = time.time()

class Stats(ctypes.Structure):
    _fields_ = [("drop", ctypes.c_ulonglong),
                ("passed", ctypes.c_ulonglong),
                ("ainc_blocked", ctypes.c_ulonglong)]

# 2.
stats = b.get_table("stats") 

print("Monitoramento iniciado. Pressione Ctrl+C para parar.")

try:
    while True:
        current_time = time.time()
        
        if (current_time - last_report) > 5:
        
            print(f"DEBUG: O mapa contém {len(stats)} chaves.")

            if len(stats) > 0:
                print(f"\n--- [ {time.ctime()} ] DADOS ENCONTRADOS ---")
                for key, value in stats.items():
                    print(f"DEBUG: Chave encontrada: {key.value}")
                  
                    print(f"Drop: {value.drop} | Pass: {value.passed} | Bloq: {value.ainc_blocked}")
            else:
                print("\n⏳ [Status] Mapa carregado, mas ainda não recebeu nenhum dado.")
            
            last_report = current_time
        
        time.sleep(1) 

except KeyboardInterrupt:
    print("\n🛑 Parando Aincrad...")
    sys.exit(0)
