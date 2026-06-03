#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generar_dataset_5g.py
=====================
Prueba de concepto: a partir de una captura tomada desde el *core* de una red
privada 5G SA (OAI / Firecell Labkit 40), de-encapsula el plano de usuario
GTP-U (N3), separa el plano de control (NGAP/SCTP, N2) y produce un pequeño
dataset etiquetado a nivel de paquete y de flujo.

Escenario capturado: ataque a Apache Tomcat (CVE-2017-12615), escritura
arbitraria de un webshell JSP (PUT) y ejecucion remota de comandos (GET ?cmd=),
generado a traves de la red 5G y observado desde el core.

Etiquetas:
  - attack_tomcat_rce : flujo del ataque (atacante <-> servicio Tomcat en el UE).
  - benign_background : trafico de usuario benigno del propio UE (QUIC/TLS/DNS...).
  - control_ngap      : plano de control N2 (NGAP sobre SCTP, puerto 38412).
  - mgmt_oai          : trafico interno del core (127.0.0.1) -> excluido del dataset.

Requisitos: tshark (Wireshark) en el PATH; Python 3.8+ (solo libreria estandar).
Uso:        python generar_dataset_5g.py [captura.pcap]

NOTA: las direcciones/puertos son las observadas en la captura de referencia;
parametrizables abajo si se reutiliza con otra traza.
"""

import csv
import os
import subprocess
import sys
from collections import defaultdict

# --------------------------- Parametros del escenario ------------------------
PCAP = sys.argv[1] if len(sys.argv) > 1 else "ataque_tomcat_5g_2.pcap"
OUTDIR = "dataset"

ATACANTE = "192.168.1.205"     # host atacante (lado red de datos / N6)
UE_5G = "12.1.1.132"           # IP 5G del UE que aloja los servicios (pool OAI 12.1.1.0/24)
PUERTO_SERVICIO = "18009"      # puerto del servicio Tomcat visto desde el core (tras NAT)
PUERTO_NGAP = "38412"          # SCTP/NGAP (N2)
GTPU_PORT = "2152"             # GTP-U (N3)
N3_GNB = "192.168.70.129"      # extremo gNB del tunel N3
N3_UPF = "192.168.70.134"      # extremo UPF del tunel N3

# Campos extraidos con tshark (una linea por paquete).
FIELDS = [
    "frame.number", "frame.time_epoch", "frame.time_relative", "frame.len",
    "ip.src", "ip.dst", "ip.proto", "gtp.teid",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "sctp.srcport", "sctp.dstport", "_ws.col.protocol", "frame.protocols",
]
SEP = "|"


def run_tshark(pcap):
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=" + SEP]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        sys.exit("tshark error:\n" + out.stderr)
    return out.stdout.splitlines()


def first(val):
    """Primer elemento de un campo multi-valor (capa externa)."""
    return val.split(",")[0] if val else ""


def last(val):
    """Ultimo elemento de un campo multi-valor (capa interna / de-encapsulada)."""
    return val.split(",")[-1] if val else ""


def parse(line):
    p = dict(zip(FIELDS, line.split(SEP)))
    tunneled = bool(p["gtp.teid"])
    # Con GTP-U hay dos capas IP: externa (transporte N3) e interna (de-encapsulada).
    ip_out_src, ip_in_src = first(p["ip.src"]), last(p["ip.src"])
    ip_out_dst, ip_in_dst = first(p["ip.dst"]), last(p["ip.dst"])
    # Puertos internos: para TCP no hay capa externa; para UDP el externo es 2152.
    tcp_sp, tcp_dp = last(p["tcp.srcport"]), last(p["tcp.dstport"])
    udp_sp, udp_dp = last(p["udp.srcport"]), last(p["udp.dstport"])
    return {
        "frame": p["frame.number"],
        "t_epoch": p["frame.time_epoch"],
        "t_rel": p["frame.time_relative"],
        "len": int(p["frame.len"] or 0),
        "ip_out_src": ip_out_src, "ip_out_dst": ip_out_dst,
        "ip_in_src": ip_in_src, "ip_in_dst": ip_in_dst,
        "ip_proto": last(p["ip.proto"]),
        "teid": p["gtp.teid"], "tunneled": tunneled,
        "tcp_sp": tcp_sp, "tcp_dp": tcp_dp,
        "udp_sp": udp_sp, "udp_dp": udp_dp,
        "sctp_sp": p["sctp.srcport"], "sctp_dp": p["sctp.dstport"],
        "proto": p["_ws.col.protocol"], "stack": p["frame.protocols"],
    }


def etiquetar(r):
    # Trafico interno del core (loopback): no forma parte del dataset.
    if r["ip_out_src"] == "127.0.0.1" or r["ip_out_dst"] == "127.0.0.1":
        return "mgmt_oai", "control"
    # Plano de control N2: NGAP sobre SCTP (puerto 38412).
    if r["sctp_sp"] == PUERTO_NGAP or r["sctp_dp"] == PUERTO_NGAP:
        return "control_ngap", "control"
    # Plano de usuario de-encapsulado de GTP-U.
    if r["tunneled"]:
        inner = {r["ip_in_src"], r["ip_in_dst"]}
        puertos = {r["tcp_sp"], r["tcp_dp"]}
        if {ATACANTE, UE_5G} <= inner and PUERTO_SERVICIO in puertos:
            return "attack_tomcat_rce", "user"
        if UE_5G in inner:
            return "benign_background", "user"
    # Fragmentos IP (proto=17/UDP) del tunel GTP-U N3 entre UPF y gNB: paquetes
    # grandes (>MTU) cuyo contenido interno se reensambla en la trama final.
    if (r["ip_proto"] == "17" and not r["tunneled"]
            and {r["ip_out_src"], r["ip_out_dst"]} == {N3_GNB, N3_UPF}):
        return "gtpu_n3_fragment", "user"
    return "other", "?"


def flujo_key(r):
    """Clave de flujo bidireccional sobre la 5-tupla interna (de-encapsulada)."""
    if r["tcp_sp"]:
        sp, dp, l4 = r["tcp_sp"], r["tcp_dp"], "TCP"
    elif r["udp_sp"]:
        sp, dp, l4 = r["udp_sp"], r["udp_dp"], "UDP"
    else:
        sp, dp, l4 = "", "", r["proto"]
    a = (r["ip_in_src"], sp)
    b = (r["ip_in_dst"], dp)
    lo, hi = sorted([a, b])
    return (lo[0], lo[1], hi[0], hi[1], l4)


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    lineas = run_tshark(PCAP)
    paquetes = [parse(l) for l in lineas if l]

    # --- CSV por paquete ---
    pkt_csv = os.path.join(OUTDIR, "dataset_5g_tomcat_packets.csv")
    cols = ["frame", "t_epoch", "t_rel", "len", "plane", "tunneled", "teid",
            "ip_in_src", "ip_in_dst", "l4_proto", "sport", "dport",
            "proto", "label"]
    clase = defaultdict(int)
    bytes_clase = defaultdict(int)
    flujos = defaultdict(lambda: {"pkts": 0, "bytes": 0, "t0": None, "t1": None,
                                  "label": None, "plane": None})

    with open(pkt_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in paquetes:
            label, plane = etiquetar(r)
            if r["tcp_sp"]:
                l4, sp, dp = "TCP", r["tcp_sp"], r["tcp_dp"]
            elif r["udp_sp"]:
                l4, sp, dp = "UDP", r["udp_sp"], r["udp_dp"]
            elif r["sctp_sp"]:
                l4, sp, dp = "SCTP", r["sctp_sp"], r["sctp_dp"]
            else:
                l4, sp, dp = "", "", ""
            w.writerow([r["frame"], r["t_epoch"], r["t_rel"], r["len"], plane,
                        int(r["tunneled"]), r["teid"], r["ip_in_src"],
                        r["ip_in_dst"], l4, sp, dp, r["proto"], label])
            clase[label] += 1
            bytes_clase[label] += r["len"]
            # Acumular flujos (solo plano de usuario de-encapsulado y control N2)
            if label in ("attack_tomcat_rce", "benign_background", "control_ngap"):
                k = flujo_key(r)
                f = flujos[k]
                f["pkts"] += 1
                f["bytes"] += r["len"]
                t = float(r["t_rel"])
                f["t0"] = t if f["t0"] is None else min(f["t0"], t)
                f["t1"] = t if f["t1"] is None else max(f["t1"], t)
                f["label"] = label
                f["plane"] = plane

    # --- CSV por flujo ---
    flow_csv = os.path.join(OUTDIR, "dataset_5g_tomcat_flows.csv")
    with open(flow_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip_a", "port_a", "ip_b", "port_b", "l4", "plane",
                    "n_pkts", "n_bytes", "dur_s", "mean_len", "label"])
        for k, f in sorted(flujos.items(), key=lambda x: -x[1]["pkts"]):
            dur = round((f["t1"] - f["t0"]), 3)
            w.writerow([k[0], k[1], k[2], k[3], k[4], f["plane"], f["pkts"],
                        f["bytes"], dur, round(f["bytes"] / f["pkts"], 1),
                        f["label"]])

    # --- Resumen por consola ---
    total = len(paquetes)
    print(f"Captura: {PCAP}  ->  {total} paquetes")
    print(f"Salida:  {pkt_csv}")
    print(f"         {flow_csv}\n")
    print(f"{'clase':<22}{'paquetes':>10}{'%':>8}{'bytes':>12}")
    print("-" * 52)
    for c in sorted(clase, key=lambda x: -clase[x]):
        print(f"{c:<22}{clase[c]:>10}{100*clase[c]/total:>7.1f}%{bytes_clase[c]:>12}")
    print("-" * 52)
    n_flujos = len([1 for f in flujos.values()
                    if f["label"] != "control_ngap"])
    print(f"flujos (plano de usuario): {n_flujos}")
    return clase, flujos


if __name__ == "__main__":
    main()
