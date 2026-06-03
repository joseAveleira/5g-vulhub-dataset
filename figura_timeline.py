#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Figura de resultados: cronologia (3 carriles) del trafico capturado desde el
core 5G. Muestra la coexistencia, en una sola captura, del ataque a Tomcat
(CVE-2017-12615) reconstruido tras de-encapsular GTP-U, del trafico benigno del
plano de usuario y de la senalizacion de control N2 (NGAP/SCTP).
Entrada: dataset/dataset_5g_tomcat_packets.csv
Salida:  ../images/captura_timeline_5g.png
"""
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
from matplotlib.lines import Line2D

CSV = "dataset/dataset_5g_tomcat_packets.csv"
OUT = "figures/captura_timeline_5g.png"

rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
T = max(float(r["t_rel"]) for r in rows)
benign = [float(r["t_rel"]) for r in rows if r["label"] == "benign_background"]
control = [float(r["t_rel"]) for r in rows if r["label"] == "control_ngap"]
attack = [float(r["t_rel"]) for r in rows if r["label"] == "attack_tomcat_rce"]

# Eventos HTTP del ataque (peticiones reconstruidas tras de-encapsular GTP-U)
eventos = [
    (25.2, "PUT"), (26.5, "GET"), (28.0, ""), (38.6, ""), (57.8, ""),
    (120.6, ""), (129.8, ""), (145.7, ""), (161.8, ""),
]
t0, t1 = eventos[0][0], eventos[-1][0]

plt.rcParams.update({"font.size": 9, "font.family": "serif"})
fig, ax = plt.subplots(figsize=(7.6, 1.95))

LANES = {"benign": 2.0, "attack": 1.0, "control": 0.0}

# Ventana del ataque (sombreado)
ax.axvspan(t0 - 2, t1 + 3, color="#d62728", alpha=0.07, zorder=0)

# Carril benigno (plano de usuario): ticks tenues -> trafico continuo
ax.eventplot(benign, lineoffsets=LANES["benign"], linelengths=0.7,
             colors="0.62", linewidths=0.4, zorder=2)
# Carril control N2 (NGAP/SCTP)
ax.eventplot(control, lineoffsets=LANES["control"], linelengths=0.7,
             colors="#1f4e79", linewidths=0.8, zorder=2)
# Carril ataque: todos los paquetes (tenue) + eventos HTTP (marcados)
ax.eventplot(attack, lineoffsets=LANES["attack"], linelengths=0.5,
             colors="#f4a3a3", linewidths=0.5, zorder=2)
for t, tag in eventos:
    ax.plot(t, LANES["attack"], marker="v", color="#b30000",
            markersize=5, zorder=4)

# Anotaciones de fase
ax.annotate("Subida del webshell (PUT, 201 Created)",
            xy=(25.2, 1.0), xytext=(20, 1.55), fontsize=7.3, color="#7a0000",
            arrowprops=dict(arrowstyle="->", color="#7a0000", lw=0.7))
ax.annotate("Ejecución remota de comandos (GET ?cmd=, 200 OK)",
            xy=(120.6, 1.0), xytext=(70, 0.45), fontsize=7.3, color="#7a0000",
            arrowprops=dict(arrowstyle="->", color="#7a0000", lw=0.7))

ax.set_yticks(list(LANES.values()))
ax.set_yticklabels([
    "Benigno\n(plano usuario)",
    "Ataque\n(CVE-2017-12615)",
    "Control N2\n(NGAP/SCTP)",
])
ax.tick_params(axis="y", length=0)
ax.set_xlim(0, T)
ax.set_ylim(-0.6, 2.2)
ax.set_xlabel("Tiempo desde el inicio de la captura (s)")
ax.xaxis.set_major_locator(MultipleLocator(30))
for s in ("top", "right", "left"):
    ax.spines[s].set_visible(False)
fig.tight_layout()
fig.savefig(OUT, dpi=300, bbox_inches="tight")
print("Figura guardada en", OUT)
print(f"benigno={len(benign)} ataque={len(attack)} control={len(control)} T={T:.1f}s")
